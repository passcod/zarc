use std::{
	io::{Cursor, Seek, SeekFrom},
	num::{NonZeroU64, NonZeroU8},
	rc::Rc,
};

use deku::DekuContainerRead;
use ozarc::framing::{
	SkippableFrame, ZstandardBlockHeader, ZstandardBlockType, ZstandardFrameHeader,
};
use tracing::{debug, instrument, trace};

use crate::{
	format::{ZarcDirectory, ZarcTrailer, ZarcHeader, FILE_MAGIC},
	ondemand::OnDemand,
};

use super::{
	error::{ErrorKind, Result, SimpleError},
	Decoder,
};

impl<R: OnDemand> Decoder<R> {
	/// Read a Skippable frame, checking its nibble.
	///
	/// Reads and returns the entire frame's payload, and thus seeks to the end of the frame.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(reader))]
	fn read_skippable_frame(reader: &mut R::Reader, nibble: u8) -> Result<SkippableFrame> {
		let (bits_read, frame) =
			SkippableFrame::from_reader((reader, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?frame, nibble=%format!("0x{:X}", frame.nibble()), "read skippable frame");

		if frame.nibble() != nibble {
			return Err(ErrorKind::InvalidNibble {
				expected: nibble,
				actual: frame.nibble(),
			}
			.into());
		}

		Ok(frame)
	}

	/// Read a Zstandard frame header.
	///
	/// This reads the frame header, checks that it's a Zstandard frame, and leaves the reader at
	/// the start of the first block. The frame header is returned.
	///
	/// This does not read the frame's payload: you need to do that yourself, reading blocks one at
	/// a time until the one marked `last`, and then reading the checksum
	/// [if present as per this header](ozarc::framing::ZstandardFrameDescriptor.checksum).
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(reader))]
	fn read_zstandard_frame_header(reader: &mut R::Reader) -> Result<ZstandardFrameHeader> {
		let (bits_read, header) =
			ZstandardFrameHeader::from_reader((reader, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?header, "read zstandard frame header");
		Ok(header)
	}

	/// Read a Zstandard frame block header.
	///
	/// This reads the block header, checks that it's a Zstandard block, and leaves the reader at
	/// the start of the block's payload. The block header is returned.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(reader))]
	fn read_zstandard_block_header(reader: &mut R::Reader) -> Result<ZstandardBlockHeader> {
		let (bits_read, header) =
			ZstandardBlockHeader::from_reader((reader, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?header, "read zstandard block header");
		Ok(header)
	}

	/// Read a Zarc header.
	///
	/// Sets the file version of the decoder.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	fn read_header(&mut self) -> Result<()> {
		if self.file_version.is_some() {
			return Err(ErrorKind::ReadOrderViolation("header cannot be read twice").into());
		};

		let mut reader = self.reader.open()?;
		let frame = Self::read_skippable_frame(&mut reader, 0x0)?;

		let mut content = Cursor::new(frame.data);
		let (bits_read, header) =
			ZarcHeader::from_reader((&mut content, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?header, "read zarc header");

		debug_assert_ne!(crate::format::ZARC_FILE_VERSION, 0);
		debug_assert_ne!(header.file_version, 0);
		if header.file_version != crate::format::ZARC_FILE_VERSION {
			return Err(ErrorKind::UnsupportedFileVersion(header.file_version).into());
		}

		self.file_version = Some(unsafe {
			// SAFETY: the version is valid and zarc versions start at 1
			NonZeroU8::new_unchecked(header.file_version)
		});
		Ok(())
	}

	/// Read a Zarc unintended magic.
	///
	/// This reads a Zstandard frame, checks that there's a first Raw block which contains the Zarc
	/// magic, then _doesn't_ seek to the end of the frame. When this is used by the public API,
	/// the immediate next action is to read the trailer, which is at the end of the file, so it
	/// doesn't matter whether we seek or not.
	///
	/// When this is used via `expose-internals`, you'll be left at the start of the next block,
	/// _or_ at the start of the checksum. You may want to seek backwards until you find the frame
	/// header again so you can reparse it to figure out what you should do next, or just don't call
	/// this method unless you're going to seek elsewhere afterwards, and do it entirely manually.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	fn read_unintended_magic(&mut self) -> Result<()> {
		let Some(file_version) = self.file_version else {
			return Err(ErrorKind::ReadOrderViolation(
				"unintended magic cannot be read before header",
			)
			.into());
		};

		let mut reader = self.reader.open()?;
		reader.seek(SeekFrom::Start(FILE_MAGIC.len() as _))?;

		let _frame_header = Self::read_zstandard_frame_header(&mut reader)?;

		let first_block_header = Self::read_zstandard_block_header(&mut reader)?;
		if first_block_header.block_type != ZstandardBlockType::Raw {
			return Err(ErrorKind::InvalidUnintendedMagic.into());
		}
		if first_block_header.actual_size() != 4 {
			return Err(ErrorKind::InvalidUnintendedMagic.into());
		}
		let (bits_read, unintended_magic) =
			ZarcHeader::from_reader((&mut reader, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?unintended_magic, "read zarc header in unintended magic raw block");
		if unintended_magic.file_version != file_version.get() {
			return Err(ErrorKind::MismatchedFileVersion.into());
		}

		// an extra check we could do is store the offset here and then check that no frame of
		// content starts before it, as that would be frames attempting to read into header space.
		// but as content frames are only zstandard frames, we achieve the same by instead checking
		// explicitly for the two known offsets of zarc metadata in zstandard frames, this very one
		// at constant offset 12 and the directory.

		Ok(())
	}

	/// Read the Zarc EOF Trailer.
	///
	/// This opens a new reader, seeks to the end minus 16 bytes, reads the EOF trailer frame, then
	/// returns the offset of the start of the Zarc Directory Header (backward from EOF) in bytes.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	fn read_eof_trailer(&mut self) -> Result<u64> {
		let mut reader = self.reader.open()?;
		reader.seek(SeekFrom::End(-16))?;
		let trailer = Self::read_skippable_frame(&mut reader, 0xE)?;

		let mut content = Cursor::new(trailer.data);
		let (bits_read, trailer) =
			ZarcTrailer::from_reader((&mut content, 0)).map_err(SimpleError::from_deku)?;

		let offset = trailer.directory_length.saturating_add(16);
		debug!(%bits_read, ?trailer, directory_header_offset=%offset, "read zarc eof trailer");

		Ok(offset)
	}

	/// Read Zarc Directory Header.
	///
	/// This opens a new reader and reads the Zarc Directory Header.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	fn read_directory_header(&mut self) -> Result<()> {
		if self.directory_header.is_some() {
			return Err(
				ErrorKind::ReadOrderViolation("directory header cannot be read twice").into(),
			);
		};
		let Some(file_version) = self.file_version else {
			return Err(ErrorKind::ReadOrderViolation(
				"directory cannot be read before file header",
			)
			.into());
		};

		let mut reader = self.reader.open()?;
		debug!("seek to trailer");
		reader.seek(SeekFrom::End(todo!()))?;

		// let frame = Self::read_skippable_frame(&mut reader, 0xF)?;
		// let mut content = Cursor::new(frame.data);
		// let (bits_read, directory_header) =
		// 	ZarcDirectoryHeader::from_reader((&mut content, 0)).map_err(SimpleError::from_deku)?;
		// debug!(%bits_read, ?directory_header, "read zarc directory header");

		// if directory_header.file_version != file_version.get() {
		// 	return Err(ErrorKind::MismatchedFileVersion.into());
		// }

		// self.directory_header = Some(Rc::new(directory_header));

		// let offset = reader.stream_position()?;
		// debug!(%offset, "cursor is at end of directory header, ie start of directory frame");
		// debug_assert_ne!(offset, 0);
		// self.directory_offset = Some(unsafe {
		// 	// SAFETY: directory is always after (multiple) headers
		// 	NonZeroU64::new_unchecked(offset)
		// });

		Ok(())
	}

	/// Read the Zarc Directory.
	///
	/// After this returns, the Zarc file is ready for reading, using the Filemap iterator to sift
	/// through the available file records and extract them on demand.
	///
	/// This has two modes, which are switched internally.
	///
	/// ## Streaming
	///
	/// If the directory doesn't decompress in one step.
	///
	/// This starts uncompressing and reading the Zarc Directory, and stops after the first four
	/// CBOR fields. This is enough to get the directory version, public key and algorithms, which
	/// are needed to verify the directory integrity. After checking the signature, decompression is
	/// resumed, and the directory's digest is verified. While doing so, the frame lookup table is
	/// constructed and held in memory. This is a map from digest to frame offset and metadata, and
	/// is used to efficiently seek to a frame when it's needed.
	///
	/// ## In-memory
	///
	/// If the directory decompresses in one step.
	///
	/// In that case, the directory is entirely hashed and decoded from CBOR, then verified, and
	/// finally stored in the context. The frame lookup table is also constructed, but maps digests
	/// to indexes in the directory's frame list to avoid duplicating memory.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	fn read_directory(&mut self) -> Result<()> {
		let Some(offset) = self.directory_offset else {
			return Err(ErrorKind::ReadOrderViolation(
				"directory cannot be read before directory header",
			)
			.into());
		};
		let Some(header) = self.directory_header.as_ref().map(|dh| Rc::clone(dh)) else {
			return Err(ErrorKind::ReadOrderViolation(
				"directory cannot be read before directory header",
			)
			.into());
		};

		// start a new decompression session
		let mut frame = self.read_zstandard_frame(offset.get())?;
		let data = frame
			.next()
			.ok_or(ErrorKind::DirectoryIntegrity("empty directory"))??;
		if frame.is_done() {
			drop(frame); // to release borrow
			debug!("processing entire directory in memory");
			let directory: ZarcDirectory = minicbor::decode(&data)?;

			trace!("verify directory signature");
			if !header.signature_type.verify_data(
				&header.public_key,
				&header.signature,
				header.digest.as_slice(),
			) {
				return Err(ErrorKind::DirectoryIntegrity("signature").into());
			}

			trace!("verify directory hash");
			if !header.digest_type.verify_data(&header.digest, &data) {
				return Err(ErrorKind::DirectoryIntegrity("digest").into());
			}

			trace!(frames=%directory.framelist.len(), "build frame lookup table");
			for frame in directory.framelist.iter() {
				if !header.signature_type.verify_data(
					&header.public_key,
					&frame.signature,
					frame.frame_hash.as_slice(),
				) {
					return Err(ErrorKind::DirectoryIntegrity("frame signature").into());
				}

				self.frame_lookup.insert(
					frame.frame_hash.clone(),
					FrameLookupEntry {
						offset: frame.offset,
						uncompressed: frame.uncompressed,
					},
				);
			}
			trace!(frames=%self.frame_lookup.len(), "verified and built frame lookup table");

			self.directory = Some(Rc::new(directory));
		} else {
			debug!("directory spans more than one block, streaming it");
			todo!("streaming directory decode")
		}

		Ok(())
	}

	/// Prepare a Zarc for reading.
	///
	/// This reads all the Zarc headers and the Zarc directory, verifies the integrity of the
	/// archive except for the actual file content, etc. Once this returns, the Zarc file is ready
	/// for reading, using the filemap iterator to sift through the available file records and
	/// extract them on demand.
	pub fn prepare(&mut self) -> Result<()> {
		self.read_header()?;
		self.read_unintended_magic()?;

		self.read_eof_trailer()?;
		self.read_directory_header()?;
		self.read_directory()?;

		Ok(())
	}
}

/// Frame lookup table entry.
#[derive(Clone, Copy, Debug)]
pub struct FrameLookupEntry {
	/// Frame offset.
	pub offset: u64,

	/// Uncompressed payload size in bytes.
	pub uncompressed: u64,
}
