//! Decoder types and functions.

use std::{
	collections::HashMap,
	fmt,
	io::{Cursor, Read, Seek, SeekFrom},
	num::{NonZeroU64, NonZeroU8},
	rc::Rc,
};

use deku::DekuContainerRead;
use ozarc::framing::{
	SkippableFrame, ZstandardBlockHeader, ZstandardBlockType, ZstandardFrameHeader,
};
use tracing::{debug, instrument, trace};
use zstd_safe::{DCtx, InBuffer, OutBuffer};

use crate::format::{
	Digest, FilemapEntry, HashAlgorithm, Signature, SignatureScheme, ZarcDirectory,
	ZarcDirectoryHeader, ZarcEofTrailer, ZarcHeader,
};

use self::error::{ErrorKind, Result, SimpleError};

pub mod error;

/// Decoder context.
///
/// Reader needs to be Seek, as Zarc reads the file backwards from the end to find the directory.
pub struct Decoder<'reader, R> {
	reader: &'reader mut R,
	zstd: DCtx<'reader>,

	/// File version number, once known. At this point only one version is supported, so this is
	/// mostly used to check that the other file version fields in the various headers match it.
	file_version: Option<NonZeroU8>,

	// offsets to various parts of the file, once known
	directory_header_offset: Option<NonZeroU64>,
	directory_offset: Option<NonZeroU64>,

	/// Zarc Directory Header, once known. This contains the digest and signature of the directory,
	/// so it's needed to verify the directory integrity.
	directory_header: Option<Rc<ZarcDirectoryHeader>>,

	/// This maps digests to frame offsets and uncompressed sizes, so reading from the directory is
	/// not required to extract a frame given its digest.
	frame_lookup: HashMap<Digest, FrameLookupEntry>,

	/// Zarc Directory, if keeping it in memory. This is only done if the directory decompresses in
	/// one step, which is the case for small to medium archives (about <128KiB of directory).
	directory: Option<Rc<ZarcDirectory>>,
}

impl<R: fmt::Debug> fmt::Debug for Decoder<'_, R> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Decoder")
			.field("reader", &self.reader)
			.field("zstd", &"zstd-safe decompression context")
			.field("file_version", &self.file_version)
			.field("directory_header_offset", &self.directory_header_offset)
			.field("directory_offset", &self.directory_offset)
			.field("directory_header", &self.directory_header)
			.field("frame_lookup", &self.frame_lookup)
			.finish()
	}
}

impl<'reader, R: Read + Seek> Decoder<'reader, R> {
	/// Create a new decoder.
	pub fn new(reader: &'reader mut R) -> Result<Self> {
		Ok(Self {
			reader,
			zstd: DCtx::try_create().ok_or(ErrorKind::ZstdInit)?,
			file_version: None,
			directory_header_offset: None,
			directory_offset: None,
			directory_header: None,
			frame_lookup: HashMap::new(),
			directory: None,
		})
	}

	/// Return the file version of the decoder.
	///
	/// This is known once the header has been read.
	pub fn file_version(&self) -> Option<u8> {
		self.file_version.map(NonZeroU8::get)
	}

	/// Return the directory digest.
	///
	/// This is known once the directory has been read.
	pub fn directory_digest(&self) -> Option<(HashAlgorithm, &Digest)> {
		todo!()
	}

	/// Return the directory signature.
	///
	/// This is known once the directory has been read.
	pub fn directory_signature(&self) -> Option<(SignatureScheme, &Signature)> {
		todo!()
	}

	/// Return the directory size (uncompressed).
	///
	/// This is known once the directory header has been read.
	pub fn directory_size(&self) -> Option<u64> {
		self.directory_header.as_ref().map(|dh| dh.directory_size)
	}

	/// Read a Skippable frame, checking its nibble.
	///
	/// Reads and returns the entire frame's payload, and thus seeks to the end of the frame.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	fn read_skippable_frame(&mut self, nibble: u8) -> Result<SkippableFrame> {
		let (bits_read, frame) =
			SkippableFrame::from_reader((&mut self.reader, 0)).map_err(SimpleError::from_deku)?;
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
	#[instrument(level = "debug", skip(self))]
	fn read_zstandard_frame_header(&mut self) -> Result<ZstandardFrameHeader> {
		let (bits_read, header) = ZstandardFrameHeader::from_reader((&mut self.reader, 0))
			.map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?header, "read zstandard frame header");
		Ok(header)
	}

	/// Read a Zstandard frame block header.
	///
	/// This reads the block header, checks that it's a Zstandard block, and leaves the reader at
	/// the start of the block's payload. The block header is returned.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	fn read_zstandard_block_header(&mut self) -> Result<ZstandardBlockHeader> {
		let (bits_read, header) = ZstandardBlockHeader::from_reader((&mut self.reader, 0))
			.map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?header, "read zstandard block header");
		Ok(header)
	}

	/// Interact with the reader directly.
	///
	/// Only available with the `expose-internals` feature, and only to be used by external
	/// consumers if they know what they're doing. This is unsafe because it allows you to break the
	/// internal state of the decoder.
	#[cfg(feature = "expose-internals")]
	pub unsafe fn with_reader(&mut self, fun: impl FnOnce(&mut R) -> Result<()>) -> Result<()> {
		fun(&mut self.reader)
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

		let frame = self.read_skippable_frame(0x0)?;

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

		let _frame_header = self.read_zstandard_frame_header()?;

		let first_block_header = self.read_zstandard_block_header()?;
		if first_block_header.block_type != ZstandardBlockType::Raw {
			return Err(ErrorKind::InvalidUnintendedMagic.into());
		}
		if first_block_header.actual_size() != 4 {
			return Err(ErrorKind::InvalidUnintendedMagic.into());
		}
		let (bits_read, unintended_magic) =
			ZarcHeader::from_reader((&mut self.reader, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?unintended_magic, "read zarc header in unintended magic raw block");
		if unintended_magic.file_version != file_version.get() {
			return Err(ErrorKind::MismatchedFileVersion.into());
		}

		// we could seek to the end of the frame, but we're going to read the trailer
		// immediately after this anyway so let's not bother

		Ok(())
	}

	/// Read the Zarc EOF Trailer.
	///
	/// This seeks to the end of the reader minus 16 bytes, then reads the EOF trailer frame, then
	/// returns the offset of the start of the Zarc Directory Header (backward from EOF) in bytes.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	fn read_eof_trailer(&mut self) -> Result<u64> {
		if self.directory_header_offset.is_some() {
			return Err(ErrorKind::ReadOrderViolation("trailer cannot be read twice").into());
		};

		self.reader.seek(SeekFrom::End(-16))?;
		let trailer = self.read_skippable_frame(0xE)?;

		let mut content = Cursor::new(trailer.data);
		let (bits_read, trailer) =
			ZarcEofTrailer::from_reader((&mut content, 0)).map_err(SimpleError::from_deku)?;

		let offset = trailer.directory_frames_size.saturating_add(16);
		debug!(%bits_read, ?trailer, directory_header_offset=%offset, "read zarc eof trailer");

		debug_assert!(offset >= 16);
		self.directory_header_offset = Some(unsafe {
			// SAFETY: we always add 16 above, so it's always non-zero
			NonZeroU64::new_unchecked(offset)
		});

		Ok(offset)
	}

	/// Read Zarc Directory Header.
	///
	/// This reads the Zarc Directory Header, and leaves the cursor at the end of the frame.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	fn read_directory_header(&mut self) -> Result<()> {
		if self.directory_header.is_some() {
			return Err(
				ErrorKind::ReadOrderViolation("directory header cannot be read twice").into(),
			);
		};
		let Some(offset) = self.directory_header_offset else {
			return Err(ErrorKind::ReadOrderViolation(
				"directory header cannot be read before trailer",
			)
			.into());
		};
		let Some(file_version) = self.file_version else {
			return Err(ErrorKind::ReadOrderViolation(
				"directory cannot be read before file header",
			)
			.into());
		};

		debug!(?offset, "seek to directory header");
		self.reader.seek(SeekFrom::End(-(offset.get() as i64)))?;

		let frame = self.read_skippable_frame(0xF)?;
		let mut content = Cursor::new(frame.data);
		let (bits_read, directory_header) =
			ZarcDirectoryHeader::from_reader((&mut content, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?directory_header, "read zarc directory header");

		if directory_header.file_version != file_version.get() {
			return Err(ErrorKind::MismatchedFileVersion.into());
		}

		self.directory_header = Some(Rc::new(directory_header));

		let offset = self.reader.stream_position()?;
		debug!(%offset, "cursor is at end of directory header, ie start of directory frame");
		debug_assert_ne!(offset, 0);
		self.directory_offset = Some(unsafe {
			// SAFETY: directory is always after (multiple) headers
			NonZeroU64::new_unchecked(offset)
		});

		Ok(())
	}

	/// Perform one step of a stream decompression.
	///
	/// The zstd session must have been properly initialised and any dictionary or parameter loaded,
	/// and the cursor must either be at the start of a frame, or left where a previous call to this
	/// method did.
	///
	/// This cursor is left at wherever the decompression stopped, which may be in the middle of a
	/// block or frame; the next call to this method will continue from there.
	///
	/// Returns the data that was decompressed and a boolean to indicate if the frame is done.
	///
	/// As with [`Self::with_reader`], this is unsafe as it can break the decoder's internal state.
	#[cfg(feature = "expose-internals")]
	pub unsafe fn manually_decompress_step(&mut self) -> Result<(Vec<u8>, bool)> {
		self.decompress_step()
	}

	#[instrument(level = "trace", skip(self))]
	fn decompress_step(&mut self) -> Result<(Vec<u8>, bool)> {
		let input_size = DCtx::in_size().max(1024);
		let mut input_buf = vec![0; input_size];
		let bytes = self.reader.read(&mut input_buf)?;
		trace!(desired=%input_size, obtained=%bytes, "read from reader to give to zstd");
		let mut input = InBuffer {
			src: &input_buf[..bytes],
			pos: 0,
		};

		let output_size = DCtx::out_size().max(1024);
		let mut output_buf: Vec<u8> = Vec::with_capacity(output_size);
		trace!(bytes=%output_size, "allocated zstd output buffer");
		let mut output = OutBuffer::around(&mut output_buf);

		trace!("decompressing");
		let mut input_hint = self
			.zstd
			.decompress_stream(&mut output, &mut input)
			.map_err(error::zstd)?;
		trace!(
			%input_hint,
			frame_done=%input_hint == 0,
			input_pos=%input.pos,
			input_size=%input.src.len(),
			output_pos=%output.pos(),
			output_size=%output.capacity(),
			"decompressed"
		);

		while output.pos() == output.capacity() {
			trace!("zstd wants more output space");
			let new_output_size = DCtx::out_size().max(1024);
			output_buf.reserve(output_size + new_output_size);
			trace!(total=%output_buf.capacity(), "allocated larger zstd output buffer");
			output = OutBuffer::around(&mut output_buf);

			trace!("decompressing again without changing input");
			input_hint = self
				.zstd
				.decompress_stream(&mut output, &mut input)
				.map_err(error::zstd)?;
			trace!(
				%input_hint,
				frame_done=%input_hint == 0,
				input_pos=%input.pos,
				input_size=%input.src.len(),
				output_pos=%output.pos(),
				output_size=%output.capacity(),
				"decompressed"
			);
		}

		let output_written = output.as_slice().len();
		trace!(bytes = output_written, "zstd has finished with the input");

		drop(output); // to release the mutable borrow on output_buf
		if output_written != output_buf.len() {
			trace!("shrink output buffer to actual written size");
			output_buf.truncate(output_written);
		}

		Ok((output_buf, input_hint == 0))
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
		self.zstd.init().map_err(error::zstd)?;
		self.reader.seek(SeekFrom::Start(offset.get()))?;

		let (data, done) = self.decompress_step()?;
		if done {
			debug!("processing entire directory in memory");
			let directory: ZarcDirectory = minicbor::decode(&data)?;

			trace!("verify directory signature");
			if !directory.signature_scheme.verify_data(
				&directory.public_key,
				&header.sig,
				header.hash.as_slice(),
			) {
				return Err(ErrorKind::DirectoryIntegrity("signature").into());
			}

			trace!("verify directory hash");
			if !directory.hash_algorithm.verify_data(&header.hash, &data) {
				return Err(ErrorKind::DirectoryIntegrity("digest").into());
			}

			trace!(frames=%directory.framelist.len(), "build frame lookup table");
			for frame in directory.framelist.iter() {
				if frame.version_added.is_some() {
					todo!("multi-version archive");
				}

				if !directory.signature_scheme.verify_data(
					&directory.public_key,
					&frame.signature,
					frame.frame_hash.as_slice(),
				) {
					return Err(ErrorKind::DirectoryIntegrity("frame signature").into());
				}

				self.frame_lookup.insert(
					frame.frame_hash.clone(),
					FrameLookupEntry {
						offset: frame.offset,
						uncompressed_size: frame.uncompressed_size,
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

	/// Iterate through the filemap.
	pub fn with_filemap(&mut self, fun: impl Fn(&FilemapEntry) -> Result<()>) -> Result<()> {
		if let Some(directory) = self.directory.as_ref().map(|dh| Rc::clone(dh)) {
			for entry in directory.filemap.iter() {
				fun(entry)?;
			}
		} else {
			todo!("streaming filemap");
		}

		Ok(())
	}
}

/// Frame lookup table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FrameLookupEntry {
	/// Frame offset.
	pub offset: u64,

	/// Uncompressed payload size in bytes.
	pub uncompressed_size: u64,
}
