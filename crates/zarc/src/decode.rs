//! Decoder types and functions.

use std::{
	collections::HashMap,
	fmt,
	io::{Cursor, Read, Seek, SeekFrom},
	num::{NonZeroU64, NonZeroU8},
};

use deku::DekuContainerRead;
use ozarc::framing::{
	SkippableFrame, ZstandardBlockHeader, ZstandardBlockType, ZstandardFrameHeader,
};
use tracing::{debug, trace};
use zstd_safe::DCtx;

use crate::format::{
	Digest, HashAlgorithm, Signature, SignatureScheme, ZarcDirectoryHeader, ZarcEofTrailer,
	ZarcHeader,
};

use self::error::{ErrorKind, Result, SimpleError};

pub mod error;

/// Decoder context.
///
/// Reader needs to be Seek, as Zarc reads the file backwards from the end to find the directory.
pub struct Decoder<'reader, R> {
	reader: &'reader mut R,
	zstd: DCtx<'reader>,
	file_version: Option<NonZeroU8>,
	directory_header_offset: Option<NonZeroU64>,
	directory_header: Option<ZarcDirectoryHeader>,
}

impl<R: fmt::Debug> fmt::Debug for Decoder<'_, R> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Decoder")
			.field("reader", &self.reader)
			.field("zstd", &"zstd-safe decompression context")
			.field("file_version", &self.file_version)
			.field("directory_header_offset", &self.directory_header_offset)
			.field("directory_header", &self.directory_header)
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
			directory_header: None,
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
	fn read_zstandard_block_header(&mut self) -> Result<ZstandardBlockHeader> {
		let (bits_read, header) = ZstandardBlockHeader::from_reader((&mut self.reader, 0))
			.map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?header, "read zstandard block header");
		Ok(header)
	}

	/// Read a Zarc header.
	///
	/// Sets the file version of the decoder.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
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
	/// magic, then seeks to the end of the frame.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	fn read_unintended_magic(&mut self) -> Result<()> {
		let Some(file_version) = self.file_version else {
			return Err(ErrorKind::ReadOrderViolation(
				"unintended magic cannot be read before header",
			)
			.into());
		};

		let frame_header = self.read_zstandard_frame_header()?;

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

		debug!("unintended magic is valid, skip to the end of the frame");
		let mut block_header = first_block_header;
		while !block_header.last {
			block_header = self.read_zstandard_block_header()?;
			let seek_bytes = block_header.actual_size() as i64;
			trace!(?block_header, %seek_bytes, "skip block");
			self.reader.seek(SeekFrom::Current(seek_bytes))?;
		}

		if frame_header.frame_descriptor.checksum {
			trace!("skip checksum");
			self.reader.seek(SeekFrom::Current(4))?;
		}

		Ok(())
	}

	/// Read the Zarc EOF Trailer.
	///
	/// This seeks to the end of the reader minus 16 bytes, then reads the EOF trailer frame, then
	/// returns the offset of the start of the Zarc Directory Header (backward from EOF) in bytes.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
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

		self.directory_header = Some(directory_header);
		Ok(())
	}
}

/// Frame lookup hashtable.
#[derive(Clone, Debug)]
pub struct FrameLookup(pub HashMap<Digest, FrameLookupEntry>);

/// Frame lookup table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FrameLookupEntry {
	/// Frame offset.
	pub offset: u64,

	/// Uncompressed payload size in bytes.
	pub uncompressed_size: u64,
}
