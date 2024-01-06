//! Decoder types and functions.

use std::{
	collections::HashMap,
	fmt,
	io::{Cursor, Read},
};

use deku::DekuContainerRead;
use ozarc::framing::SkippableFrame;
use tracing::trace;
use zstd_safe::DCtx;

use crate::format::{Digest, ZarcHeader};

use self::error::{ErrorKind, Result, SimpleError};

pub mod error;

/// Decoder context.
pub struct Decoder<'reader, R: Read> {
	reader: &'reader mut R,
	zstd: DCtx<'reader>,
}

impl<R: Read + fmt::Debug> fmt::Debug for Decoder<'_, R> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Decoder")
			.field("reader", &self.reader)
			.field("zstd", &"zstd-safe decompression context")
			.finish()
	}
}

impl<'reader, R: Read> Decoder<'reader, R> {
	/// Create a new decoder.
	pub fn new(reader: &'reader mut R) -> Result<Self> {
		Ok(Self {
			reader,
			zstd: DCtx::try_create().ok_or(ErrorKind::ZstdInit)?,
		})
	}

	fn read_skippable_frame(&mut self, nibble: u8) -> Result<SkippableFrame> {
		let (bits_read, frame) =
			SkippableFrame::from_reader((&mut self.reader, 0)).map_err(SimpleError::from_deku)?;
		trace!(%bits_read, ?frame, nibble=%format!("0x{:X}", frame.nibble()), "read skippable frame");

		if frame.nibble() != nibble {
			return Err(ErrorKind::InvalidNibble {
				expected: nibble,
				actual: frame.nibble(),
			}
			.into());
		}

		Ok(frame)
	}

	/// Read a Zarc header.
	pub fn read_header(&mut self) -> Result<()> {
		let frame = self.read_skippable_frame(0x0)?;

		let mut content = Cursor::new(frame.data);
		let (bits_read, header) =
			ZarcHeader::from_reader((&mut content, 0)).map_err(SimpleError::from_deku)?;
		trace!(%bits_read, ?header, "read zarc header");

		if header.file_version != crate::format::ZARC_FILE_VERSION {
			return Err(ErrorKind::UnsupportedFileVersion(header.file_version).into());
		}

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
