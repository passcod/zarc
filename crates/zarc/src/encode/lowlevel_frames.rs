use std::io::{Result, Write};

use deku::DekuContainerWrite;
use tracing::{instrument, trace};

use crate::map_zstd_error;

use super::Encoder;

impl<'writer, W: Write> Encoder<'writer, W> {
	/// Write a compressed frame.
	///
	/// Zstd-safe is bad at writing data, so we always write to a buffer in memory and then write
	/// that buffer to the writer.
	///
	/// Returns the amount of bytes written.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "trace", skip(self, data))]
	pub(crate) fn write_compressed_frame(&mut self, data: &[u8]) -> Result<usize> {
		// start with a buffer slightly larger than the input
		let mut buffer: Vec<u8> = Vec::with_capacity(data.len() + 1024.max(data.len() / 10));

		trace!(
			bytes = %format!("{data:02x?}"),
			length = %data.len(),
			buffer_size = %buffer.capacity(),
			"compress data into buffer"
		);
		self.zstd
			.compress2(&mut buffer, data)
			.map_err(map_zstd_error)?;

		trace!(
			bytes = %format!("{buffer:02x?}"),
			length = %buffer.len(),
			"write buffer to writer"
		);
		self.writer.write(&buffer)
	}

	/// Write an uncompressed frame.
	///
	/// Zstd can't write fully-uncompressed data, so we use [`ozarc`]'s types to write raw blocks
	/// and the frame directly.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "trace", skip(self, data))]
	pub(crate) fn write_uncompressed_frame(&mut self, data: &[u8]) -> Result<usize> {
		use ozarc::framing::*;
		let mut frame = ZstandardFrame {
			header: ZstandardFrameHeader {
				frame_descriptor: ZstandardFrameDescriptor {
					fcs_size: 3,
					single_segment: false,
					unused_bit: false,
					reserved_bit: false,
					checksum: false,
					did_size: 0,
				},
				window_descriptor: None,
				did: Vec::new(),
				frame_content_size: u64::try_from(data.len()).unwrap().to_le_bytes().to_vec(),
			},
			blocks: data
				.chunks(u16::MAX as _)
				.map(|data| ZstandardBlock {
					header: ZstandardBlockHeader::new(
						ZstandardBlockType::Raw,
						false,
						u32::try_from(data.len()).unwrap(), // UNWRAP: chunks() limits to u16
					),
					data: data.into(),
				})
				.collect(),
			checksum: None,
		};

		if let Some(last) = frame.blocks.last_mut() {
			last.header.last = true;
		}

		self.writer.write(&frame.to_bytes()?)
	}

	/// Write a skippable frame.
	///
	/// Zstd-safe doesn't have an API for this, so we use [`ozarc`].
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "trace", skip(self, magic, data))]
	pub(crate) fn write_skippable_frame(&mut self, magic: u8, data: Vec<u8>) -> Result<usize> {
		trace!(
			bytes = %format!("{data:02x?}"),
			length = %data.len(),
			magic,
			"compose data into frame"
		);
		let frame = ozarc::framing::SkippableFrame::new(magic, data);
		let buffer = frame.to_bytes()?;

		trace!(
			bytes = %format!("{buffer:02x?}"),
			length = %buffer.len(),
			"write buffer to writer"
		);
		self.writer.write(&buffer)
	}
}
