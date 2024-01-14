use std::io::{Error, Result, Write};

use tracing::{instrument, trace};
use zstd_safe::ResetDirective;

use crate::{directory::Frame, integrity::Digest, map_zstd_error};

use super::Encoder;

impl<'writer, W: Write> Encoder<'writer, W> {
	/// Add a frame of data.
	///
	/// Processes the entire input in memory.
	///
	/// Returns the hash of the data, so it can be referenced in a filemap entry.
	///
	/// If the content hashes to a frame that already exists, returns the hash without storing
	/// a duplicate frame.
	#[instrument(level = "trace", skip(self, content))]
	pub fn add_data_frame(&mut self, content: &[u8]) -> Result<Digest> {
		// collect pre-compression values
		let offset = self.offset.try_into().map_err(Error::other)?;
		let uncompressed_size = content.len();

		// compute content hash
		let digest = blake3::hash(content);
		let digest = Digest(digest.as_bytes().to_vec());
		trace!(%uncompressed_size, digest=%format!("{digest:02x?}"), "computed digest");

		if self.frames.contains_key(&digest) {
			trace!("frame already exists, skipping");
			return Ok(digest);
		}

		let bytes = if self.compress {
			// start new compression context
			self.zstd
				.reset(ResetDirective::SessionOnly)
				.map_err(map_zstd_error)?;

			self.write_compressed_frame(content)
		} else {
			self.write_uncompressed_frame(content)
		}?;
		self.offset += bytes;

		// push frame to list
		self.frames.insert(
			digest.clone(),
			Frame {
				edition: self.edition,
				offset,
				digest: digest.clone(),
				length: bytes as _,
				uncompressed: uncompressed_size as _,
			},
		);

		Ok(digest)
	}
}
