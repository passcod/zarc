//! Decoder types and functions.

use std::io::{Read, Seek};

use crate::{format::Digest, ondemand::OnDemand};

use super::{
	error::{ErrorKind, Result},
	Decoder, ZstdFrameIterator,
};

impl<R: OnDemand> Decoder<R> {
	/// Decompress a content frame by digest.
	///
	/// This returns an iterator of chunks of bytes. Each call to the iterator decompresses some
	/// data and returns it, until the frame is exhausted.
	pub fn read_content_frame(
		&self,
		digest: &Digest,
	) -> Result<Option<FrameIterator<'_, R::Reader>>> {
		let Some(entry) = self.frame_lookup.get(digest) else {
			return Ok(None);
		};

		if entry.offset == 12 {
			// this is the unintended magic frame, which is not a content frame
			return Ok(None);
		}

		let Some(directory_offset) = self.directory_offset else {
			return Err(ErrorKind::ReadOrderViolation(
				"content frames cannot be read before directory header",
			)
			.into());
		};
		if entry.offset == directory_offset.get() {
			// this is the directory frame, which is not a content frame
			return Ok(None);
		}

		Ok(Some(FrameIterator::new(
			self.read_zstandard_frame(entry.offset)?,
			digest.clone(),
			entry.uncompressed,
		)))
	}
}

/// Iterator over a Zarc content frame's chunks.
///
/// This is returned by [`Decoder::read_content_frame()`][super::Decoder::read_content_frame].
///
/// Each call to the iterator decompresses some data and returns it, until the frame is exhausted.
/// It also computes the frame's digest as it goes, so you can check it against the one you used to
/// request the frame.
#[derive(Debug)]
pub struct FrameIterator<'zstd, R> {
	framer: ZstdFrameIterator<'zstd, R>,
	hasher: blake3::Hasher,
	digest: Digest,
	uncompressed_size: u64,
	uncompressed_read: u64,
}

impl<'zstd, R> FrameIterator<'zstd, R> {
	pub(crate) fn new(
		framer: ZstdFrameIterator<'zstd, R>,
		digest: Digest,
		uncompressed_size: u64,
	) -> Self {
		Self {
			framer,
			hasher: blake3::Hasher::new(),
			digest,
			uncompressed_size,
			uncompressed_read: 0,
		}
	}

	/// Return the uncompressed size of the frame.
	pub fn uncompressed_size(&self) -> u64 {
		self.uncompressed_size
	}

	/// How many (uncompressed) bytes are left to go.
	pub fn bytes_left(&self) -> u64 {
		self.uncompressed_size
			.saturating_sub(self.uncompressed_read)
	}

	/// Return the digest of the frame.
	///
	/// Returns None if the iterator isn't yet done.
	pub fn digest(&self) -> Option<Digest> {
		if self.framer.is_done() {
			Some(Digest(self.hasher.finalize().as_bytes().to_vec()))
		} else {
			None
		}
	}

	/// Check the digest of the frame.
	///
	/// Returns None if the iterator isn't yet done.
	pub fn verify(&self) -> Option<bool> {
		self.digest().map(|d| d == self.digest)
	}
}

impl<'zstd, R: Read + Seek> Iterator for FrameIterator<'zstd, R> {
	type Item = Result<Vec<u8>>;

	fn next(&mut self) -> Option<Self::Item> {
		let data = self.framer.next()?;

		if let Ok(data) = &data {
			self.uncompressed_read += data.len() as u64;
			self.hasher.update(&data);
		}

		Some(data)
	}
}
