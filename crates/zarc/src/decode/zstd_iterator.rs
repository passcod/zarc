use std::{
	fmt,
	io::{Read, Seek, SeekFrom},
};

use tracing::{debug, instrument, trace};
use zstd_safe::{DCtx, InBuffer, OutBuffer};

use crate::ondemand::OnDemand;

use super::{
	error::{self, ErrorKind, Result},
	Decoder,
};

impl<R: OnDemand> Decoder<R> {
	/// Read a Zstandard frame, decompressing it on demand.
	///
	/// This opens a new reader, seeks to the position given, and returns an iterator of chunks of
	/// bytes. Each call to the iterator decompresses some data and returns it, until the frame is
	/// exhausted.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	pub(crate) fn read_zstandard_frame(
		&self,
		offset: u64,
	) -> Result<ZstdFrameIterator<'_, R::Reader>> {
		let mut reader = self.reader.open()?;
		let zstd = DCtx::try_create().ok_or(ErrorKind::ZstdInit)?;
		// TODO method to create zstd context with the parameters saved against Decoder

		debug!(%offset, "seek to frame");
		reader.seek(SeekFrom::Start(offset))?;

		Ok(ZstdFrameIterator::new(reader, zstd, offset))
	}
}

/// Iterator over a zstandard frame's chunks.
///
/// This is returned by [`Decoder::read_zstandard_frame()`][super::Decoder::read_zstandard_frame].
///
/// Each call to the iterator decompresses some data and returns it, until the frame is exhausted.
/// It also computes the frame's digest as it goes, so you can check it against the one you used to
/// request the frame.
pub struct ZstdFrameIterator<'zstd, R> {
	reader: R,
	zstd: DCtx<'zstd>,
	start_offset: u64,
	done: bool,
}

impl<R: fmt::Debug> fmt::Debug for ZstdFrameIterator<'_, R> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ZstdFrameIterator")
			.field("reader", &self.reader)
			.field("zstd", &"zstd-safe decompression context")
			.field("start_offset", &self.start_offset)
			.field("done", &self.done)
			.finish()
	}
}

impl<'zstd, R> ZstdFrameIterator<'zstd, R> {
	/// Return `true` if the iterator is done, without advancing it.
	pub fn is_done(&self) -> bool {
		self.done
	}
}

impl<'zstd, R: Read + Seek> ZstdFrameIterator<'zstd, R> {
	pub(crate) fn new(reader: R, zstd: DCtx<'zstd>, start_offset: u64) -> Self {
		Self {
			reader,
			zstd,
			start_offset,
			done: false,
		}
	}

	/// Perform one step of a stream decompression.
	///
	/// This cursor is left at wherever the decompression stopped, which may be in the middle of a
	/// block or frame; the next call to this method will continue from there.
	///
	/// Returns the data that was decompressed and a boolean to indicate if the frame is done.
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

		#[allow(clippy::drop_non_drop)]
		drop(output); // to release the mutable borrow on output_buf

		if output_written != output_buf.len() {
			trace!("shrink output buffer to actual written size");
			output_buf.truncate(output_written);
		}

		Ok((output_buf, input_hint == 0))
	}
}

impl<'zstd, R: Read + Seek> Iterator for ZstdFrameIterator<'zstd, R> {
	type Item = Result<Vec<u8>>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.done {
			return None;
		}

		let (data, done) = match self.decompress_step() {
			Ok(ok) => ok,
			Err(err) => return Some(Err(err)),
		};

		if done {
			self.done = true;
		}

		Some(Ok(data))
	}
}
