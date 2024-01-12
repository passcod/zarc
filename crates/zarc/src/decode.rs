//! Decoder types and functions.

use std::{collections::HashMap, rc::Rc};

use crate::{
	directory::{File, LegacyDirectory},
	integrity::Digest,
	ondemand::OnDemand,
	trailer::Trailer,
};

use self::directory::FrameLookupEntry;

#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
#[doc(inline)]
pub(crate) use self::zstd_iterator::ZstdFrameIterator;

#[doc(inline)]
pub use self::frame_iterator::FrameIterator;

mod directory;
pub mod error;
mod frame_iterator;
mod open;
mod zstd_iterator;

/// Decoder context.
///
/// Reader needs to be Seek, as Zarc reads the file backwards from the end to find the directory.
#[derive(Debug)]
pub struct Decoder<R> {
	reader: R,

	/// Length of the file in bytes.
	file_length: u64,

	/// Trailer, once known.
	///
	/// This contains the digest and signature of the directory, so it's needed to verify the
	/// directory integrity.
	trailer: Trailer,

	/// This maps digests to frame offsets and uncompressed sizes, so reading from the directory is
	/// not required to extract a frame given its digest.
	frame_lookup: HashMap<Digest, FrameLookupEntry>,

	/// Zarc Directory, if keeping it in memory. This is only done if the directory decompresses in
	/// one step, which is the case for small to medium archives (about <128KiB of directory).
	directory: Option<Rc<LegacyDirectory>>,
}

impl<R: OnDemand> Decoder<R> {
	/// Length of the file in bytes.
	pub fn file_length(&self) -> u64 {
		self.file_length
	}

	/// The trailer metadata.
	pub fn trailer(&self) -> &Trailer {
		&self.trailer
	}

	/// Iterate through the filemap.
	///
	/// TODO: Really this should be an iterator.
	pub fn with_filemap(&self, fun: impl Fn(&File)) {
		if let Some(directory) = self.directory.as_ref().map(|dh| Rc::clone(dh)) {
			for entry in directory.filemap.iter() {
				fun(entry);
			}
		} else {
			todo!("streaming filemap");
		}
	}
}
