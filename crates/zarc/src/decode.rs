//! Decoder types and functions.

use std::{
	collections::HashMap,
	num::{NonZeroU64, NonZeroU8},
	rc::Rc,
};

use crate::{
	format::{
		Digest, FilemapEntry, HashAlgorithm, Signature, SignatureScheme, ZarcDirectory,
		ZarcDirectoryHeader,
	},
	ondemand::OnDemand,
};

use self::{error::Result, prepare::FrameLookupEntry};

#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
#[doc(inline)]
pub(crate) use self::zstd_iterator::ZstdFrameIterator;

#[doc(inline)]
pub use self::frame_iterator::FrameIterator;

pub mod error;
mod frame_iterator;
mod prepare;
mod zstd_iterator;

/// Decoder context.
///
/// Reader needs to be Seek, as Zarc reads the file backwards from the end to find the directory.
#[derive(Debug)]
pub struct Decoder<R> {
	reader: R,

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

impl<R: OnDemand> Decoder<R> {
	/// Create a new decoder.
	pub fn new(reader: R) -> Result<Self> {
		Ok(Self {
			reader,
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

	/// Iterate through the filemap.
	///
	/// TODO: Really this should be an iterator.
	pub fn with_filemap(&self, fun: impl Fn(&FilemapEntry)) {
		if let Some(directory) = self.directory.as_ref().map(|dh| Rc::clone(dh)) {
			for entry in directory.filemap.iter() {
				fun(entry);
			}
		} else {
			todo!("streaming filemap");
		}
	}
}
