//! Decoder types and functions.

use std::{collections::{HashMap, BTreeMap}, num::NonZeroU16};

use crate::{
	directory::{File, Frame, Pathname, Edition},
	integrity::Digest,
	ondemand::OnDemand,
	trailer::Trailer,
};

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
/// Reader needs to be Seek, as Zarc reads the file backwards from the end to find the trailer and directory.
#[derive(Debug)]
pub struct Decoder<R> {
	// given by user
	reader: R,

	// obtained from trailer
	file_length: u64,
	trailer: Trailer,

	// obtained from directory
	editions: BTreeMap<NonZeroU16, Edition>,
	files: Vec<File>,
	frames: HashMap<Digest, Frame>,
	files_by_name: BTreeMap<Pathname, Vec<usize>>,
	files_by_digest: HashMap<Digest, Vec<usize>>,
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

	/// Iterate through the editions.
	pub fn editions(&self) -> impl Iterator<Item = &Edition> {
		self.editions.values()
	}

	/// Get edition metadata by number.
	pub fn edition(&self, number: impl TryInto<NonZeroU16>) -> Option<&Edition> {
		number.try_into().ok().and_then(|number| self.editions.get(&number))
	}

	/// Get the latest (current) edition.
	pub fn latest_edition(&self) -> Option<&Edition> {
		self.editions.values().last()
	}

	/// Iterate through the files.
	pub fn files(&self) -> impl Iterator<Item = &File> {
		self.files.iter()
	}

	/// Get file entries that have a particular (path)name.
	pub fn files_by_name(&self, name: impl Into<Pathname>) -> Option<Vec<&File>> {
		self.files_by_name.get(&name.into()).map(Vec::as_slice).map(|v| {
			v.iter().filter_map(|i| self.files.get(*i)).collect()
		})
	}

	/// Get files that reference a frame from its digest.
	pub fn files_by_digest(&self, digest: &Digest) -> Option<Vec<&File>> {
		self.files_by_digest.get(digest).map(Vec::as_slice).map(|v| {
			v.iter().filter_map(|i| self.files.get(*i)).collect()
		})
	}

	/// Iterate through the frames.
	pub fn frames(&self) -> impl Iterator<Item = &Frame> {
		self.frames.values()
	}

	/// Get frame metadata by digest.
	pub fn frame(&self, digest: &Digest) -> Option<&Frame> {
		self.frames.get(digest)
	}
}
