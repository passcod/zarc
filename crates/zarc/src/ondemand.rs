//! On-demand reader+seek trait and implementations.
//!
//! This is a trait that allows for obtaining multiple reader+seeker instances from a single byte
//! source. Zarc uses it to allow for reading from multiple places in the source at the same time.
//!
//! This is implemented for files ([`Path`] and [`PathBuf`]) in this crate.

use std::{
	fs::File,
	io::{Read, Result, Seek},
	path::{Path, PathBuf},
};

/// On-demand independent readers for a byte source.
pub trait OnDemand {
	/// The output reader type.
	type Reader: Read + Seek;

	/// Open an independent reader for this byte source.
	fn open(&self) -> Result<Self::Reader>;
}

impl OnDemand for &Path {
	type Reader = File;

	fn open(&self) -> Result<Self::Reader> {
		File::open(self)
	}
}

impl OnDemand for PathBuf {
	type Reader = File;

	fn open(&self) -> Result<Self::Reader> {
		File::open(self)
	}
}
