//! Decoder types and functions.

use std::collections::HashMap;

use crate::format::Digest;

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
