use std::num::NonZeroU16;

use minicbor::{Decode, Encode};

use crate::integrity::{Digest, Signature};

/// Zarc Directory Frame Entry
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#kind-3-frames)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct Frame {
	/// Edition which added this frame.
	#[n(0)]
	pub edition: NonZeroU16,

	/// Frame offset.
	#[n(1)]
	pub offset: u64,

	/// Hash of the frame.
	#[n(2)]
	pub frame_hash: Digest,

	/// Signature against hash.
	#[n(3)]
	pub signature: Signature,

	/// Entire frame length in bytes.
	#[n(4)]
	pub length: u64,

	/// Uncompressed content size in bytes.
	#[n(5)]
	pub uncompressed: u64,
}
