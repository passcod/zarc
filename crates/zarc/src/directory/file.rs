use std::{collections::HashMap, num::NonZeroU16};

use minicbor::{Decode, Encode};

use super::{
	posix_owner::PosixOwner,
	specials::SpecialFile,
	strings::{AttributeValue, Pathname},
	timestamps::Timestamps,
};
use crate::integrity::Digest;

/// Zarc Directory File Entry
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#kind-2-files)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct File {
	/// Edition that added this entry.
	#[n(0)]
	pub edition: NonZeroU16,

	/// Pathname.
	#[n(1)]
	pub name: Pathname,

	/// Hash of a frame of content.
	#[n(2)]
	pub frame_hash: Option<Digest>,

	/// POSIX mode.
	#[n(3)]
	pub mode: Option<u32>,

	/// POSIX user.
	#[n(4)]
	pub user: Option<PosixOwner>,

	/// POSIX group.
	#[n(5)]
	pub group: Option<PosixOwner>,

	/// Timestamps.
	#[n(6)]
	pub timestamps: Option<Timestamps>,

	/// Special files.
	#[n(7)]
	pub special: Option<SpecialFile>,

	/// User metadata.
	#[n(10)]
	pub user_metadata: Option<HashMap<String, AttributeValue>>,

	/// File attributes.
	#[n(11)]
	pub attributes: Option<HashMap<String, AttributeValue>>,

	/// Extended attributes.
	#[n(12)]
	pub extended_attributes: Option<HashMap<String, AttributeValue>>,
}
