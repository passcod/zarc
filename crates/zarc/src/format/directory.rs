use std::{collections::HashMap, num::NonZeroU16};

use minicbor::{Decode, Encode};

use super::{
	integrity::{Digest, DigestType, PublicKey, Signature, SignatureType},
	posix_owner::PosixOwner,
	specials::SpecialFile,
	strings::{AttributeValue, Pathname},
	timestamps::{Timestamp, Timestamps},
};

/// Zarc Directory
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-directory)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct ZarcDirectory {
	/// Editions.
	///
	/// Editions are the versions of the archive. There will always be one edition, and if the file
	/// is modified or appended to, a new edition will be introduced.
	#[n(1)]
	pub editions: Vec<Edition>,

	/// Files.
	///
	/// List of files, their pathname, their metadata, and which frame of content they point to.
	#[n(2)]
	pub filemap: Vec<FilemapEntry>,

	/// Frames.
	///
	/// List of frames, their digest, signature, and offset in the file.
	#[n(3)]
	pub framelist: Vec<FrameEntry>,
}

/// Metadata about a (previous) version of the Zarc Directory
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#13-prior-versions)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct Edition {
	/// Edition number.
	///
	/// Used for referencing it in frames and files.
	#[n(0)]
	pub number: NonZeroU16,

	/// Public key of this edition.
	#[n(1)]
	pub public_key: PublicKey,

	/// Version creation date.
	#[n(2)]
	pub written_at: Timestamp,

	/// Digest algorithm used by this edition.
	#[n(3)]
	pub digest_type: DigestType,

	/// Signature algorithm used by this edition.
	#[n(4)]
	pub signature_type: SignatureType,

	/// User Metadata of that version.
	///
	/// You can write a Some(empty HashMap), but you'll save two bytes if you write a None instead.
	/// This is pretty cheap here, but adds up for the similar fields in [`files`](FilemapEntry).
	#[n(10)]
	pub user_metadata: Option<HashMap<String, AttributeValue>>,
}

/// Zarc Directory Filemap Entry
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#4-filemap)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct FilemapEntry {
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

/// Zarc Directory Framelist Entry
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#l-framelist)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct FrameEntry {
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
