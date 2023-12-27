//! Zarc: Archive format based on Zstd.
//!
//! [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md)
//!
//! TBD

#![warn(clippy::unwrap_used, missing_docs)]
#![deny(rust_2018_idioms)]

use std::collections::HashMap;

use deku::prelude::*;
use rmpv::Value;
use serde::{Deserialize, Serialize};

/// Magic bytes
pub const ZARC_MAGIC: [u8; 3] = [0x65, 0xAA, 0xDC];

/// Static file magic
///
/// This is a zstd Skippable frame containing the Zarc Header, as a hardcoded constant.
///
/// In a valid Zarc file, the first 12 bytes will match exactly.
///
/// For better diagnostics, you may prefer to parse the frame with zstd and [`ZarcHeader`] instead.
pub const FILE_MAGIC: [u8; 12] = [
	0x50, 0x2A, 0x4D, 0x18, // zstd skippable frame
	0x04, 0x00, 0x00, 0x00, // payload size = 4 bytes
	0x65, 0xAA, 0xDC, // zarc magic
	0x01, // zarc file version
];

/// File format version
pub const ZARC_FILE_VERSION: u8 = 1;

/// Directory structure version
pub const ZARC_DIRECTORY_VERSION: u8 = 1;

/// Zarc Header
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-header)
#[derive(Clone, Copy, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct ZarcHeader {
	/// Magic number. Should match [`ZARC_MAGIC`].
	#[deku(bytes = "3")]
	pub magic: [u8; 3],

	/// File format version number. Should match [`ZARC_FILE_VERSION`].
	#[deku(bytes = "1")]
	pub file_version: u8,
}

/// Zarc Directory Header
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-directory-header)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct ZarcDirectoryHeader {
	/// Magic number. Should match [`ZARC_MAGIC`].
	#[deku(bytes = "3")]
	pub magic: [u8; 3],

	/// File format version number. Should match [`ZARC_FILE_VERSION`].
	#[deku(bytes = "1")]
	pub file_version: u8,

	#[deku(bytes = "2", update = "self.hash.len()")]
	hash_length: u16,

	/// Digest hash of the directory
	#[deku(count = "hash_length")]
	pub hash: Vec<u8>,

	#[deku(bytes = "2", update = "self.sig.len()")]
	sig_length: u16,

	/// Signature over the digest
	#[deku(count = "sig_length")]
	pub sig: Vec<u8>,

	/// Uncompressed size in bytes of the directory
	#[deku(bytes = "8")]
	pub directory_size: u64,
}

/// Zarc EOF Trailer
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-eof-trailer)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct ZarcEofTrailer {
	/// Directory frames length in bytes.
	#[deku(bytes = "8")]
	pub directory_frames_size: u64,
}

/// Zarc Directory
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-directory)
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ZarcDirectory {
	/// The `v`, `h`, `s`, `k` fields.
	#[serde(flatten)]
	pub prelude: ZarcDirectoryPrelude,

	/// User Metadata.
	#[serde(rename = "u")]
	pub user_metadata: HashMap<String, Value>,

	/// Filemap.
	///
	/// List of files, their pathname, their metadata, and which frame of content they point to.
	#[serde(rename = "m")]
	pub filemap: Vec<FilemapEntry>,

	/// Framelist.
	///
	/// List of frames, their digest, signature, and offset in the file.
	#[serde(rename = "l")]
	pub framelist: Vec<FrameEntry>,
}

/// Zarc Directory Prelude
///
/// This is the `v`, `h`, `s`, `k` fields of the directory only.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ZarcDirectoryPrelude {
	/// Directory version. Should match [`ZARC_DIRECTORY_VERSION`].
	#[serde(rename = "v")]
	pub version: u8,

	/// Digest (hash) algorithm.
	#[serde(rename = "h")]
	pub hash_algorithm: HashAlgorithm,

	/// Signature scheme.
	#[serde(rename = "s")]
	pub signature_scheme: SignatureScheme,

	/// Public key.
	#[serde(rename = "k")]
	pub public_key: Vec<u8>,
}

/// Available digest algorithms.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum HashAlgorithm {
	/// BLAKE3 hash function.
	#[serde(rename = "b3")]
	Blake3,
}

/// Available signature schemes.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum SignatureScheme {
	/// Ed25519 scheme.
	#[serde(rename = "ed25519")]
	Ed25519,
}

/// Zarc Directory Filemap Entry
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#m-filemap)
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct FilemapEntry {
	/// Hash of a frame of content.
	#[serde(rename = "h")]
	pub frame_hash: Option<Vec<u8>>,

	/// Pathname.
	#[serde(rename = "n")]
	pub name: Pathname,

	/// User metadata.
	#[serde(rename = "u")]
	pub user_metadata: HashMap<String, Value>,

	/// Is readonly.
	#[serde(rename = "r")]
	pub readonly: Option<bool>,

	/// POSIX mode.
	#[serde(rename = "m")]
	pub mode: Option<u32>,

	/// POSIX user.
	#[serde(rename = "o")]
	pub user: Option<PosixOwner>,

	/// POSIX group.
	#[serde(rename = "g")]
	pub group: Option<PosixOwner>,

	/// File attributes.
	#[serde(rename = "a")]
	pub attributes: HashMap<String, Value>,

	/// Extended attributes.
	#[serde(rename = "x")]
	pub extended_attributes: HashMap<String, Value>,

	/// Timestamps.
	#[serde(rename = "t")]
	pub timestamps: Option<Timestamps>,

	/// Special files.
	#[serde(rename = "z")]
	pub special: Option<FilemapSpecial>,
}

/// Pathname as components.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Pathname(
	/// Components of the path.
	pub Vec<RawValue>,
);

/// Msgpack String or Binary value.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum RawValue {
	/// UTF-8-encoded string value.
	String(String),

	/// Non-unicode binary value.
	Binary(Vec<u8>),
}

/// POSIX owner information (user or group).
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct PosixOwner {
	/// Owner numeric ID.
	#[serde(rename = "i")]
	pub id: u64,

	/// Owner name.
	#[serde(rename = "n")]
	pub name: RawValue,
}

/// Directory Filemap Entry Timestamps.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Timestamps {
	/// Creation time (ctime).
	#[serde(rename = "c")]
	pub created: Option<Timestamp>,

	/// Modification time (mtime).
	#[serde(rename = "m")]
	pub modified: Option<Timestamp>,

	/// Access time (atime).
	#[serde(rename = "a")]
	pub accessed: Option<Timestamp>,

	/// Insertion time (time added to Zarc).
	#[serde(rename = "z")]
	pub inserted: Option<Timestamp>,
}

/// Msgpack timestamp.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum Timestamp {
	/// 32-bit: Seconds since the epoch
	Seconds(u32),

	/// 64-bit: Seconds and nanos since the epoch
	Nanoseconds {
		/// Seconds since the epoch
		seconds: u32,
		/// Nanoseconds within the second
		nanos: u32,
	},

	/// 96-bit: Extended range seconds and nanos
	Extended {
		/// Seconds with zero at the epoch
		seconds: i64,
		/// Nanoseconds within the second
		nanos: u32,
	},
}

/// Special File metadata.
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#z-special-file-types)
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct FilemapSpecial {
	/// Kind of special file.
	#[serde(rename = "t")]
	pub kind: SpecialFile,

	/// Link target.
	#[serde(rename = "d")]
	pub link_target: LinkTarget,
}

/// Special File kinds.
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#z-special-file-types)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
pub enum SpecialFile {
	/// Normal file.
	///
	/// Generally unneeded (omit the `z` special file structure).
	NormalFile = 0x00,

	/// Directory.
	///
	/// To encode metadata/attributes against a directory.
	Directory = 0x01,

	/// Internal hardlink.
	///
	/// Must point to a file that exists within this Zarc.
	InternalHardlink = 0x10,

	/// External hardlink.
	ExternalHardlink = 0x11,

	/// Internal symbolic link.
	///
	/// Must point to a file that exists within this Zarc.
	InternalSymlink = 0x12,

	/// External absolute symbolic link.
	ExternalAbsoluteSymlink = 0x13,

	/// External relative symbolic link.
	ExternalRelativeSymlink = 0x14,
}

/// Target of link (for [`FilemapSpecial`])
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#z-special-file-types)
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum LinkTarget {
	/// Target as full pathname.
	FullPath(RawValue),

	/// Target as array of path components.
	Components(Vec<RawValue>),
}

/// Zarc Directory Framelist Entry
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#l-framelist)
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct FrameEntry {
	/// Frame offset.
	#[serde(rename = "o")]
	pub offset: u64,

	/// Uncompressed payload size in bytes.
	#[serde(rename = "n")]
	pub uncompressed_size: u64,

	/// Zstandard frame checksum.
	#[serde(rename = "c")]
	pub checksum: [u8; 4],

	/// Payload digest.
	#[serde(rename = "h")]
	pub digest: Vec<u8>,

	/// Signature against digest.
	#[serde(rename = "s")]
	pub signature: Vec<u8>,
}
