//! Common types defining the binary format structures.

use std::{
	collections::HashMap,
	ffi::OsStr,
	path::{Component, Path},
	time::SystemTime,
};

use deku::prelude::*;
use minicbor::{data::Type, Decode, Decoder, Encode, Encoder};

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
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct ZarcHeader {
	/// Magic number. Should match [`ZARC_MAGIC`].
	#[deku(count = "3")]
	pub magic: Vec<u8>,

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
	#[deku(count = "3")]
	pub magic: Vec<u8>,

	/// File format version number. Should match [`ZARC_FILE_VERSION`].
	#[deku(bytes = "1")]
	pub file_version: u8,

	#[deku(bytes = "2", update = "self.hash.len()")]
	hash_length: u16,

	/// Digest hash of the directory
	#[deku(
		count = "hash_length",
		map = "|field: Vec<u8>| -> Result<_, DekuError> { Ok(Digest(field)) }",
		writer = "self.hash.0.write(deku::output, ())"
	)]
	pub hash: Digest,

	#[deku(bytes = "2", update = "self.sig.len()")]
	sig_length: u16,

	/// Signature over the digest
	#[deku(
		count = "sig_length",
		map = "|field| -> Result<_, DekuError> { Ok(Signature(field)) }",
		writer = "self.sig.0.write(deku::output, ())"
	)]
	pub sig: Signature,

	/// Uncompressed size in bytes of the directory
	#[deku(bytes = "8")]
	pub directory_size: u64,
}

impl ZarcDirectoryHeader {
	/// Correctly create header from data.
	pub fn new(size: usize, hash: Vec<u8>, sig: Vec<u8>) -> std::io::Result<Self> {
		Ok(Self {
			directory_size: size.try_into().map_err(|err| std::io::Error::other(err))?,
			magic: ZARC_MAGIC.to_vec(),
			file_version: ZARC_FILE_VERSION,
			hash_length: hash
				.len()
				.try_into()
				.map_err(|err| std::io::Error::other(format!("hash is too long: {err}")))?,
			hash: Digest(hash),
			sig_length: sig
				.len()
				.try_into()
				.map_err(|err| std::io::Error::other(format!("signature is too long: {err}")))?,
			sig: Signature(sig),
		})
	}
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
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct ZarcDirectory {
	/// Directory version. Should match [`ZARC_DIRECTORY_VERSION`].
	#[n(0)]
	pub version: u8,

	/// Digest (hash) algorithm.
	#[n(1)]
	pub hash_algorithm: HashAlgorithm,

	/// Signature scheme.
	#[n(2)]
	pub signature_scheme: SignatureScheme,

	/// Public key.
	#[n(3)]
	pub public_key: PublicKey,

	/// Filemap.
	///
	/// List of files, their pathname, their metadata, and which frame of content they point to.
	#[n(4)]
	pub filemap: Vec<FilemapEntry>,

	/// Framelist.
	///
	/// List of frames, their digest, signature, and offset in the file.
	#[n(5)]
	pub framelist: Vec<FrameEntry>,

	/// User Metadata.
	///
	/// You can write a Some(empty HashMap), but you'll save two bytes if you write a None
	/// instead. This is pretty cheap here, but adds up for the similar fields in
	/// [`filemap`](FilemapEntry).
	#[n(10)]
	pub user_metadata: Option<HashMap<String, AttributeValue>>,
}

macro_rules! bytea_newtype {
	($name:ident # $doc:literal) => {
		#[doc = $doc]
		#[derive(Clone, Debug, Eq, PartialEq, Hash)]
		pub struct $name(pub Vec<u8>);

		impl std::ops::Deref for $name {
			type Target = Vec<u8>;

			fn deref(&self) -> &Self::Target {
				&self.0
			}
		}

		impl<C> Encode<C> for $name {
			fn encode<W: minicbor::encode::write::Write>(
				&self,
				e: &mut Encoder<W>,
				_ctx: &mut C,
			) -> Result<(), minicbor::encode::Error<W::Error>> {
				e.bytes(&self.0).map(drop)
			}
		}

		impl<'b, C> Decode<'b, C> for $name {
			fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
				match d.datatype()? {
					Type::Bytes => d.bytes().map(|b| Self(b.into())),
					Type::BytesIndef => Ok(Self(d.bytes_iter()?.try_fold(
						Vec::new(),
						|mut vec, b| {
							b.map(|b| {
								vec.extend(b);
								vec
							})
						},
					)?)),
					ty => Err(minicbor::decode::Error::type_mismatch(ty)),
				}
			}
		}
	};
}

bytea_newtype!(Digest # "Hash or digest.");
bytea_newtype!(Signature # "Signature.");
bytea_newtype!(PublicKey # "Public key.");

/// Available digest algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Encode, Decode)]
#[cbor(index_only)]
pub enum HashAlgorithm {
	/// BLAKE3 hash function.
	#[n(1)]
	Blake3,
}

/// Available signature schemes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Encode, Decode)]
#[cbor(index_only)]
pub enum SignatureScheme {
	/// Ed25519 scheme.
	#[n(1)]
	Ed25519,
}

/// Zarc Directory Filemap Entry
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#4-filemap)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct FilemapEntry {
	/// Pathname.
	#[n(0)]
	pub name: Pathname,

	/// Hash of a frame of content.
	#[n(1)]
	pub frame_hash: Option<Digest>,

	/// Is readonly.
	#[n(2)]
	pub readonly: Option<bool>,

	/// POSIX mode.
	#[n(3)]
	pub mode: Option<u32>,

	/// POSIX user.
	#[n(4)]
	pub user: Option<PosixOwner>,

	/// POSIX group.
	#[n(5)]
	pub group: Option<PosixOwner>,

	/// User metadata.
	#[n(10)]
	pub user_metadata: Option<HashMap<String, AttributeValue>>,

	/// File attributes.
	#[n(11)]
	pub attributes: Option<HashMap<String, AttributeValue>>,

	/// Extended attributes.
	#[n(12)]
	pub extended_attributes: Option<HashMap<String, AttributeValue>>,

	/// Timestamps.
	#[n(20)]
	pub timestamps: Option<Timestamps>,

	/// Special files.
	#[n(30)]
	pub special: Option<SpecialFile>,
}

/// Pathname as components.
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(transparent)]
pub struct Pathname(
	/// Components of the path.
	#[n(0)] // but unused because of transparent
	pub  Vec<CborString>,
	// double space is from rustfmt: https://github.com/rust-lang/rustfmt/issues/5997
);

impl Pathname {
	/// Converts a Path, ignoring all non-normal components.
	pub fn from_normal_components(path: &Path) -> Self {
		Self(
			path.components()
				.filter_map(|c| {
					if let Component::Normal(comp) = c {
						Some(CborString::from(comp))
					} else {
						None
					}
				})
				.collect(),
		)
	}
}

/// CBOR Text or Byte string.
#[derive(Clone, Debug, PartialEq)]
pub enum CborString {
	/// UTF-8 text string value.
	String(String),

	/// Non-unicode byte string value.
	Binary(Vec<u8>),
}

impl From<&OsStr> for CborString {
	fn from(string: &OsStr) -> Self {
		if let Some(unicode) = string.to_str() {
			Self::String(unicode.into())
		} else {
			#[cfg(unix)]
			{
				use std::os::unix::ffi::OsStrExt;
				Self::Binary(string.as_bytes().into())
			}
			#[cfg(not(unix))]
			{
				Self::Binary(string.as_encoded_bytes().into())
			}
		}
	}
}

impl From<&str> for CborString {
	fn from(string: &str) -> Self {
		Self::String(string.into())
	}
}

impl From<String> for CborString {
	fn from(string: String) -> Self {
		Self::String(string)
	}
}

impl<C> Encode<C> for CborString {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		match self {
			Self::String(s) => s.encode(e, ctx),
			Self::Binary(b) => <&minicbor::bytes::ByteSlice>::from(b.as_slice()).encode(e, ctx),
		}
	}
}

impl<'b, C> Decode<'b, C> for CborString {
	fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		match d.datatype()? {
			Type::String => d.str().map(|s| Self::String(s.into())),
			Type::StringIndef => Ok(Self::String(d.str_iter()?.try_fold(
				String::new(),
				|mut string, s| {
					s.map(|s| {
						string.extend(s.chars());
						string
					})
				},
			)?)),
			Type::Bytes => d.bytes().map(|b| Self::Binary(b.into())),
			Type::BytesIndef => Ok(Self::Binary(d.bytes_iter()?.try_fold(
				Vec::new(),
				|mut vec, b| {
					b.map(|b| {
						vec.extend(b);
						vec
					})
				},
			)?)),
			ty => Err(minicbor::decode::Error::type_mismatch(ty)),
		}
	}
}

/// Attributes can be booleans or text or byte strings.
#[derive(Clone, Debug, PartialEq)]
pub enum AttributeValue {
	/// A boolean.
	Boolean(bool),

	/// A string.
	String(CborString),
}

impl From<bool> for AttributeValue {
	fn from(b: bool) -> Self {
		Self::Boolean(b)
	}
}

impl<T> From<T> for AttributeValue
where
	T: Into<CborString>,
{
	fn from(string: T) -> Self {
		Self::String(string.into())
	}
}

impl<C> Encode<C> for AttributeValue {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		match self {
			Self::Boolean(b) => b.encode(e, ctx),
			Self::String(s) => s.encode(e, ctx),
		}
	}
}

impl<'b, C> Decode<'b, C> for AttributeValue {
	fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		match d.datatype()? {
			Type::String | Type::StringIndef | Type::Bytes | Type::BytesIndef => {
				d.decode().map(Self::String)
			}
			Type::Bool => d.decode().map(Self::Boolean),
			ty => Err(minicbor::decode::Error::type_mismatch(ty)),
		}
	}
}

/// POSIX owner information (user or group).
#[derive(Clone, Debug, PartialEq)]
pub struct PosixOwner {
	/// Owner numeric ID.
	pub id: Option<u64>,

	/// Owner name.
	pub name: Option<CborString>,
}

impl<C> Encode<C> for PosixOwner {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		_ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		e.array(match (self.id.is_some(), self.name.is_some()) {
			(true, true) => 2,
			(true, false) | (false, true) => 1,
			(false, false) => 0,
		})?;

		if let Some(id) = &self.id {
			e.u64(*id)?;
		}

		if let Some(name) = &self.name {
			e.encode(name)?;
		}

		Ok(())
	}
}

impl<'b, C> Decode<'b, C> for PosixOwner {
	fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		let mut id = None;
		let mut name = None;

		let max = d.array()?.unwrap_or(u64::MAX);
		for _ in 0..max {
			match d.datatype()? {
				Type::Break => break,
				Type::U8 => {
					id = Some(d.u8()? as _);
				}
				Type::U16 => {
					id = Some(d.u16()? as _);
				}
				Type::U32 => {
					id = Some(d.u32()? as _);
				}
				Type::U64 => {
					id = Some(d.u64()?);
				}
				Type::String | Type::StringIndef => {
					name = Some(d.decode()?);
				}
				Type::Bytes | Type::BytesIndef if name.is_none() => {
					name = Some(d.decode()?);
				}
				ty => return Err(minicbor::decode::Error::type_mismatch(ty)),
			}
		}

		Ok(Self { id, name })
	}
}

/// Directory Filemap Entry Timestamps.
// TODO: chrono
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct Timestamps {
	/// Insertion time (time added to Zarc).
	#[n(0)]
	pub inserted: Option<SystemTime>,

	/// Creation time (ctime).
	#[n(1)]
	pub created: Option<SystemTime>,

	/// Modification time (mtime).
	#[n(2)]
	pub modified: Option<SystemTime>,

	/// Access time (atime).
	#[n(3)]
	pub accessed: Option<SystemTime>,
}

/// Special File metadata.
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#30-special-file-types)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(array)]
pub struct SpecialFile {
	/// Kind of special file.
	///
	/// Will be `None` for unknown kinds.
	#[n(0)]
	pub kind: Option<SpecialFileKind>,

	/// Link target.
	#[n(1)]
	pub link_target: Option<LinkTarget>,
}

/// Special File kinds.
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#30-special-file-types)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(index_only)]
pub enum SpecialFileKind {
	/// Directory.
	///
	/// To encode metadata/attributes against a directory.
	#[n(1)]
	Directory = 1,

	/// A link.
	///
	/// Some kind of link, but without specifying what exactly it is.
	#[n(10)]
	Link = 10,

	/// Internal hardlink.
	///
	/// Must point to a file that exists within this Zarc.
	#[n(11)]
	InternalHardlink = 11,

	/// External hardlink.
	#[n(12)]
	ExternalHardlink = 12,

	/// Internal symbolic link.
	///
	/// Must point to a file that exists within this Zarc.
	#[n(13)]
	InternalSymlink = 13,

	/// External absolute symbolic link.
	#[n(14)]
	ExternalAbsoluteSymlink = 14,

	/// External relative symbolic link.
	#[n(15)]
	ExternalRelativeSymlink = 15,
}

/// Target of link (for [`SpecialFile`])
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#30-special-file-types)
#[derive(Clone, Debug, PartialEq)]
pub enum LinkTarget {
	/// Target as full pathname.
	FullPath(CborString),

	/// Target as array of path components.
	Components(Vec<CborString>),
}

impl From<Pathname> for LinkTarget {
	fn from(pathname: Pathname) -> Self {
		Self::Components(pathname.0)
	}
}

impl From<&Path> for LinkTarget {
	fn from(path: &Path) -> Self {
		if path.is_absolute()
			|| path
				.components()
				.any(|c| !matches!(c, Component::Normal(_)))
		{
			Self::FullPath(CborString::from(path.as_os_str()))
		} else {
			Self::from(Pathname::from_normal_components(path))
		}
	}
}

impl<C> Encode<C> for LinkTarget {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		match self {
			Self::FullPath(s) => s.encode(e, ctx),
			Self::Components(v) => {
				e.array(v.len().try_into().expect("path way too long"))?;
				for s in v {
					s.encode(e, ctx)?;
				}
				Ok(())
			}
		}
	}
}

impl<'b, C> Decode<'b, C> for LinkTarget {
	fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		match d.datatype()? {
			Type::Array => todo!(),
			Type::ArrayIndef => todo!(),
			_ => CborString::decode(d, ctx).map(Self::FullPath),
		}
	}
}

/// Zarc Directory Framelist Entry
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#l-framelist)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct FrameEntry {
	/// Frame offset.
	#[n(0)]
	pub offset: u64,

	/// Hash of the frame.
	#[n(1)]
	pub frame_hash: Digest,

	/// Signature against hash.
	#[n(2)]
	pub signature: Signature,

	/// Uncompressed content size in bytes.
	#[n(3)]
	pub uncompressed_size: u64,
}
