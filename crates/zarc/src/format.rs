//! Common types defining the binary format structures.

use std::{
	collections::HashMap,
	ffi::OsStr,
	fmt,
	num::NonZeroU16,
	path::{Component, Path, PathBuf},
	time::SystemTime,
};

use chrono::{DateTime, Utc};
use deku::prelude::*;
use minicbor::{
	data::{Tag, Type},
	Decode, Decoder, Encode, Encoder,
};

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
	/// Magic number. Asserted to match [`ZARC_MAGIC`].
	#[deku(count = "3", assert = "*magic == ZARC_MAGIC")]
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
pub struct ZarcTrailer {
	/// Magic number. Should match [`ZARC_MAGIC`].
	#[deku(count = "3", pad_bytes_after = "1")]
	pub magic: Vec<u8>,

	/// File format version number. Should match [`ZARC_FILE_VERSION`].
	#[deku(bytes = "1")]
	pub file_version: u8,

	/// Directory format version number. Should match [`ZARC_DIRECTORY_VERSION`].
	#[deku(bytes = "1")]
	pub directory_version: u8,

	/// Digest (hash) algorithm
	pub digest_type: DigestType,

	/// Signature scheme
	pub signature_type: SignatureType,

	/// Directory framed length in bytes.
	#[deku(bytes = "8")]
	pub directory_length: u64,

	/// Uncompressed size in bytes of the directory
	#[deku(bytes = "8")]
	pub directory_uncompressed_size: u64,

	/// Public key
	#[deku(
		count = "signature_type.public_key_len()",
		map = "|field| -> Result<_, DekuError> { Ok(PublicKey(field)) }",
		writer = "self.public_key.0.write(deku::output, ())"
	)]
	pub public_key: PublicKey,

	/// Digest of the directory
	#[deku(
		count = "digest_type.digest_len()",
		map = "|field: Vec<u8>| -> Result<_, DekuError> { Ok(Digest(field)) }",
		writer = "self.digest.0.write(deku::output, ())"
	)]
	pub digest: Digest,

	/// Signature over the digest
	#[deku(
		count = "signature_type.signature_len()",
		map = "|field| -> Result<_, DekuError> { Ok(Signature(field)) }",
		writer = "self.signature.0.write(deku::output, ())"
	)]
	pub signature: Signature,
}

impl<C> Encode<C> for ZarcTrailer {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		_ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		e.bytes(
			&self
				.to_bytes()
				.map_err(|err| minicbor::encode::Error::message(err.to_string()))?,
		)
		.map(drop)
	}
}

impl<'b, C> Decode<'b, C> for ZarcTrailer {
	fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		let bytes = match d.datatype()? {
			Type::Bytes => d.bytes()?.into(),
			Type::BytesIndef => d.bytes_iter()?.try_fold(Vec::new(), |mut vec, b| {
				b.map(|b| {
					vec.extend(b);
					vec
				})
			})?,
			ty => return Err(minicbor::decode::Error::type_mismatch(ty)),
		};

		let ((rest, remaining), header) = Self::from_bytes((&bytes, 0))
			.map_err(|err| minicbor::decode::Error::message(err.to_string()))?;

		if remaining == 0 {
			Ok(header)
		} else {
			Err(minicbor::decode::Error::message(format!(
				"{remaining} trailing bytes: {rest:02x?}"
			)))
		}
	}
}

/// Available digest algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Encode, Decode, DekuRead, DekuWrite)]
#[deku(endian = "endian", type = "u8", ctx = "endian: deku::ctx::Endian")]
#[cbor(index_only)]
pub enum DigestType {
	/// BLAKE3 hash function.
	#[n(1)]
	Blake3 = 1,
}

impl DigestType {
	/// Length in bytes of a digest of this type.
	pub const fn digest_len(self) -> usize {
		match self {
			Self::Blake3 => blake3::OUT_LEN,
		}
	}

	/// Verify that a block of data matches the given digest.
	pub fn verify_data(self, expected: &Digest, data: &[u8]) -> bool {
		match self {
			Self::Blake3 => {
				let actual = blake3::hash(&data);
				let Ok(expected_bytes) = expected.as_slice().try_into() else {
					return false;
				};
				blake3::Hash::from_bytes(expected_bytes) == actual
			}
		}
	}
}

/// Available signature schemes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Encode, Decode, DekuRead, DekuWrite)]
#[deku(endian = "endian", type = "u8", ctx = "endian: deku::ctx::Endian")]
#[cbor(index_only)]
pub enum SignatureType {
	/// Ed25519 scheme.
	#[n(1)]
	Ed25519 = 1,
}

impl SignatureType {
	/// Length in bytes of a public key in this scheme.
	pub const fn public_key_len(self) -> usize {
		match self {
			Self::Ed25519 => ed25519_dalek::PUBLIC_KEY_LENGTH,
		}
	}

	/// Length in bytes of a signature in this scheme.
	pub const fn signature_len(self) -> usize {
		match self {
			Self::Ed25519 => ed25519_dalek::SIGNATURE_LENGTH,
		}
	}

	/// Verify that a block of data matches the given signature.
	pub fn verify_data(self, public_key: &PublicKey, signature: &Signature, data: &[u8]) -> bool {
		match self {
			Self::Ed25519 => {
				use ed25519_dalek::{Signature, Verifier, VerifyingKey};
				let Ok(public_key_bytes) = public_key.as_slice().try_into() else {
					return false;
				};
				let Ok(vkey) = VerifyingKey::from_bytes(public_key_bytes) else {
					return false;
				};

				let Ok(signature_bytes) = signature.as_slice().try_into() else {
					return false;
				};
				let sig = Signature::from_bytes(signature_bytes);

				vkey.verify(data, &sig).is_ok()
			}
		}
	}
}

/// Zarc Directory
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-directory)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct ZarcDirectory {
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

macro_rules! bytea_newtype {
	($name:ident # $doc:literal) => {
		#[doc = $doc]
		#[derive(Clone, Debug, Eq, PartialEq, Hash, DekuWrite)]
		pub struct $name(pub Vec<u8>);

		impl std::ops::Deref for $name {
			type Target = Vec<u8>;

			fn deref(&self) -> &Self::Target {
				&self.0
			}
		}

		impl From<Vec<u8>> for $name {
			fn from(bytes: Vec<u8>) -> Self {
				Self(bytes)
			}
		}

		impl<'a, Ctx> DekuReader<'a, Ctx> for $name
		where
			Vec<u8>: DekuReader<'a, Ctx>,
			Ctx: Copy,
		{
			fn from_reader_with_ctx<R: deku::no_std_io::Read>(
				reader: &mut deku::reader::Reader<'_, R>,
				ctx: Ctx,
			) -> Result<Self, DekuError>
			where
				Self: Sized,
			{
				Vec::<u8>::from_reader_with_ctx(reader, ctx).map(Self)
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

bytea_newtype!(Digest # "Digest.");
bytea_newtype!(Signature # "Signature.");
bytea_newtype!(PublicKey # "Public key.");

impl From<blake3::Hash> for Digest {
	fn from(value: blake3::Hash) -> Self {
		Self(value.as_bytes().to_vec())
	}
}

impl From<ed25519_dalek::Signature> for Signature {
	fn from(value: ed25519_dalek::Signature) -> Self {
		Self(value.to_vec())
	}
}

impl From<ed25519_dalek::VerifyingKey> for PublicKey {
	fn from(value: ed25519_dalek::VerifyingKey) -> Self {
		Self(value.as_bytes().to_vec())
	}
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

	/// Converts to a (platform-specific) Path.
	pub fn to_path(&self) -> PathBuf {
		let mut path = PathBuf::new();
		for comp in &self.0 {
			match comp {
				CborString::Text(text) => {
					path.push(text);
				}
				CborString::Binary(bytes) => {
					#[cfg(unix)]
					{
						use std::os::unix::ffi::OsStrExt;
						path.push(OsStr::from_bytes(bytes));
					}
					#[cfg(not(unix))]
					{
						path.push(String::from_utf8_lossy(bytes));
					}
				}
			}
		}

		path
	}
}

/// CBOR Text or Byte string.
#[derive(Clone, Debug, PartialEq)]
pub enum CborString {
	/// UTF-8 text string value.
	Text(String),

	/// Non-unicode byte string value.
	Binary(Vec<u8>),
}

impl CborString {
	/// Convert from bytes that might be UTF-8.
	pub fn from_maybe_utf8(bytes: Vec<u8>) -> Self {
		match String::from_utf8(bytes) {
			Ok(string) => Self::Text(string),
			Err(err) => Self::Binary(err.into_bytes()),
		}
	}
}

impl From<&OsStr> for CborString {
	fn from(string: &OsStr) -> Self {
		if let Some(unicode) = string.to_str() {
			Self::Text(unicode.into())
		} else {
			#[cfg(unix)]
			{
				use std::os::unix::ffi::OsStrExt;
				Self::Binary(string.as_bytes().into())
			}
			#[cfg(windows)]
			{
				use std::os::windows::ffi::OsStrExt;
				Self::Text(String::from_utf16_lossy(&string.encode_wide().collect()))
			}
		}
	}
}

impl From<&str> for CborString {
	fn from(string: &str) -> Self {
		Self::Text(string.into())
	}
}

impl From<String> for CborString {
	fn from(string: String) -> Self {
		Self::Text(string)
	}
}

impl<C> Encode<C> for CborString {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		match self {
			Self::Text(s) => s.encode(e, ctx),
			Self::Binary(b) => <&minicbor::bytes::ByteSlice>::from(b.as_slice()).encode(e, ctx),
		}
	}
}

impl<'b, C> Decode<'b, C> for CborString {
	fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		match d.datatype()? {
			Type::String => d.str().map(|s| Self::Text(s.into())),
			Type::StringIndef => Ok(Self::Text(d.str_iter()?.try_fold(
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
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct Timestamps {
	/// Creation time (birth time).
	#[n(1)]
	pub created: Option<Timestamp>,

	/// Modification time (mtime).
	#[n(2)]
	pub modified: Option<Timestamp>,

	/// Access time (atime).
	#[n(3)]
	pub accessed: Option<Timestamp>,
}

/// A timestamp.
///
/// Internally this is a [`chrono`] type, and always encodes to an RFC3339 tagged text string.
/// However for flexibility it can decode from a CBOR epoch-based timestamp as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp(pub DateTime<Utc>);

impl Timestamp {
	/// The current date and time.
	pub fn now() -> Self {
		Self(Utc::now())
	}
}

impl From<SystemTime> for Timestamp {
	fn from(st: SystemTime) -> Self {
		Self(st.into())
	}
}

impl From<Timestamp> for SystemTime {
	fn from(ts: Timestamp) -> Self {
		ts.0.into()
	}
}

impl From<DateTime<Utc>> for Timestamp {
	fn from(dt: DateTime<Utc>) -> Self {
		Self(dt)
	}
}

impl From<Timestamp> for DateTime<Utc> {
	fn from(ts: Timestamp) -> Self {
		ts.0
	}
}

impl fmt::Display for Timestamp {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl<C> Encode<C> for Timestamp {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		_ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		e.tag(Tag::DateTime)?.str(&self.0.to_rfc3339()).map(drop)
	}
}

impl<'b, C> Decode<'b, C> for Timestamp {
	fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		let p = d.position();
		match d.tag()? {
			Tag::DateTime => Ok(Self(
				DateTime::parse_from_rfc3339(d.str()?)
					.map_err(|err| minicbor::decode::Error::message(err.to_string()).at(p))?
					.into(),
			)),
			Tag::Timestamp => match d.datatype()? {
				Type::U32 => DateTime::<Utc>::from_timestamp(i64::from(d.u32()?), 0),
				Type::U64 => DateTime::<Utc>::from_timestamp(
					i64::try_from(d.u64()?).map_err(|err| {
						minicbor::decode::Error::message(format!("timestamp out of range: {err}"))
							.at(p)
					})?,
					0,
				),
				Type::I32 => DateTime::<Utc>::from_timestamp(i64::from(d.i32()?), 0),
				Type::I64 => DateTime::<Utc>::from_timestamp(d.i64()?, 0),
				Type::Int => DateTime::<Utc>::from_timestamp(
					i64::try_from(d.int()?).map_err(|err| {
						minicbor::decode::Error::message(format!("timestamp out of range: {err}"))
							.at(p)
					})?,
					0,
				),
				Type::F32 => {
					let f = d.f32()?;
					DateTime::<Utc>::from_timestamp(f.trunc() as _, (f.fract() * 1.0e9) as _)
				}
				Type::F64 => {
					let f = d.f64()?;
					DateTime::<Utc>::from_timestamp(f.trunc() as _, (f.fract() * 1.0e9) as _)
				}
				ty => return Err(minicbor::decode::Error::type_mismatch(ty)),
			}
			.ok_or_else(|| minicbor::decode::Error::message("timestamp out of range").at(p))
			.map(Self),
			other => Err(minicbor::decode::Error::message(format!(
				"expected Timestamp or DateTime tag, got {other:?}"
			))
			.at(p)),
		}
	}
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

	/// A symlink.
	///
	/// Some kind of symlink, but without specifying what exactly it is.
	#[n(10)]
	Symlink = 10,

	/// Internal symbolic link.
	///
	/// Must point to a file that exists within this Zarc.
	#[n(11)]
	InternalSymlink = 11,

	/// External absolute symbolic link.
	#[n(12)]
	ExternalAbsoluteSymlink = 12,

	/// External relative symbolic link.
	#[n(13)]
	ExternalRelativeSymlink = 13,

	/// A hardlink.
	///
	/// Some kind of hardlink, but without specifying what exactly it is.
	#[n(20)]
	Hardlink = 20,

	/// Internal hardlink.
	///
	/// Must point to a file that exists within this Zarc.
	#[n(21)]
	InternalHardlink = 21,

	/// External hardlink.
	#[n(22)]
	ExternalHardlink = 22,
}

impl SpecialFileKind {
	/// Returns `true` if this is a directory.
	pub fn is_dir(self) -> bool {
		matches!(self, Self::Directory)
	}

	/// Returns `true` if this is a link.
	///
	/// This covers all the symlink and hardlink variants.
	pub fn is_link(self) -> bool {
		self.is_symlink() || self.is_hardlink()
	}

	/// Returns `true` if this is a symlink.
	///
	/// This covers all the symlink variants.
	pub fn is_symlink(self) -> bool {
		matches!(
			self,
			Self::Symlink
				| Self::InternalSymlink
				| Self::ExternalAbsoluteSymlink
				| Self::ExternalRelativeSymlink
		)
	}

	/// Returns `true` if this is a hardlink.
	///
	/// This covers all the hardlink variants.
	pub fn is_hardlink(self) -> bool {
		matches!(
			self,
			Self::Hardlink | Self::InternalHardlink | Self::ExternalHardlink
		)
	}
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
