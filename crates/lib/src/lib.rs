//! Zarc: Archive format based on Zstd.
//!
//! [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md)
//!
//! TBD

#![warn(clippy::unwrap_used, missing_docs)]
#![deny(rust_2018_idioms)]

pub mod format {
	//! Common types defining the binary format structures.

	use std::{collections::HashMap, time::SystemTime};

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
				sig_length: sig.len().try_into().map_err(|err| {
					std::io::Error::other(format!("signature is too long: {err}"))
				})?,
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
				fn decode(
					d: &mut Decoder<'b>,
					_ctx: &mut C,
				) -> Result<Self, minicbor::decode::Error> {
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

	/// CBOR Text or Byte string.
	#[derive(Clone, Debug, PartialEq)]
	pub enum CborString {
		/// UTF-8 text string value.
		String(String),

		/// Non-unicode byte string value.
		Binary(Vec<u8>),
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

		/// Internal hardlink.
		///
		/// Must point to a file that exists within this Zarc.
		#[n(10)]
		InternalHardlink = 10,

		/// External hardlink.
		#[n(11)]
		ExternalHardlink = 11,

		/// Internal symbolic link.
		///
		/// Must point to a file that exists within this Zarc.
		#[n(12)]
		InternalSymlink = 12,

		/// External absolute symbolic link.
		#[n(13)]
		ExternalAbsoluteSymlink = 13,

		/// External relative symbolic link.
		#[n(14)]
		ExternalRelativeSymlink = 14,
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
}

pub mod decode {
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
}

pub mod encode {
	//! Encoder types and functions.

	use std::{
		collections::HashMap,
		io::{Error, Result, Write},
	};

	use deku::{DekuContainerRead, DekuContainerWrite};
	use ed25519_dalek::{Signer, SigningKey};
	pub use zstd_safe::CParameter as ZstdParameter;
	use zstd_safe::{CCtx, ResetDirective};

	use crate::format::{
		Digest, FilemapEntry, FrameEntry, HashAlgorithm, PublicKey, Signature, SignatureScheme,
		ZarcDirectory, ZarcDirectoryHeader, ZarcEofTrailer, FILE_MAGIC, ZARC_DIRECTORY_VERSION,
	};
	use crate::map_zstd_error;

	/// Zarc encoder context.
	pub struct Encoder<'writer, W: Write> {
		writer: &'writer mut W,
		zstd: CCtx<'writer>,
		key: SigningKey,
		filemap: Vec<FilemapEntry>,
		framelist: HashMap<Digest, FrameEntry>,
		offset: usize,
	}

	impl<'writer, W: Write> Encoder<'writer, W> {
		/// Create a new encoder and write the header.
		///
		/// Requires a CSRNG implementation to generate the signing key.
		///
		/// The `defensive_header` is a bit of text that is ignored by Zarc decoders, but may be
		/// read and unpacked by Zstd decoders, providing a human-readable message to explain that
		/// this is a Zarc file is and how to properly unpack it.
		pub fn new<R: rand_core::CryptoRngCore + ?Sized>(
			writer: &'writer mut W,
			csrng: &mut R,
			defensive_header: &str,
		) -> Result<Self> {
			tracing::trace!("generate signing key");
			let key = SigningKey::generate(csrng);
			if key.verifying_key().is_weak() {
				return Err(Error::other("signing key is weak"));
			}

			tracing::trace!("create zstd context");
			let mut zstd =
				CCtx::try_create().ok_or_else(|| Error::other("failed allocating zstd context"))?;

			tracing::trace!("write zarc magic");
			let mut offset = writer.write(&FILE_MAGIC)?;

			// zstd's block api is deprecated, so we have to do this bit manually:
			// compress the defensive header text into a buffer, then parse it to
			// obtain the compressed blocks, and reframe it into the zarc format.
			tracing::trace!("write zarc unintended magic");
			{
				tracing::trace!("initialise zstd session");
				zstd.init(20).map_err(map_zstd_error)?;
				// explicitly turn checksums off so we don't have to recompute it
				zstd.set_parameter(ZstdParameter::ChecksumFlag(false))
					.map_err(map_zstd_error)?;

				// write compressed frame to buf
				let mut buf: Vec<u8> = Vec::with_capacity(defensive_header.len() + 1024);
				tracing::trace!("compress unintended magic");
				zstd.compress2(&mut buf, defensive_header.as_bytes())
					.map_err(map_zstd_error)?;

				// parse frame manually
				tracing::trace!(
					bytes = %format!("{buf:02x?}"),
					length = %buf.len(),
					buffer = %buf.capacity(),
					"reparse frame"
				);
				let ((rest, _), mut frame) = reparse_zstd::ZstandardFrame::from_bytes((&buf, 0))?;
				tracing::trace!(
					?frame,
					rest = %format!("{rest:02x?}"),
					"reparsed zstd frame for defensive header"
				);
				assert!(rest.is_empty(), "should parse zstd completely");

				// write zarc header into raw block in position 0
				use crate::format::{ZARC_FILE_VERSION, ZARC_MAGIC};
				frame.blocks.insert(
					0,
					reparse_zstd::ZstandardBlock {
						header: reparse_zstd::ZstandardBlockHeader::new(
							reparse_zstd::ZstandardBlockType::Raw,
							false,
							4,
						),
						data: vec![
							ZARC_MAGIC[0],
							ZARC_MAGIC[1],
							ZARC_MAGIC[2],
							ZARC_FILE_VERSION,
						],
					},
				);
				// write zero-length null-byte RLE in position 1
				frame.blocks.insert(
					1,
					reparse_zstd::ZstandardBlock {
						header: reparse_zstd::ZstandardBlockHeader::new(
							reparse_zstd::ZstandardBlockType::Rle,
							false,
							0,
						),
						data: vec![0],
					},
				);
				// add 4 to the frame content size
				frame.frame_content_size[0] += 4;

				// write edited frame
				let bytes = frame.to_bytes()?;
				tracing::trace!(
					?frame,
					bytes = %format!("{bytes:02x?}"),
					length = bytes.len(),
					"write edited frame for defensive header"
				);
				offset += writer.write(&bytes)?;
			}

			// reset zstd to defaults
			zstd.init(0).map_err(map_zstd_error)?;

			Ok(Self {
				writer,
				zstd,
				key,
				filemap: Vec::new(),
				framelist: HashMap::new(),
				offset,
			})
		}

		/// Sign user-provided data.
		pub fn sign_user_data(&self, data: &[u8]) -> Result<Signature> {
			let signature = self.key.try_sign(data).map_err(|err| Error::other(err))?;
			Ok(Signature(signature.to_vec()))
		}

		/// Set a zstd parameter.
		///
		/// This will apply to future data frames.
		pub fn set_zstd_parameter(&mut self, parameter: ZstdParameter) -> Result<()> {
			self.zstd
				.set_parameter(parameter)
				.map_err(map_zstd_error)
				.map(drop)
		}

		// zstd-safe is bad at writing data, so we always write to a buffer in memory
		// and then write that buffer to the writer
		fn write_compressed_frame(&mut self, data: &[u8]) -> Result<usize> {
			// start with a buffer slightly larger than the input
			let mut buffer: Vec<u8> = Vec::with_capacity(data.len() + 1024);

			tracing::trace!(
				bytes = %format!("{data:02x?}"),
				length = %data.len(),
				buffer_size = %buffer.capacity(),
				"compress data into buffer"
			);
			self.zstd
				.compress2(&mut buffer, data)
				.map_err(map_zstd_error)?;

			tracing::trace!(
				bytes = %format!("{buffer:02x?}"),
				length = %buffer.len(),
				"write buffer to writer"
			);
			self.writer.write(&buffer)
		}

		// we write skippable frames manually as zstd-safe doesn't have an api
		fn write_skippable_frame(&mut self, magic: u8, data: Vec<u8>) -> Result<usize> {
			tracing::trace!(
				bytes = %format!("{data:02x?}"),
				length = %data.len(),
				magic,
				"compose data into frame"
			);
			let frame = reparse_zstd::SkippableFrame::new(magic, data);
			let buffer = frame.to_bytes()?;

			tracing::trace!(
				bytes = %format!("{buffer:02x?}"),
				length = %buffer.len(),
				"write buffer to writer"
			);
			self.writer.write(&buffer)
		}

		/// Add a frame of data.
		///
		/// Processes the entire input in memory.
		///
		/// Returns the hash of the data, so it can be referenced in a filemap entry.
		///
		/// If the content hashes to a frame that already exists, returns the hash without storing
		/// a duplicate frame.
		pub fn add_data_frame(&mut self, content: &[u8]) -> Result<Digest> {
			// compute content hash
			let digest = blake3::hash(&content);
			let digest = Digest(digest.as_bytes().to_vec());

			if self.framelist.contains_key(&digest) {
				return Ok(digest);
			}

			// start new compression context
			self.zstd
				.reset(ResetDirective::SessionOnly)
				.map_err(map_zstd_error)?;

			// collect pre-compression values
			let offset = self.offset;
			let uncompressed_size = content.len();

			// compute signature
			let signature = Signature(
				self.key
					.try_sign(digest.as_slice())
					.map_err(|err| Error::other(err))?
					.to_vec(),
			);

			self.offset += self.write_compressed_frame(content)?;

			// push frame to list
			self.framelist.insert(
				digest.clone(),
				FrameEntry {
					offset: offset.try_into().map_err(|err| Error::other(err))?,
					frame_hash: digest.clone(),
					signature,
					uncompressed_size: uncompressed_size
						.try_into()
						.map_err(|err| Error::other(err))?,
				},
			);

			Ok(digest)
		}

		/// Add a file entry.
		// TODO: more ergonomic APIs, e.g. from a File
		// TODO: builder API for user metadata?
		pub fn add_file_entry(&mut self, entry: FilemapEntry) -> Result<()> {
			if let Some(hash) = &entry.frame_hash {
				if !self.framelist.contains_key(hash) {
					return Err(Error::other(
						"cannot add file entry referencing unknown data frame",
					));
				}
			}

			self.filemap.push(entry);
			Ok(())
		}

		/// Write the directory and trailer.
		///
		/// Flushes the writer and drops all state.
		///
		/// Discards the private key and returns the public key.
		pub fn finalise(mut self) -> Result<PublicKey> {
			let public_key = PublicKey(self.key.verifying_key().as_bytes().to_vec());

			let directory = ZarcDirectory {
				version: ZARC_DIRECTORY_VERSION,
				hash_algorithm: HashAlgorithm::Blake3,
				signature_scheme: SignatureScheme::Ed25519,
				public_key: public_key.clone(),
				filemap: std::mem::take(&mut self.filemap),
				framelist: std::mem::take(&mut self.framelist).into_values().collect(),
				user_metadata: Default::default(),
			};
			tracing::trace!(?directory, "built directory");

			let directory_bytes = minicbor::to_vec(&directory).map_err(Error::other)?;
			tracing::trace!(
				bytes = %format!("{directory_bytes:02x?}"),
				length = %directory_bytes.len(),
				"serialised directory"
			);

			let digest = blake3::hash(&directory_bytes);
			tracing::trace!(?digest, "hashed directory");
			let digest = digest.as_bytes();
			let signature = self.key.try_sign(digest).map_err(|err| Error::other(err))?;
			tracing::trace!(?signature, "signed directory hash");

			let header = ZarcDirectoryHeader::new(
				directory_bytes.len(),
				digest.to_vec(),
				signature.to_vec(),
			)?;
			tracing::trace!(?header, "built directory header");

			let header_bytes = header.to_bytes()?;
			tracing::trace!(
				bytes = %format!("{header_bytes:02x?}"),
				length = %header_bytes.len(),
				"serialised directory header"
			);

			// write directory header
			let mut directory_frames_size = self.write_skippable_frame(0xF, header_bytes)?;
			tracing::trace!(%directory_frames_size, "wrote directory header");

			// write directory
			directory_frames_size += self.write_compressed_frame(&directory_bytes)?;
			tracing::trace!(%directory_frames_size, "wrote directory frame");

			// write trailer
			let trailer = ZarcEofTrailer {
				directory_frames_size: directory_frames_size
					.try_into()
					.map_err(|err| Error::other(err))?,
			};
			tracing::trace!(?trailer, "built trailer");

			let trailer_bytes = trailer.to_bytes()?;
			tracing::trace!(
				bytes = %format!("{trailer_bytes:02x?}"),
				length = %trailer_bytes.len(),
				"serialised trailer"
			);

			assert_eq!(self.write_skippable_frame(0xE, trailer_bytes)?, 16);
			tracing::trace!("wrote trailer");

			self.writer.flush()?;
			tracing::trace!("flushed writer");

			Ok(public_key)
		}
	}

	mod reparse_zstd {
		use deku::prelude::*;

		#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
		#[deku(endian = "little")]
		pub struct SkippableFrame {
			#[deku(bytes = "4")]
			magic: u32,
			#[deku(bytes = "4")]
			size: u32,
			#[deku(count = "size")]
			pub data: Vec<u8>,
		}

		impl SkippableFrame {
			pub fn new(nibble: u8, data: Vec<u8>) -> Self {
				assert!(
					nibble < 16,
					"skippable frame nibble must be between 0 and 15"
				);
				Self {
					magic: u32::from_le_bytes([0x50 + nibble, 0x2A, 0x4D, 0x18]),
					size: data
						.len()
						.try_into()
						.expect("skippable frame data is too long"),
					data,
				}
			}
		}

		#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
		#[deku(endian = "little", magic = b"\x28\xB5\x2F\xFD")]
		pub struct ZstandardFrame {
			pub frame_descriptor: ZstandardFrameDescriptor,
			#[deku(bytes = 1, cond = "!frame_descriptor.single_segment")]
			pub window_descriptor: Option<u8>,
			#[deku(count = "frame_descriptor.did_length()")]
			pub did: Vec<u8>,
			#[deku(count = "frame_descriptor.fcs_length()")]
			pub frame_content_size: Vec<u8>,
			#[deku(until = "|b: &ZstandardBlock| b.header.last")]
			pub blocks: Vec<ZstandardBlock>,
			#[deku(bytes = 4, cond = "frame_descriptor.checksum")]
			pub checksum: Option<u32>,
		}

		#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
		#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
		pub struct ZstandardFrameDescriptor {
			#[deku(bits = 2)]
			pub fcs_size: u8,
			#[deku(bits = 1)]
			pub single_segment: bool,
			#[deku(bits = 1)]
			pub unused_bit: bool,
			#[deku(bits = 1)]
			pub reserved_bit: bool,
			#[deku(bits = 1)]
			pub checksum: bool,
			#[deku(bits = 2)]
			pub did_size: u8,
		}

		impl ZstandardFrameDescriptor {
			fn did_length(&self) -> usize {
				match self.did_size {
					0 => 0,
					1 => 1,
					2 => 2,
					3 => 4,
					_ => unreachable!(),
				}
			}

			fn fcs_length(&self) -> usize {
				match self.fcs_size {
					0 if self.single_segment => 1,
					0 => 0,
					1 => 2,
					2 => 4,
					3 => 8,
					_ => unreachable!(),
				}
			}
		}

		#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
		#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
		pub struct ZstandardBlock {
			pub header: ZstandardBlockHeader,
			#[deku(count = "header.actual_size()")]
			pub data: Vec<u8>,
		}

		#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
		#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
		pub struct ZstandardBlockHeader {
			#[deku(bits = "5")]
			size_low: u8,
			pub block_type: ZstandardBlockType,
			#[deku(bits = "1")]
			pub last: bool,
			#[deku(bits = "16")]
			size_high: u16,
		}

		impl ZstandardBlockHeader {
			pub fn new(block_type: ZstandardBlockType, last: bool, size: u32) -> Self {
				assert!(size <= 2_u32.pow(24) - 1);

				let [a, b, c, d] = u32::to_be_bytes(size << 3);
				let size_high = u16::from_be_bytes([b, c]);
				let size_low = d >> 3;
				tracing::trace!(
					field = %format!("{a:08b} {b:08b} {c:08b} {d:08b}"),
					high = %format!("{size_high:016b}"),
					low = %format!("{size_low:08b}"),
					"block header size bit wrangling (write)"
				);

				Self {
					size_low,
					block_type,
					last,
					size_high,
				}
			}

			pub fn actual_size(&self) -> u32 {
				let [a, b] = u16::to_be_bytes(self.size_high);
				let c = self.size_low << 3;
				let real_size = u32::from_be_bytes([0, a, b, c]) >> 3;
				tracing::trace!(
					high = %format!("{:016b}", self.size_high),
					low = %format!("{:08b}", self.size_low),
					real_dec = %real_size,
					real_hex = %format!("{real_size:02x?}"),
					"block header size bit wrangling (read)"
				);

				match self.block_type {
					ZstandardBlockType::Raw | ZstandardBlockType::Compressed => real_size,
					ZstandardBlockType::Rle => 1,
					ZstandardBlockType::Reserved => panic!("corrupt zstd: reserved block type"),
				}
			}
		}

		#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
		#[deku(
			endian = "endian",
			ctx = "endian: deku::ctx::Endian",
			type = "u8",
			bits = "2"
		)]
		pub enum ZstandardBlockType {
			#[deku(id = "0b00")] // = 0
			Raw,
			#[deku(id = "0b01")] // = 1
			Rle,
			#[deku(id = "0b10")] // = 2
			Compressed,
			#[deku(id = "0b11")] // = 3
			Reserved,
		}
	}
}

pub(crate) fn map_zstd_error(code: usize) -> std::io::Error {
	let msg = zstd_safe::get_error_name(code);
	std::io::Error::other(msg)
}
