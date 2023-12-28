//! Zarc: Archive format based on Zstd.
//!
//! [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md)
//!
//! TBD

#![warn(clippy::unwrap_used, missing_docs)]
#![deny(rust_2018_idioms)]

pub mod format {
	//! Common types defining the binary format structures.

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
		#[deku(count = "3")]
		pub magic: Vec<u8>,

		/// File format version number. Should match [`ZARC_FILE_VERSION`].
		#[deku(bytes = "1")]
		pub file_version: u8,

		#[deku(bytes = "2", update = "self.hash.len()")]
		hash_length: u16,

		/// Digest hash of the directory
		#[deku(count = "hash_length")]
		pub hash: Digest,

		#[deku(bytes = "2", update = "self.sig.len()")]
		sig_length: u16,

		/// Signature over the digest
		#[deku(count = "sig_length")]
		pub sig: Signature,

		/// Uncompressed size in bytes of the directory
		#[deku(bytes = "8")]
		pub directory_size: u64,
	}

	impl ZarcDirectoryHeader {
		/// Correctly create header from data.
		pub fn new(size: usize, hash: Digest, sig: Signature) -> std::io::Result<Self> {
			Ok(Self {
				directory_size: size.try_into().map_err(|err| std::io::Error::other(err))?,
				magic: ZARC_MAGIC.to_vec(),
				file_version: ZARC_FILE_VERSION,
				hash_length: hash
					.len()
					.try_into()
					.map_err(|err| std::io::Error::other(format!("hash is too long: {err}")))?,
				hash,
				sig_length: sig.len().try_into().map_err(|err| {
					std::io::Error::other(format!("signature is too long: {err}"))
				})?,
				sig,
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

	/// Hash or digest.
	pub type Digest = Vec<u8>;

	/// Signature.
	pub type Signature = Vec<u8>;

	/// Public key.
	pub type PublicKey = Vec<u8>;

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
		pub public_key: PublicKey,
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
		pub frame_hash: Option<Digest>,

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

		/// Payload digest.
		#[serde(rename = "h")]
		pub digest: Digest,

		/// Signature against digest.
		#[serde(rename = "s")]
		pub signature: Signature,
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

	use ed25519_dalek::{Signer, SigningKey};
	pub use zstd_safe::CParameter as ZstdParameter;
	use zstd_safe::{CCtx, ResetDirective};

	use crate::format::{
		Digest, FilemapEntry, FrameEntry, HashAlgorithm, PublicKey, Signature, SignatureScheme,
		ZarcDirectory, ZarcDirectoryHeader, ZarcDirectoryPrelude, ZarcEofTrailer, FILE_MAGIC,
		ZARC_DIRECTORY_VERSION,
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
				use deku::DekuContainerRead;
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

				// write edited frame
				use deku::DekuContainerWrite;
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
			Ok(signature.to_vec())
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
			let digest = digest.as_bytes().to_vec();

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
			let signature = self
				.key
				.try_sign(&digest)
				.map_err(|err| Error::other(err))?;

			self.offset += self.write_compressed_frame(content)?;

			// push frame to list
			self.framelist.insert(
				digest.clone(),
				FrameEntry {
					digest: digest.clone(),
					offset: offset.try_into().map_err(|err| Error::other(err))?,
					signature: signature.to_vec(),
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
			let public_key = self.key.verifying_key().as_bytes().to_vec();

			let directory = ZarcDirectory {
				prelude: ZarcDirectoryPrelude {
					version: ZARC_DIRECTORY_VERSION,
					hash_algorithm: HashAlgorithm::Blake3,
					signature_scheme: SignatureScheme::Ed25519,
					public_key: public_key.clone(),
				},
				user_metadata: Default::default(),
				filemap: std::mem::take(&mut self.filemap),
				framelist: std::mem::take(&mut self.framelist).into_values().collect(),
			};
			tracing::trace!(?directory, "built directory");

			let directory_bytes =
				rmp_serde::encode::to_vec_named(&directory).map_err(|err| Error::other(err))?;
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

			// we write skippable frames manually as zstd-safe doesn't have an api
			use deku::DekuContainerWrite;
			let header_bytes = header.to_bytes()?;
			tracing::trace!(
				bytes = %format!("{header_bytes:02x?}"),
				length = %header_bytes.len(),
				"serialised directory header"
			);

			// write directory header
			let mut directory_frames_size = self.writer.write(&header_bytes)?;
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

			assert_eq!(self.writer.write(&trailer_bytes)?, 8);
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
			magic: [u8; 4],
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
					magic: [0x50 + nibble, 0x2A, 0x4D, 0x18],
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
