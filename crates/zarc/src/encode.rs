//! Encoder types and functions.

use std::{
	collections::HashMap,
	fmt,
	io::{Error, Result, Write},
	num::NonZeroU16,
};

use deku::DekuContainerWrite;
use ed25519_dalek::{Signer, SigningKey};
use ozarc::framing::SKIPPABLE_FRAME_OVERHEAD;
use zstd_safe::{CCtx, ResetDirective};
pub use zstd_safe::{CParameter as ZstdParameter, Strategy as ZstdStrategy};

use crate::{
	constants::{ZARC_DIRECTORY_VERSION, ZARC_FILE_VERSION},
	directory::{Edition, File, Frame, LegacyDirectory, Timestamp},
	header::FILE_MAGIC,
	integrity::{Digest, DigestType, PublicKey, Signature, SignatureType},
	map_zstd_error,
	trailer::Trailer,
};

/// Zarc encoder context.
pub struct Encoder<'writer, W: Write> {
	writer: &'writer mut W,
	zstd: CCtx<'writer>,
	key: SigningKey,
	edition: NonZeroU16,
	filemap: Vec<File>,
	framelist: HashMap<Digest, Frame>,
	offset: usize,
	compress: bool,
}

impl<W: Write + fmt::Debug> fmt::Debug for Encoder<'_, W> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Encoder")
			.field("writer", &self.writer)
			.field("zstd", &"zstd-safe compression context")
			.field("key", &self.key)
			.field("edition", &self.edition)
			.field("filemap", &self.filemap)
			.field("framelist", &self.framelist)
			.field("offset", &self.offset)
			.field("compress", &self.compress)
			.finish()
	}
}

impl<'writer, W: Write> Encoder<'writer, W> {
	/// Create a new encoder and write the header.
	///
	/// Requires a CSRNG implementation to generate the signing key.
	pub fn new<R: rand_core::CryptoRngCore + ?Sized>(
		writer: &'writer mut W,
		csrng: &mut R,
	) -> Result<Self> {
		tracing::trace!("generate signing key");
		let key = SigningKey::generate(csrng);
		if key.verifying_key().is_weak() {
			return Err(Error::other("signing key is weak"));
		}

		tracing::trace!("create zstd context");
		let mut zstd =
			CCtx::try_create().ok_or_else(|| Error::other("failed allocating zstd context"))?;
		zstd.init(0).map_err(map_zstd_error)?;

		tracing::trace!("write zarc magic");
		let offset = writer.write(&FILE_MAGIC)?;

		Ok(Self {
			writer,
			zstd,
			key,
			edition: unsafe { NonZeroU16::new_unchecked(1) },
			filemap: Vec::new(),
			framelist: HashMap::new(),
			offset,
			compress: true,
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

	/// Enable or disable compression.
	///
	/// This well apply to future data frames.
	pub fn enable_compression(&mut self, compress: bool) {
		self.compress = compress;
	}

	// zstd-safe is bad at writing data, so we always write to a buffer in memory
	// and then write that buffer to the writer
	fn write_compressed_frame(&mut self, data: &[u8]) -> Result<usize> {
		// start with a buffer slightly larger than the input
		let mut buffer: Vec<u8> = Vec::with_capacity(data.len() + 1024.max(data.len() / 10));

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

	// zstd can't write fully-uncompressed data, so we use our own
	// deku types to write raw blocks and the frame directly
	fn write_uncompressed_frame(&mut self, data: &[u8]) -> Result<usize> {
		use ozarc::framing::*;
		let mut frame = ZstandardFrame {
			header: ZstandardFrameHeader {
				frame_descriptor: ZstandardFrameDescriptor {
					fcs_size: 3,
					single_segment: false,
					unused_bit: false,
					reserved_bit: false,
					checksum: false,
					did_size: 0,
				},
				window_descriptor: None,
				did: Vec::new(),
				frame_content_size: u64::try_from(data.len()).unwrap().to_le_bytes().to_vec(),
			},
			blocks: data
				.chunks(u16::MAX as _)
				.map(|data| ZstandardBlock {
					header: ZstandardBlockHeader::new(
						ZstandardBlockType::Raw,
						false,
						u32::try_from(data.len()).unwrap(), // UNWRAP: chunks() limits to u16
					),
					data: data.into(),
				})
				.collect(),
			checksum: None,
		};

		if let Some(last) = frame.blocks.last_mut() {
			last.header.last = true;
		}

		self.writer.write(&frame.to_bytes()?)
	}

	// we write skippable frames manually as zstd-safe doesn't have an api
	fn write_skippable_frame(&mut self, magic: u8, data: Vec<u8>) -> Result<usize> {
		tracing::trace!(
			bytes = %format!("{data:02x?}"),
			length = %data.len(),
			magic,
			"compose data into frame"
		);
		let frame = ozarc::framing::SkippableFrame::new(magic, data);
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

		let bytes = if self.compress {
			self.write_compressed_frame(content)
		} else {
			self.write_uncompressed_frame(content)
		}?;
		self.offset += bytes;

		// push frame to list
		self.framelist.insert(
			digest.clone(),
			Frame {
				edition: self.edition,
				offset: offset.try_into().map_err(|err| Error::other(err))?,
				frame_hash: digest.clone(),
				signature,
				length: bytes as _,
				uncompressed: uncompressed_size as _,
			},
		);

		Ok(digest)
	}

	/// Add a file entry.
	// TODO: more ergonomic APIs, e.g. from a File
	// TODO: builder API for user metadata?
	pub fn add_file_entry(&mut self, entry: File) -> Result<()> {
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

		let mut framelist: Vec<Frame> = std::mem::take(&mut self.framelist).into_values().collect();
		framelist.sort_by_key(|entry| entry.offset);

		let directory = LegacyDirectory {
			editions: vec![Edition {
				number: self.edition,
				written_at: Timestamp::now(),
				user_metadata: Default::default(),
				digest_type: DigestType::Blake3,
				signature_type: SignatureType::Ed25519,
				public_key: public_key.clone(),
			}],
			filemap: std::mem::take(&mut self.filemap),
			framelist,
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

		let bytes = self.write_compressed_frame(&directory_bytes)?;
		tracing::trace!(%bytes, "wrote directory");

		let mut trailer = Trailer {
			file_version: ZARC_FILE_VERSION,
			directory_version: ZARC_DIRECTORY_VERSION,
			digest_type: DigestType::Blake3,
			signature_type: SignatureType::Ed25519,
			directory_offset: 0,
			directory_uncompressed_size: directory_bytes.len() as _,
			public_key: public_key.clone().into(),
			digest: Digest(digest.to_vec()),
			signature: Signature(signature.to_vec()),
		};
		trailer.directory_offset = -((bytes + SKIPPABLE_FRAME_OVERHEAD + trailer.len()) as i64);
		tracing::trace!(?trailer, "built trailer");

		let trailer_bytes = trailer.to_bytes();
		tracing::trace!(
			bytes = %format!("{trailer_bytes:02x?}"),
			length = %trailer_bytes.len(),
			"serialised trailer"
		);

		let bytes = self.write_skippable_frame(0xF, trailer_bytes)?;
		tracing::trace!(%bytes, "wrote trailer");

		self.writer.flush()?;
		tracing::trace!("flushed writer");

		Ok(public_key)
	}
}
