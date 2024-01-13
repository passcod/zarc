//! Encoder types and functions.

use std::{
	collections::{BTreeMap, HashMap},
	fmt,
	io::{Error, Result, Write},
	mem::take,
	num::NonZeroU16,
};

use blake3::Hasher;
use deku::DekuContainerWrite;
use ed25519_dalek::{Signer, SigningKey};
use ozarc::framing::SKIPPABLE_FRAME_OVERHEAD;
use tracing::{debug, trace};
use zstd_safe::{CCtx, ResetDirective};
pub use zstd_safe::{CParameter as ZstdParameter, Strategy as ZstdStrategy};

use crate::{
	constants::{ZARC_DIRECTORY_VERSION, ZARC_FILE_VERSION},
	directory::{Edition, Element, ElementFrame, File, Frame, Pathname, Timestamp},
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
	files: Vec<Option<File>>,
	frames: HashMap<Digest, Frame>,
	files_by_name: BTreeMap<Pathname, Vec<usize>>,
	files_by_digest: HashMap<Digest, Vec<usize>>,
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
			.field("filemap", &self.files)
			.field("framelist", &self.frames)
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
		trace!("generate signing key");
		let key = SigningKey::generate(csrng);
		if key.verifying_key().is_weak() {
			return Err(Error::other("signing key is weak"));
		}

		trace!("create zstd context");
		let mut zstd =
			CCtx::try_create().ok_or_else(|| Error::other("failed allocating zstd context"))?;
		zstd.init(0).map_err(map_zstd_error)?;

		trace!("write zarc magic");
		let offset = writer.write(&FILE_MAGIC)?;

		Ok(Self {
			writer,
			zstd,
			key,
			edition: unsafe { NonZeroU16::new_unchecked(1) },
			files: Vec::new(),
			frames: HashMap::new(),
			files_by_name: BTreeMap::new(),
			files_by_digest: HashMap::new(),
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

		trace!(
			bytes = %format!("{data:02x?}"),
			length = %data.len(),
			buffer_size = %buffer.capacity(),
			"compress data into buffer"
		);
		self.zstd
			.compress2(&mut buffer, data)
			.map_err(map_zstd_error)?;

		trace!(
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
		trace!(
			bytes = %format!("{data:02x?}"),
			length = %data.len(),
			magic,
			"compose data into frame"
		);
		let frame = ozarc::framing::SkippableFrame::new(magic, data);
		let buffer = frame.to_bytes()?;

		trace!(
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

		if self.frames.contains_key(&digest) {
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
		self.frames.insert(
			digest.clone(),
			Frame {
				edition: self.edition,
				offset: offset.try_into().map_err(|err| Error::other(err))?,
				digest: digest.clone(),
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
		if let Some(hash) = &entry.digest {
			if !self.frames.contains_key(hash) {
				return Err(Error::other(
					"cannot add file entry referencing unknown data frame",
				));
			}
		}

		let name = entry.name.clone();
		let digest = entry.digest.clone();

		self.files.push(Some(entry));
		let index = self.files.len() - 1;
		trace!(index, "added file entry");

		self.files_by_name
			.entry(name)
			.or_insert_with(Vec::new)
			.push(index);
		if let Some(digest) = digest {
			self.files_by_digest
				.entry(digest)
				.or_insert_with(Vec::new)
				.push(index);
		}

		Ok(())
	}

	fn write_element(buf: &mut Vec<u8>, hasher: &mut Hasher, element: &Element) -> Result<()> {
		let frame = ElementFrame::create(element).map_err(Error::other)?;
		let bytes = frame.to_bytes().map_err(Error::other)?;
		buf.write_all(&bytes)?;
		hasher.update(&bytes);
		trace!(
			kind = ?element.kind(),
			length = %bytes.len(),
			bytes = %format!("{bytes:02x?}"),
			"wrote element"
		);
		Ok(())
	}

	/// Write the directory and trailer.
	///
	/// Flushes the writer and drops all state.
	///
	/// Discards the private key and returns the public key.
	pub fn finalise(mut self) -> Result<PublicKey> {
		let mut directory = Vec::new();
		let mut hasher = Hasher::new();

		let public_key = PublicKey(self.key.verifying_key().as_bytes().to_vec());
		let digest_type = DigestType::Blake3;
		let signature_type = SignatureType::Ed25519;

		Self::write_element(
			&mut directory,
			&mut hasher,
			&Element::Edition(Edition {
				number: self.edition,
				public_key: public_key.clone(),
				written_at: Timestamp::now(),
				digest_type,
				signature_type,
				user_metadata: Default::default(),
			}),
		)?;

		for (name, indices) in take(&mut self.files_by_name) {
			debug!(?name, "write file and frame elements");

			for index in indices {
				let Some(file) = self.files.get_mut(index).and_then(Option::take) else {
					// this shouldn't happen, but it's cheap to just skip instead of unwrapping
					continue;
				};

				// we always want to insert a frame element before the linked file element
				if let Some(digest) = &file.digest {
					// if we've already written it, this will be None
					if let Some(frame) = self.frames.remove(digest) {
						Self::write_element(&mut directory, &mut hasher, &Element::Frame(frame))?;
					}
				}

				Self::write_element(&mut directory, &mut hasher, &Element::File(file))?;
			}
		}

		// we should have written every frame, but just in case
		// (or if user inserted frames not linked to files)
		for frame in take(&mut self.frames).into_values() {
			Self::write_element(&mut directory, &mut hasher, &Element::Frame(frame))?;
		}

		let digest = hasher.finalize();
		trace!(?digest, "hashed directory");
		let digest = digest.as_bytes();
		let signature = self.key.try_sign(digest).map_err(|err| Error::other(err))?;
		trace!(?signature, "signed directory hash");

		let bytes = self.write_compressed_frame(&directory)?;
		trace!(%bytes, "wrote directory");

		let mut trailer = Trailer {
			file_version: ZARC_FILE_VERSION,
			directory_version: ZARC_DIRECTORY_VERSION,
			digest_type,
			signature_type,
			directory_offset: 0,
			directory_uncompressed_size: directory.len() as _,
			public_key: public_key.clone().into(),
			digest: Digest(digest.to_vec()),
			signature: Signature(signature.to_vec()),
		};
		trailer.directory_offset = -((bytes + SKIPPABLE_FRAME_OVERHEAD + trailer.len()) as i64);
		trace!(?trailer, "built trailer");

		let trailer_bytes = trailer.to_bytes();
		trace!(
			bytes = %format!("{trailer_bytes:02x?}"),
			length = %trailer_bytes.len(),
			"serialised trailer"
		);

		let bytes = self.write_skippable_frame(0xF, trailer_bytes)?;
		trace!(%bytes, "wrote trailer");

		self.writer.flush()?;
		trace!("flushed writer");

		Ok(public_key)
	}
}
