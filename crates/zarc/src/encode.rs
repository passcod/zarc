//! Encoder types and functions.

use std::{
	collections::{BTreeMap, HashMap},
	fmt,
	io::{Error, Result, Write},
	num::NonZeroU16,
};

use ed25519_dalek::{Signer, SigningKey};
use tracing::{instrument, trace};
use zstd_safe::CCtx;
pub use zstd_safe::{CParameter as ZstdParameter, Strategy as ZstdStrategy};

use crate::{
	directory::{File, Frame, Pathname},
	header::FILE_MAGIC,
	integrity::{Digest, Signature},
	map_zstd_error,
};

mod add_file;
mod content_frame;
mod directory;
mod lowlevel_frames;

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
			.field("files", &self.files)
			.field("frames", &self.frames)
			.field("files_by_name", &self.files_by_name)
			.field("files_by_digest", &self.files_by_digest)
			.field("offset", &self.offset)
			.field("compress", &self.compress)
			.finish()
	}
}

impl<'writer, W: Write> Encoder<'writer, W> {
	/// Create a new encoder and write the header.
	///
	/// Requires a CSRNG implementation to generate the signing key.
	#[instrument(level = "trace", skip(writer, csrng))]
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
	#[instrument(level = "trace", skip(self))]
	pub fn sign_user_data(&self, data: &[u8]) -> Result<Signature> {
		let signature = self.key.try_sign(data).map_err(|err| Error::other(err))?;
		Ok(Signature(signature.to_vec()))
	}

	/// Set a zstd parameter.
	///
	/// This will apply to future data frames.
	#[instrument(level = "trace", skip(self))]
	pub fn set_zstd_parameter(&mut self, parameter: ZstdParameter) -> Result<()> {
		self.zstd
			.set_parameter(parameter)
			.map_err(map_zstd_error)
			.map(drop)
	}

	/// Enable or disable compression.
	///
	/// This well apply to future data frames.
	#[instrument(level = "trace", skip(self))]
	pub fn enable_compression(&mut self, compress: bool) {
		self.compress = compress;
	}
}
