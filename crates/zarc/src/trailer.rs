//! Zarc Trailer structure
//!
//! This is the last part of a Zarc archive, and contains the critical metadata of the archive.
//! Where [the header][super::header] is used to identify a Zarc file, this is used to actually
//! decode it.
//!
//! The peculiarity of the trailer is that it's parsed backwards from the end. There are three
//! fields that may be variable in length, and the only way to know where they are is to read two
//! bytes in the trailer, and because the trailer is at the end of the file, that means those bytes
//! have to come *after* the variable fields.
//!
//! However, reading a file backward is obnoxious and possibly slow, so the way this module works is
//! with the [`Epilogue`], comprising the last eight fields of the trailer, all fixed-size. You
//! should use [`EPILOGUE_LENGTH`] to seek and read these bytes from the end, parse them, and then
//! use [`Epilogue::full_length()`] to seek and read the remaining bytes, and finally pass them to
//! [`Epilogue::complete()`] to obtain a [`Trailer`].
//!
//! Additionally, what you probably want to do for performance is to read, for example, a kilobyte
//! from the end of the file at once, and then be reasonably sure that the whole trailer is in it.

use deku::prelude::*;

use super::integrity::{Digest, DigestType, PublicKey, Signature, SignatureType};

/// Zarc Trailer
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-trailer)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trailer {
	/// Public key.
	pub public_key: PublicKey,

	/// Digest of the directory.
	pub digest: Digest,

	/// Signature over the digest.
	pub signature: Signature,

	/// Digest (hash) algorithm.
	pub digest_type: DigestType,

	/// Signature scheme.
	pub signature_type: SignatureType,

	/// Offset in bytes to the start of the [Directory][crate::directory]'s Zstandard frame.
	pub directory_offset: i64,

	/// Uncompressed size in bytes of the directory.
	pub directory_uncompressed_size: u64,

	/// Directory format version number.
	///
	/// Should match [`ZARC_DIRECTORY_VERSION`][crate::ZARC_DIRECTORY_VERSION].
	pub directory_version: u8,

	/// File format version number.
	///
	/// Should match [`ZARC_FILE_VERSION`][crate::ZARC_FILE_VERSION].
	pub file_version: u8,
}

impl Trailer {
	/// Write the trailer to a writer.
	pub fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
		writer.write_all(&self.public_key)?;
		writer.write_all(&self.digest)?;
		writer.write_all(&self.signature)?;

		let epilogue = Epilogue::from(self)
			.to_bytes()
			.map_err(std::io::Error::other)?;
		writer.write_all(&epilogue)
	}

	/// Write the trailer to a vector.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(self.len());
		bytes.extend(self.public_key.iter());
		bytes.extend(self.digest.iter());
		bytes.extend(self.signature.iter());
		// UNWRAP: there's no way to construct an epilogue that doesn't serialise
		bytes.extend(Epilogue::from(self).to_bytes().unwrap());
		bytes
	}

	/// The full length of the trailer in bytes.
	pub fn len(&self) -> usize {
		self.public_key.len() + self.digest.len() + self.signature.len() + EPILOGUE_LENGTH
	}

	/// Make the offset positive.
	///
	/// Having the offset negative is very useful when _writing_ the trailer, but generally a pain
	/// when using it to decode the archive, so this method inverts it given the file length.
	///
	/// Does nothing if the offset is already positive.
	///
	/// See also [`Epilogue::make_offset_positive()`].
	pub fn make_offset_positive(&mut self, file_length: u64) {
		if self.directory_offset < 0 {
			self.directory_offset += file_length as i64;
		}
	}

	/// Compute the check byte.
	pub fn compute_check(&self) -> u8 {
		let mut bytes = Vec::with_capacity(self.len());
		bytes.extend(self.public_key.iter());
		bytes.extend(self.digest.iter());
		bytes.extend(self.signature.iter());
		// UNWRAP: there's no way to construct an epilogue that doesn't serialise
		bytes.extend(self.epilogue_without_check().to_bytes().unwrap());
		bytes.iter().fold(0, |check, x| check ^ *x)
	}

	/// Get the epilogue from this trailer, but set the check byte to 0.
	fn epilogue_without_check(&self) -> Epilogue {
		Epilogue {
			check: 0,
			digest_type: self.digest_type,
			signature_type: self.signature_type,
			directory_offset: self.directory_offset,
			directory_uncompressed_size: self.directory_uncompressed_size,
			directory_version: self.directory_version,
			file_version: self.file_version,
			magic: crate::ZARC_MAGIC.to_vec(),
		}
	}
}

impl From<&Trailer> for Epilogue {
	fn from(trailer: &Trailer) -> Self {
		let mut epilogue = trailer.epilogue_without_check();
		epilogue.check = trailer.compute_check();
		epilogue
	}
}

/// Length of the epilogue in bytes.
///
/// This is the wire length, not the size of the struct.
pub const EPILOGUE_LENGTH: usize = 24;

/// The last eight fields of the trailer, which are all fixed-size.
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct Epilogue {
	/// Check byte.
	#[deku(bytes = "1")]
	pub check: u8,

	/// Digest (hash) algorithm.
	pub digest_type: DigestType,

	/// Signature scheme.
	pub signature_type: SignatureType,

	/// Offset in bytes to the start of the [Directory][crate::directory]'s Zstandard frame.
	///
	/// A positive value is from the start of the file, a negative value is from the end.
	#[deku(bytes = "8")]
	pub directory_offset: i64,

	/// Uncompressed size in bytes of the directory.
	#[deku(bytes = "8")]
	pub directory_uncompressed_size: u64,

	/// Directory format version number.
	///
	/// Should match [`ZARC_DIRECTORY_VERSION`][crate::ZARC_DIRECTORY_VERSION].
	#[deku(bytes = "1")]
	pub directory_version: u8,

	/// File format version number.
	///
	/// Should match [`ZARC_FILE_VERSION`][crate::ZARC_FILE_VERSION].
	#[deku(bytes = "1")]
	pub file_version: u8,

	/// Magic number.
	///
	/// Should match [`ZARC_MAGIC`][crate::ZARC_MAGIC].
	#[deku(count = "3")]
	pub magic: Vec<u8>,
}

impl Epilogue {
	/// The full length of the trailer including the variable fields.
	pub const fn full_length(&self) -> usize {
		EPILOGUE_LENGTH
			+ self.signature_type.public_key_len()
			+ self.signature_type.signature_len()
			+ self.digest_type.digest_len()
	}

	/// Reparse the trailer from the full bytes.
	///
	/// This copies the bytes it needs.
	///
	/// Returns `Err(bytes needed)` if there's not enough data to parse the trailer.
	/// Passing in too much data is fine, so long as the epilogue is at the end.
	pub fn complete(&self, all_bytes: &[u8]) -> Result<Trailer, usize> {
		if all_bytes.len() < self.full_length() {
			return Err(self.full_length() - all_bytes.len());
		}

		let head = all_bytes.len() - self.full_length();
		let pubkey = head + self.signature_type.public_key_len();
		let digest = pubkey + self.digest_type.digest_len();
		let signature = digest + self.signature_type.signature_len();

		Ok(Trailer {
			public_key: PublicKey(all_bytes[head..pubkey].to_vec()),
			digest: Digest(all_bytes[pubkey..digest].to_vec()),
			signature: Signature(all_bytes[digest..signature].to_vec()),
			digest_type: self.digest_type,
			signature_type: self.signature_type,
			directory_offset: self.directory_offset,
			directory_uncompressed_size: self.directory_uncompressed_size,
			directory_version: self.directory_version,
			file_version: self.file_version,
		})
	}

	/// Make the offset positive.
	///
	/// Having the offset negative is very useful when _writing_ the trailer, but generally a pain
	/// when using it to decode the archive, so this method inverts it given the file length.
	///
	/// Does nothing if the offset is already positive.
	///
	/// See also [`Trailer::make_offset_positive()`].
	pub fn make_offset_positive(&mut self, file_length: u64) {
		if self.directory_offset < 0 {
			self.directory_offset += file_length as i64;
		}
	}
}
