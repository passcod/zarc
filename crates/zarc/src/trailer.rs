//! Zarc Trailer structure
//!
//! This is the last part of a Zarc archive, and contains the critical metadata of the archive.
//! Where [the header][super::header] is used to identify a Zarc file, this is used to actually
//! decode it.
//!
//! The peculiarity of the trailer is that it's parsed backwards from the end. The digest field is
//! potentially variable in length, and the only way to know its length is to read one of two bytes
//! in the trailer, at either sides of that variable field.
//!
//! However, reading a file backward is obnoxious and possibly slow, so the way this module works is
//! with the [`Epilogue`], comprising the last six fields of the trailer, all fixed-size. You should
//! use [`EPILOGUE_LENGTH`] to seek and read these bytes from the end, parse them, and then use
//! [`Epilogue::full_length()`] to seek and read the remaining bytes, and finally pass them to
//! [`Epilogue::complete()`] to obtain a [`Trailer`].
//!
//! Additionally, what you probably want to do for performance is to read, for example, a kilobyte
//! from the end of the file at once, and then be reasonably sure that the whole trailer is in it.
//!
//! The trailer also has [`PROLOGUE_LENGTH`] bytes of "prologue", which this library ignores (but
//! will write correctly). The prologue contains a duplicate of the digest type, and can be used to
//! read the trailer "forward", if you really want to, though this library provides no support here.

use deku::prelude::*;

use super::integrity::{Digest, DigestType};

/// Zarc Trailer
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-trailer)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trailer {
	/// Digest of the directory.
	pub digest: Digest,

	/// Digest (hash) algorithm.
	pub digest_type: DigestType,

	/// Offset in bytes to the start of the [Directory][crate::directory]'s Zstandard frame.
	pub directory_offset: i64,

	/// Uncompressed size in bytes of the directory.
	pub directory_uncompressed_size: u64,

	/// Zarc format version number.
	///
	/// Should match [`ZARC_VERSION`][crate::ZARC_VERSION].
	pub version: u8,
}

impl Trailer {
	/// Write the trailer to a writer.
	pub fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
		// reserved field and duplicated digest type
		writer.write_all(&[0, self.digest_type as u8])?;

		writer.write_all(&self.digest)?;

		let epilogue = Epilogue::from(self)
			.to_bytes()
			.map_err(std::io::Error::other)?;
		writer.write_all(&epilogue)
	}

	/// Write the trailer to a vector.
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(self.len());
		bytes.extend(self.digest.iter());

		// UNWRAP: there's no way to construct an epilogue that doesn't serialise
		#[allow(clippy::unwrap_used)]
		bytes.extend(Epilogue::from(self).to_bytes().unwrap());

		bytes
	}

	/// The full length of the trailer in bytes.
	#[allow(clippy::len_without_is_empty)] // CLIPPY: this is not a collection
	pub fn len(&self) -> usize {
		self.digest.len() + EPILOGUE_LENGTH
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
		bytes.extend(&[0, self.digest_type as u8]);
		bytes.extend(self.digest.iter());

		// UNWRAP: there's no way to construct an epilogue that doesn't serialise
		#[allow(clippy::unwrap_used)]
		bytes.extend(self.epilogue_without_check().to_bytes().unwrap());

		bytes.iter().fold(0, |check, x| check ^ *x)
	}

	/// Get the epilogue from this trailer, but set the check byte to 0.
	fn epilogue_without_check(&self) -> Epilogue {
		Epilogue {
			check: 0,
			digest_type: self.digest_type,
			directory_offset: self.directory_offset,
			directory_uncompressed_size: self.directory_uncompressed_size,
			version: self.version,
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

/// Length of the prologue in bytes.
///
/// This is the wire length, not the size of the struct.
pub const PROLOGUE_LENGTH: usize = 2;

/// Length of the epilogue in bytes.
///
/// This is the wire length, not the size of the struct.
pub const EPILOGUE_LENGTH: usize = 22;

/// The last eight fields of the trailer, which are all fixed-size.
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct Epilogue {
	/// Digest (hash) algorithm.
	pub digest_type: DigestType,

	/// Offset in bytes to the start of the [Directory][crate::directory]'s Zstandard frame.
	///
	/// A positive value is from the start of the file, a negative value is from the end.
	#[deku(bytes = "8")]
	pub directory_offset: i64,

	/// Uncompressed size in bytes of the directory.
	#[deku(bytes = "8")]
	pub directory_uncompressed_size: u64,

	/// Check byte.
	#[deku(bytes = "1")]
	pub check: u8,

	/// Zarc format version number.
	///
	/// Should match [`ZARC_VERSION`][crate::ZARC_VERSION].
	#[deku(bytes = "1")]
	pub version: u8,

	/// Magic number.
	///
	/// Should match [`ZARC_MAGIC`][crate::ZARC_MAGIC].
	#[deku(count = "3")]
	pub magic: Vec<u8>,
}

impl Epilogue {
	/// The full length of the trailer including the variable fields.
	pub const fn full_length(&self) -> usize {
		PROLOGUE_LENGTH + self.digest_type.digest_len() + EPILOGUE_LENGTH
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

		let head = all_bytes.len() - (self.digest_type.digest_len() + EPILOGUE_LENGTH);
		let size = self.digest_type.digest_len();
		let digest = all_bytes[head..(head + size)].to_vec();

		Ok(Trailer {
			digest: Digest(digest),
			digest_type: self.digest_type,
			directory_offset: self.directory_offset,
			directory_uncompressed_size: self.directory_uncompressed_size,
			version: self.version,
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
