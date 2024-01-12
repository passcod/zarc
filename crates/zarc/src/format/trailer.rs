use deku::prelude::*;
use minicbor::{data::Type, Decode, Decoder, Encode, Encoder};

use super::integrity::{Digest, DigestType, PublicKey, Signature, SignatureType};

/// Zarc Directory Header
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-directory-header)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct ZarcTrailer {
	/// Magic number. Should match [`ZARC_MAGIC`][super::constants::ZARC_MAGIC].
	#[deku(count = "3", pad_bytes_after = "1")]
	pub magic: Vec<u8>,

	/// File format version number. Should match [`ZARC_FILE_VERSION`][super::constants::ZARC_FILE_VERSION].
	#[deku(bytes = "1")]
	pub file_version: u8,

	/// Directory format version number. Should match [`ZARC_DIRECTORY_VERSION`][super::constants::ZARC_DIRECTORY_VERSION].
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
