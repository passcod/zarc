//! Types supporting file integrity (checksums).

use deku::prelude::*;
use minicbor::{data::Type, Decode, Decoder, Encode, Encoder};

/// Digest newtype.
///
/// This is a wrapper around a byte vector, which is the actual digest.
///
/// Currently only BLAKE3 is supported, but this type is designed to be generic over algorithms.
///
/// The `PartialEq` and `Eq` implementations are constant-time.
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Clone, Debug, Eq, Hash, DekuWrite)]
pub struct Digest(pub Vec<u8>);

impl PartialEq for Digest {
	fn eq(&self, other: &Self) -> bool {
		use subtle::ConstantTimeEq;
		self.0.ct_eq(&other.0).into()
	}
}

impl std::ops::Deref for Digest {
	type Target = Vec<u8>;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl From<Vec<u8>> for Digest {
	fn from(bytes: Vec<u8>) -> Self {
		Self(bytes)
	}
}

impl<'a, Ctx> DekuReader<'a, Ctx> for Digest
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

impl<C> Encode<C> for Digest {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		_ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		e.bytes(&self.0).map(drop)
	}
}

impl<'b, C> Decode<'b, C> for Digest {
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

impl From<blake3::Hash> for Digest {
	fn from(value: blake3::Hash) -> Self {
		Self(value.as_bytes().to_vec())
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
				let actual = blake3::hash(data);
				let Ok(expected_bytes) = expected.as_slice().try_into() else {
					return false;
				};
				blake3::Hash::from_bytes(expected_bytes) == actual
			}
		}
	}
}
