use deku::prelude::*;
use minicbor::{data::Type, Decode, Decoder, Encode, Encoder};

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
