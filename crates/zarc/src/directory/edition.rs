use std::{collections::HashMap, num::NonZeroU16};

use minicbor::{Decode, Encode};

use super::{strings::AttributeValue, timestamps::Timestamp};
use crate::integrity::{DigestType, PublicKey, SignatureType};

/// Metadata about a (previous) version of the Zarc Directory
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#kind-1-editions)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct Edition {
	/// Edition number.
	///
	/// Used for referencing it in frames and files.
	#[n(0)]
	pub number: NonZeroU16,

	/// Public key of this edition.
	#[n(1)]
	pub public_key: PublicKey,

	/// Version creation date.
	#[n(2)]
	pub written_at: Timestamp,

	/// Digest algorithm used by this edition.
	#[n(3)]
	pub digest_type: DigestType,

	/// Signature algorithm used by this edition.
	#[n(4)]
	pub signature_type: SignatureType,

	/// User Metadata of that version.
	///
	/// You can write a Some(empty HashMap), but you'll save two bytes if you write a None instead.
	/// This is pretty cheap here, but adds up for the similar fields in [`files`](FilemapEntry).
	#[n(10)]
	pub user_metadata: Option<HashMap<String, AttributeValue>>,
}
