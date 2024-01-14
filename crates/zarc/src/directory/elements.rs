use std::num::TryFromIntError;

use deku::prelude::*;

use super::{edition::Edition, file::File, frame::Frame};

/// Zarc Directory Element framing
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-directory)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct ElementFrame {
	/// Element kind.
	pub kind: ElementKind,

	/// Length of CBOR data.
	#[deku(bytes = "2", update = "self.payload.len()", pad_bytes_after = "1")]
	pub length: u16,

	/// CBOR data.
	///
	/// This is at most 65536 bytes.
	#[deku(count = "length")]
	pub payload: Vec<u8>,
}

impl ElementFrame {
	/// Encode an [Element] into a CBOR payload.
	///
	/// CBOR encoding is infallible; this returns `Err` if the element is too large to fit (>64K).
	pub fn create(element: &Element) -> Result<Self, TryFromIntError> {
		let payload = element.to_vec();
		u16::try_from(payload.len()).map(|length| Self {
			kind: element.kind(),
			length,
			payload,
		})
	}

	/// Decode the CBOR payload into its [Element].
	///
	/// Returns `Ok(None)` if the element kind is unknown.
	pub fn element(&self) -> Result<Option<Element>, minicbor::decode::Error> {
		match self.kind {
			ElementKind::Edition => {
				minicbor::decode(&self.payload).map(|e| Some(Element::Edition(e)))
			}
			ElementKind::File => minicbor::decode(&self.payload).map(|e| Some(Element::File(e))),
			ElementKind::Frame => minicbor::decode(&self.payload).map(|e| Some(Element::Frame(e))),
			ElementKind::Unknown(_) => Ok(None),
		}
	}
}

/// Kind of an element (including unknown variant).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, DekuRead, DekuWrite)]
#[deku(endian = "endian", type = "u8", ctx = "endian: deku::ctx::Endian")]
pub enum ElementKind {
	/// [Edition]
	#[deku(id = "1")]
	Edition,

	/// [File]
	#[deku(id = "2")]
	File,

	/// [Frame]
	#[deku(id = "3")]
	Frame,

	/// Unknown element kind.
	#[deku(id_pat = "_")]
	Unknown(u8),
}

/// Elements supported by Zarc.
#[derive(Clone, Debug, PartialEq)]
pub enum Element {
	/// [Edition]
	Edition(Box<Edition>),
	/// [File]
	File(Box<File>),
	/// [Frame]
	Frame(Box<Frame>),
}

impl Element {
	/// Get the [ElementKind] of this element.
	pub fn kind(&self) -> ElementKind {
		match self {
			Element::Edition(_) => ElementKind::Edition,
			Element::File(_) => ElementKind::File,
			Element::Frame(_) => ElementKind::Frame,
		}
	}

	/// Write the [Element] into a CBOR payload.
	pub fn to_vec(&self) -> Vec<u8> {
		#[allow(clippy::unwrap_used)] // UNWRAP: minicbor encoding is infallible
		match self {
			Element::Edition(edition) => minicbor::to_vec(edition),
			Element::File(file) => minicbor::to_vec(file),
			Element::Frame(frame) => minicbor::to_vec(frame),
		}
		.unwrap()
	}
}
