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

/// Kind of an element (as a unit enum).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, DekuRead, DekuWrite)]
#[deku(endian = "endian", type = "u8", ctx = "endian: deku::ctx::Endian")]
#[repr(u8)]
pub enum ElementKind {
	/// [Edition]
	Edition = 1,
	/// [File]
	File = 2,
	/// [Frame]
	Frame = 3,
}

/// Element enum.
#[derive(Clone, Debug, PartialEq)]
pub enum Element {
	/// [Edition]
	Edition(Edition),
	/// [File]
	File(File),
	/// [Frame]
	Frame(Frame),
}

impl ElementFrame {
	/// Encode an [Element] into a CBOR payload.
	///
	/// CBOR encoding is infallible; this returns `Err` if the element is too large to fit (>64K).
	pub fn create(element: &Element) -> Result<Self, TryFromIntError> {
		// UNWRAP: minicbor encoding is infallible
		let (kind, payload) = match element {
			Element::Edition(edition) => (ElementKind::Edition, minicbor::to_vec(edition).unwrap()),
			Element::File(file) => (ElementKind::File, minicbor::to_vec(file).unwrap()),
			Element::Frame(frame) => (ElementKind::Frame, minicbor::to_vec(frame).unwrap()),
		};

		u16::try_from(payload.len()).map(|length| Self {
			kind,
			length,
			payload,
		})
	}

	/// Decode the CBOR payload into its [Element].
	pub fn element(&self) -> Result<Element, minicbor::decode::Error> {
		match self.kind {
			ElementKind::Edition => minicbor::decode(&self.payload).map(Element::Edition),
			ElementKind::File => minicbor::decode(&self.payload).map(Element::File),
			ElementKind::Frame => minicbor::decode(&self.payload).map(Element::Frame),
		}
	}
}