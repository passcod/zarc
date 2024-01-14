//! Zarc Header structure and byte array
//!
//! The purpose of the header is to identify the file as a Zarc file. It also has the file version
//! number, but this can be considered part of the "file magic" rather than actual metadata.
//!
//! This module has two implementations of the header: [`Header`] which lets you decode the header
//! from the skippable frame's payload, and [`FILE_MAGIC`] which is a constant byte array that
//! includes the Zstd framing and can be matched byte-for-byte against the start of a Zarc file.

use deku::prelude::*;

use super::constants::{ZARC_MAGIC, ZARC_VERSION};

/// Zarc Header
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-header)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct Header {
	/// Magic number. Asserted to match [`ZARC_MAGIC`].
	#[deku(count = "3", assert = "*magic == ZARC_MAGIC")]
	pub magic: Vec<u8>,

	/// Zarc format version number. Should match [`ZARC_VERSION`].
	#[deku(bytes = "1")]
	pub version: u8,
}

/// Static file magic
///
/// This is a zstd Skippable frame containing the Zarc Header, as a hardcoded constant.
///
/// In a valid Zarc file, the first 12 bytes will match exactly.
#[rustfmt::skip]
pub const FILE_MAGIC: [u8; 12] = [
	0x50, 0x2A, 0x4D, 0x18, // zstd skippable frame
	0x04, 0x00, 0x00, 0x00, // payload size = 4 bytes
	0x65, 0xAA, 0xDC, // zarc magic
	ZARC_VERSION, // zarc version
];
