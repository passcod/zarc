use deku::prelude::*;

use super::constants::ZARC_MAGIC;

/// Zarc Header
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-header)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct ZarcHeader {
	/// Magic number. Asserted to match [`ZARC_MAGIC`].
	#[deku(count = "3", assert = "*magic == ZARC_MAGIC")]
	pub magic: Vec<u8>,

	/// File format version number. Should match [`ZARC_FILE_VERSION`][super::constants::ZARC_FILE_VERSION].
	#[deku(bytes = "1")]
	pub file_version: u8,
}
