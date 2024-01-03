//! Zstd file format parsing types.
//!
//! [Spec (Informational RFC8878)](https://datatracker.ietf.org/doc/html/rfc8878)
//!
//! Here's a quick recap of the zstd format, full specification available at link above:
//!
//! - The format is a sequence of frames
//! - Frames can either be [Zstandard frames](ZstandardFrame) or [Skippable frames](SkippableFrame)
//! - A standard zstd decoder will skip Skippable frames
//! - Numbers are little-endian
//! - Zstandard frames:
//!   - `[magic][header][blocks...][checksum]`
//!   - Magic is 0xFD2FB528
//!   - [Header](ZstandardFrameDescriptor) is 2-14 bytes, described in spec above
//!   - Checksum is optional, last 4 bytes of xxhash64
//!   - [Blocks](ZstandardBlock) are:
//!     - `[last][type][size][data]`
//!       - Last is 1 bit (boolean)
//!       - Type is 2 bits (enum)
//!       - Size is 21 bits, unsigned
//!     - [Type](ZstandardBlockType) describes:
//!       0. Raw block (`data` is uncompressed, verbatim)
//!       1. RLE block (`data` is a single byte, `size` is how many times it's repeated verbatim)
//!       2. Compressed block
//!       3. Reserved
//! - Skippable frames:
//!   - `[magic][size][data]`
//!   - Magic is 0x184D2A5? where the last nibble **?** is any value from 0 to F
//!   - Size is unsigned 32-bit int

use deku::prelude::*;

/// Magic number for a [Skippable Frame](SkippableFrame).
///
/// This is only bytes 1-3 of the magic, and the first byte is any value from 0x50 to 0x5F.
pub const SKIPPABLE_FRAME_MAGIC: &'static [u8] = b"\x2A\x4D\x18";

/// Magic number for a [Zstandard Frame](ZstandardFrame).
pub const ZSTANDARD_FRAME_MAGIC: &'static [u8] = b"\x28\xB5\x2F\xFD";

/// A "Skippable" frame.
///
/// [Spec](https://datatracker.ietf.org/doc/html/rfc8878#name-skippable-frames)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct SkippableFrame {
	#[deku(bytes = "4")]
	magic: u32,

	#[deku(bytes = "4")]
	size: u32,

	/// The user data contained in the frame.
	#[deku(count = "size")]
	pub data: Vec<u8>,
}

impl SkippableFrame {
	/// Create a new skippable frame.
	///
	/// Panics if the nibble is greater than 15.
	pub fn new(nibble: u8, data: Vec<u8>) -> Self {
		assert!(
			nibble < 16,
			"skippable frame nibble must be between 0 and 15"
		);
		Self {
			magic: u32::from_le_bytes([0x50 + nibble, 0x2A, 0x4D, 0x18]),
			size: data
				.len()
				.try_into()
				.expect("skippable frame data is too long"),
			data,
		}
	}

	/// The length of the frame's content.
	pub fn size(&self) -> usize {
		self.size as usize
	}
}

/// A Zstandard Frame.
///
/// [Spec](https://datatracker.ietf.org/doc/html/rfc8878#name-zstandard-frames)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little", magic = b"\x28\xB5\x2F\xFD")]
pub struct ZstandardFrame {
	/// The frame descriptor.
	///
	/// [Spec](https://datatracker.ietf.org/doc/html/rfc8878#section-3.1.1.1.1)
	///
	/// Describes what other fields are present in the frame header.
	pub frame_descriptor: ZstandardFrameDescriptor,

	/// Minimum memory needed to decode the frame.
	///
	/// [Spec](https://datatracker.ietf.org/doc/html/rfc8878#name-window-descriptor)
	#[deku(bytes = 1, cond = "!frame_descriptor.single_segment")]
	pub window_descriptor: Option<u8>,

	/// Dictionary ID.
	///
	/// [Spec](https://datatracker.ietf.org/doc/html/rfc8878#section-3.1.1.1.3)
	///
	/// See [`ZstandardFrame::dictionary_id()`] for the value as an integer.
	#[deku(count = "frame_descriptor.did_length()")]
	pub did: Vec<u8>,

	/// Original (uncompressed) size.
	///
	/// [Spec](https://datatracker.ietf.org/doc/html/rfc8878#name-frame_content_size)
	///
	/// This field is optional.
	///
	/// This needs to be interpreted before it can be used. See [`ZstandardFrame::size()`].
	#[deku(count = "frame_descriptor.fcs_length()")]
	pub frame_content_size: Vec<u8>,

	/// Blocks.
	///
	/// Those are the actual content of the frame.
	#[deku(until = "|b: &ZstandardBlock| b.header.last")]
	pub blocks: Vec<ZstandardBlock>,

	/// Optional 32-bit checksum.
	///
	/// The lower 4 bytes of the [xxhash64](https://cyan4973.github.io/xxHash/) digested from the
	/// original content and a seed of zero.
	///
	/// Only present if [`ZstandardFrameDescriptor::checksum`] is set.
	#[deku(bytes = 4, cond = "frame_descriptor.checksum")]
	pub checksum: Option<u32>,
}

impl ZstandardFrame {
	/// The uncompressed length of the frame's content in bytes.
	pub fn uncompressed_size(&self) -> u64 {
		match self.frame_descriptor.fcs_length() {
			0 => 0,
			1 => u64::from(self.frame_content_size[0]),
			2 => {
				u64::from(u16::from_le_bytes([
					self.frame_content_size[0],
					self.frame_content_size[1],
				])) + 256
			}
			4 => u64::from(u32::from_le_bytes([
				self.frame_content_size[0],
				self.frame_content_size[1],
				self.frame_content_size[2],
				self.frame_content_size[3],
			])),
			8 => u64::from_le_bytes([
				self.frame_content_size[0],
				self.frame_content_size[1],
				self.frame_content_size[2],
				self.frame_content_size[3],
				self.frame_content_size[4],
				self.frame_content_size[5],
				self.frame_content_size[6],
				self.frame_content_size[7],
			]),
			_ => unreachable!(),
		}
	}

	/// The dictionary ID as an integer.
	pub fn dictionary_id(&self) -> u32 {
		self.did.iter().fold(0, |acc, &x| acc << 8 | x as u32)
	}
}

/// Frame descriptor for a [Zstandard Frame](ZstandardFrame).
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct ZstandardFrameDescriptor {
	/// [Frame content size (FCS)](ZstandardFrame::frame_content_size) field size flag.
	///
	/// This is _not_ the size of the FCS field itself, but a flag that needs to be interpreted in
	/// conjunction with [`single_segment`](ZstandardFrameDescriptor::single_segment) to determine
	/// the size of the FCS field.
	///
	/// The [`ZstandardFrameDescriptor::fcs_length()`] method performs this calculation.
	#[deku(bits = 2)]
	pub fcs_size: u8,

	/// If this flag is set, data must be regenerated within a single continuous memory segment.
	///
	/// This is also used in the calculation for [`ZstandardFrame::frame_content_size`]'s length.
	#[deku(bits = 1)]
	pub single_segment: bool,

	/// Unused. Always false.
	#[deku(bits = 1)]
	pub unused_bit: bool,

	/// Reserved. Always false.
	#[deku(bits = 1)]
	pub reserved_bit: bool,

	/// Whether the frame has a [checksum](ZstandardFrame::checksum).
	#[deku(bits = 1)]
	pub checksum: bool,

	/// [Dictionary ID (DID)](ZstandardFrame::did) field size flag.
	///
	/// This is _not_ the size of the DID field itself, but a flag that needs to be interpreted to
	/// determine the size of the DID field.
	///
	/// The [`ZstandardFrameDescriptor::did_length()`] method performs this calculation.
	#[deku(bits = 2)]
	pub did_size: u8,
}

impl ZstandardFrameDescriptor {
	/// The length in bytes of the [DID](ZstandardFrame::did) field.
	pub fn did_length(&self) -> usize {
		match self.did_size {
			0 => 0,
			1 => 1,
			2 => 2,
			3 => 4,
			_ => unreachable!(),
		}
	}

	/// The length in bytes of the [FCS](ZstandardFrame::frame_content_size) field.
	pub fn fcs_length(&self) -> usize {
		match self.fcs_size {
			0 if self.single_segment => 1,
			0 => 0,
			1 => 2,
			2 => 4,
			3 => 8,
			_ => unreachable!(),
		}
	}
}

/// A Zstandard block.
///
/// [Spec](https://datatracker.ietf.org/doc/html/rfc8878#name-blocks)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct ZstandardBlock {
	/// The block header.
	pub header: ZstandardBlockHeader,

	/// The block data.
	#[deku(count = "header.actual_size()")]
	pub data: Vec<u8>,
}

/// The header for a Zstandard block.
///
/// [Spec](https://datatracker.ietf.org/doc/html/rfc8878#name-blocks)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "endian", ctx = "endian: deku::ctx::Endian")]
pub struct ZstandardBlockHeader {
	#[deku(bits = "5")]
	size_low: u8,

	/// The block type.
	pub block_type: ZstandardBlockType,

	/// Whether this is the last block in the frame.
	#[deku(bits = "1")]
	pub last: bool,

	#[deku(bits = "16")]
	size_high: u16,
}

impl ZstandardBlockHeader {
	/// Create a new Zstandard block header.
	pub fn new(block_type: ZstandardBlockType, last: bool, size: u32) -> Self {
		assert!(size <= 2_u32.pow(24) - 1);

		let [a, b, c, d] = u32::to_be_bytes(size << 3);
		let size_high = u16::from_be_bytes([b, c]);
		let size_low = d >> 3;
		tracing::trace!(
			field = %format!("{a:08b} {b:08b} {c:08b} {d:08b}"),
			high = %format!("{size_high:016b}"),
			low = %format!("{size_low:08b}"),
			"block header size bit wrangling (write)"
		);

		Self {
			size_low,
			block_type,
			last,
			size_high,
		}
	}

	fn size(&self) -> u32 {
		let [a, b] = u16::to_be_bytes(self.size_high);
		let c = self.size_low << 3;
		let real_size = u32::from_be_bytes([0, a, b, c]) >> 3;
		tracing::trace!(
			high = %format!("{:016b}", self.size_high),
			low = %format!("{:08b}", self.size_low),
			real_dec = %real_size,
			real_hex = %format!("{real_size:02x?}"),
			"block header size bit wrangling (read)"
		);

		real_size
	}

	/// If this is an RLE, how many times is the byte repeated?
	pub fn rle_count(&self) -> Option<u32> {
		if self.block_type == ZstandardBlockType::Rle {
			Some(self.size())
		} else {
			None
		}
	}

	/// How many bytes of data are in this block.
	pub fn actual_size(&self) -> u32 {
		match self.block_type {
			ZstandardBlockType::Raw | ZstandardBlockType::Compressed => self.size(),
			ZstandardBlockType::Rle => 1,
			ZstandardBlockType::Reserved => panic!("corrupt zstd: reserved block type"),
		}
	}
}

/// The type of a Zstandard block.
///
/// [Spec](https://datatracker.ietf.org/doc/html/rfc8878#name-block_type)
#[derive(Clone, Debug, Eq, PartialEq, DekuRead, DekuWrite)]
#[deku(
	endian = "endian",
	ctx = "endian: deku::ctx::Endian",
	type = "u8",
	bits = "2"
)]
pub enum ZstandardBlockType {
	/// An uncompressed block.
	#[deku(id = "0b00")] // = 0
	Raw,

	/// A block with a single byte repeated many times.
	#[deku(id = "0b01")] // = 1
	Rle,

	/// A compressed block.
	#[deku(id = "0b10")] // = 2
	Compressed,

	/// Reserved.
	#[deku(id = "0b11")] // = 3
	Reserved,
}
