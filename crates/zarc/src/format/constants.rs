/// Magic bytes
pub const ZARC_MAGIC: [u8; 3] = [0x65, 0xAA, 0xDC];

/// Static file magic
///
/// This is a zstd Skippable frame containing the Zarc Header, as a hardcoded constant.
///
/// In a valid Zarc file, the first 12 bytes will match exactly.
///
/// For better diagnostics, you may prefer to parse the frame with zstd and [`ZarcHeader`] instead.
pub const FILE_MAGIC: [u8; 12] = [
	0x50, 0x2A, 0x4D, 0x18, // zstd skippable frame
	0x04, 0x00, 0x00, 0x00, // payload size = 4 bytes
	0x65, 0xAA, 0xDC, // zarc magic
	0x01, // zarc file version
];

/// File format version
pub const ZARC_FILE_VERSION: u8 = 1;

/// Directory structure version
pub const ZARC_DIRECTORY_VERSION: u8 = 1;
