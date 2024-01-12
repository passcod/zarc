use std::{
	io::{Cursor, Read, Seek, SeekFrom},
	num::NonZeroU8,
};

use deku::DekuContainerRead;
use ozarc::framing::SkippableFrame;
use tracing::{debug, instrument, trace, warn};

use crate::{
	header::Header,
	ondemand::OnDemand,
	trailer::{Epilogue, Trailer, EPILOGUE_LENGTH},
};

use super::{
	error::{ErrorKind, Result, SimpleError},
	Decoder,
};

impl<R: OnDemand> Decoder<R> {
	/// Read a Skippable frame, checking its nibble.
	///
	/// Reads and returns the entire frame's payload, and thus seeks to the end of the frame.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(reader))]
	fn read_skippable_frame(reader: &mut R::Reader, nibble: u8) -> Result<SkippableFrame> {
		let (bits_read, frame) =
			SkippableFrame::from_reader((reader, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?frame, nibble=%format!("0x{:X}", frame.nibble()), "read skippable frame");

		if frame.nibble() != nibble {
			return Err(ErrorKind::InvalidNibble {
				expected: nibble,
				actual: frame.nibble(),
			}
			.into());
		}

		Ok(frame)
	}

	/// Read a Zarc header.
	///
	/// Returns the file version in the header.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(ondemand))]
	fn read_header(ondemand: &R) -> Result<NonZeroU8> {
		let mut reader = ondemand.open()?;
		let frame = Self::read_skippable_frame(&mut reader, 0x0)?;

		let mut content = Cursor::new(frame.data);
		let (bits_read, header) =
			Header::from_reader((&mut content, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?header, "read zarc header");

		debug_assert_ne!(crate::constants::ZARC_FILE_VERSION, 0);
		debug_assert_ne!(header.file_version, 0);
		if header.file_version != crate::constants::ZARC_FILE_VERSION {
			return Err(ErrorKind::UnsupportedFileVersion(header.file_version).into());
		}

		Ok(unsafe {
			// SAFETY: the version is valid and zarc versions start at 1
			NonZeroU8::new_unchecked(header.file_version)
		})
	}

	/// Read the Zarc Trailer.
	///
	/// This opens a new reader, seeks to the end, and reads the [trailer][crate::trailer].
	///
	/// Returns the trailer and the length of the file.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(ondemand))]
	fn read_trailer(ondemand: &R) -> Result<(Trailer, u64)> {
		let mut reader = ondemand.open()?;

		// seek to the end to figure out how long this file is
		reader.seek(SeekFrom::End(0))?;
		let file_length = reader.stream_position()?;
		let ending_length = file_length.min(1024);

		// read up to 1KB from the end of the file
		reader.seek(SeekFrom::End(-(ending_length as i64)))?;
		let mut ending = Vec::with_capacity(ending_length as _);
		let bytes = reader.read_to_end(&mut ending)?;
		debug_assert_eq!(bytes, ending_length as _);

		// read the epilogue out of the end of the ending
		let ((rest, remaining_bits), mut epilogue) =
			Epilogue::from_bytes((&ending[(bytes - EPILOGUE_LENGTH)..], 0))
				.map_err(SimpleError::from_deku)?;
		trace!(?epilogue, "read zarc trailer epilogue (raw)");
		epilogue.make_offset_positive(file_length);
		debug!(?epilogue, "read zarc trailer epilogue");

		if remaining_bits > 0 {
			trace!(%remaining_bits, ?rest, "some data remaining");
			return Err(SimpleError::new(ErrorKind::Parse)
				.with_message(format!(
					"parse error: too much data ({remaining_bits} bits) {rest:02x?}"
				))
				.into());
		}

		// check we have enough data
		let trailer_length = epilogue.full_length();
		if bytes < trailer_length {
			todo!("read more bytes");
		}

		// complete reading the trailer
		let trailer = epilogue.complete(&ending).expect("not enough data");
		// UNWRAP: we know we have enough data, we just checked

		debug!(bytes=%trailer.len(), ?trailer, "read zarc trailer");
		Ok((trailer, file_length))
	}

	/// Open a Zarc for reading.
	///
	/// This checks the [header][crate::header], reads the [trailer][crate::trailer], and verifies
	/// the integrity of the trailer.
	///
	/// You'll then need to read the directory and extract some files!
	pub fn open(reader: R) -> Result<Self> {
		let file_version = Self::read_header(&reader)?;
		let (trailer, file_length) = Self::read_trailer(&reader)?;
		warn!(header=%file_version, trailer=%trailer.file_version, "file version mismatch in header and trailer");

		Ok(Self {
			reader,
			file_length,
			trailer,
			frame_lookup: Default::default(),
			directory: None,
		})
	}
}
