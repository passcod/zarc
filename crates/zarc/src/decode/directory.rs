use std::rc::Rc;

use deku::DekuContainerRead;
use ozarc::framing::{ZstandardBlockHeader, ZstandardFrameHeader};
use tracing::{debug, instrument, trace};

use crate::{directory::LegacyDirectory, ondemand::OnDemand};

use super::{
	error::{ErrorKind, Result, SimpleError},
	Decoder,
};

impl<R: OnDemand> Decoder<R> {
	/// Read a Zstandard frame header.
	///
	/// This reads the frame header, checks that it's a Zstandard frame, and leaves the reader at
	/// the start of the first block. The frame header is returned.
	///
	/// This does not read the frame's payload: you need to do that yourself, reading blocks one at
	/// a time until the one marked `last`, and then reading the checksum
	/// [if present as per this header](ozarc::framing::ZstandardFrameDescriptor.checksum).
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(reader))]
	fn read_zstandard_frame_header(reader: &mut R::Reader) -> Result<ZstandardFrameHeader> {
		let (bits_read, header) =
			ZstandardFrameHeader::from_reader((reader, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?header, "read zstandard frame header");
		Ok(header)
	}

	/// Read a Zstandard frame block header.
	///
	/// This reads the block header, checks that it's a Zstandard block, and leaves the reader at
	/// the start of the block's payload. The block header is returned.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(reader))]
	fn read_zstandard_block_header(reader: &mut R::Reader) -> Result<ZstandardBlockHeader> {
		let (bits_read, header) =
			ZstandardBlockHeader::from_reader((reader, 0)).map_err(SimpleError::from_deku)?;
		debug!(%bits_read, ?header, "read zstandard block header");
		Ok(header)
	}

	/// Read the Zarc Directory.
	///
	/// After this returns, the Zarc file is ready for reading, using the Filemap iterator to sift
	/// through the available file records and extract them on demand.
	///
	/// This has two modes, which are switched internally.
	///
	/// ## Streaming
	///
	/// If the directory doesn't decompress in one step.
	///
	/// This starts uncompressing and reading the Zarc Directory, and stops after the first four
	/// CBOR fields. This is enough to get the directory version, public key and algorithms, which
	/// are needed to verify the directory integrity. After checking the signature, decompression is
	/// resumed, and the directory's digest is verified. While doing so, the frame lookup table is
	/// constructed and held in memory. This is a map from digest to frame offset and metadata, and
	/// is used to efficiently seek to a frame when it's needed.
	///
	/// ## In-memory
	///
	/// If the directory decompresses in one step.
	///
	/// In that case, the directory is entirely hashed and decoded from CBOR, then verified, and
	/// finally stored in the context. The frame lookup table is also constructed, but maps digests
	/// to indexes in the directory's frame list to avoid duplicating memory.
	#[cfg_attr(feature = "expose-internals", visibility::make(pub))]
	#[instrument(level = "debug", skip(self))]
	fn read_directory(&mut self) -> Result<()> {
		// start a new decompression session
		let mut frame = self.read_zstandard_frame(self.trailer.directory_offset as _)?;
		let data = frame
			.next()
			.ok_or(ErrorKind::DirectoryIntegrity("empty directory"))??;

		if frame.is_done() {
			drop(frame); // to release borrow
			debug!("processing entire directory in memory");
			let directory: LegacyDirectory = minicbor::decode(&data)?;

			trace!("verify directory signature");
			if !self.trailer.signature_type.verify_data(
				&self.trailer.public_key,
				&self.trailer.signature,
				self.trailer.digest.as_slice(),
			) {
				return Err(ErrorKind::DirectoryIntegrity("signature").into());
			}

			trace!("verify directory hash");
			if !self
				.trailer
				.digest_type
				.verify_data(&self.trailer.digest, &data)
			{
				return Err(ErrorKind::DirectoryIntegrity("digest").into());
			}

			trace!(frames=%directory.framelist.len(), "build frame lookup table");
			for frame in directory.framelist.iter() {
				if !self.trailer.signature_type.verify_data(
					&self.trailer.public_key,
					&frame.signature,
					frame.frame_hash.as_slice(),
				) {
					return Err(ErrorKind::DirectoryIntegrity("frame signature").into());
				}

				self.frame_lookup.insert(
					frame.frame_hash.clone(),
					FrameLookupEntry {
						offset: frame.offset,
						uncompressed: frame.uncompressed,
					},
				);
			}
			trace!(frames=%self.frame_lookup.len(), "verified and built frame lookup table");

			self.directory = Some(Rc::new(directory));
		} else {
			debug!("directory spans more than one block, streaming it");
			todo!("streaming directory decode")
		}

		Ok(())
	}
}

/// Frame lookup table entry.
#[derive(Clone, Copy, Debug)]
pub struct FrameLookupEntry {
	/// Frame offset.
	pub offset: u64,

	/// Uncompressed payload size in bytes.
	pub uncompressed: u64,
}
