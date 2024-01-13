use std::mem::take;

use blake3::Hasher;
use deku::DekuContainerRead;
use ozarc::framing::{ZstandardBlockHeader, ZstandardFrameHeader};
use tracing::{debug, instrument, trace};

use crate::{directory::{ElementFrame, Element}, integrity::Digest, ondemand::OnDemand};

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
	/// After this returns, the Zarc file is ready for reading, using the files() iterator to sift
	/// through the available file records and extract them on demand.
	#[instrument(level = "debug", skip(self))]
	pub fn read_directory(&mut self) -> Result<()> {
		let mut hasher = Hasher::new();
		let mut editions = take(&mut self.editions);
		let mut frames = take(&mut self.frames);
		let mut files = take(&mut self.files);
		let mut files_by_name = take(&mut self.files_by_name);
		let mut files_by_digest = take(&mut self.files_by_digest);

		// start a new decompression session
		let frame = self.read_zstandard_frame(self.trailer.directory_offset as _)?;
		for data in frame {
			let data = data?;
			hasher.update(&data);

			let mut bytes = &data[..];
			loop {
				let ((rest, _), element) =
					ElementFrame::from_bytes((&bytes, 0)).map_err(SimpleError::from_deku)?;
				bytes = rest;

				trace!(?element, "read element");
				match element.element()? {
					Element::Edition(edition) => {
						editions.insert(edition.number, edition);
					}
					Element::Frame(frame) => {
						frames.insert(frame.digest.clone(), frame);
					}
					Element::File(file) => {
						let name = file.name.clone();
						let digest = file.digest.clone();
						files.push(file);
						let index = files.len() - 1;
						files_by_name.entry(name).or_insert_with(Vec::new).push(index);
						if let Some(digest) = digest {
							files_by_digest.entry(digest).or_insert_with(Vec::new).push(index);
						}
					}
				}

				if bytes.is_empty() {
					trace!("done with this chunk of data");
					break;
				}
			}
		}

		self.editions = editions;
		self.frames = frames;
		self.files = files;
		self.files_by_name = files_by_name;
		self.files_by_digest = files_by_digest;

		trace!("finished reading directory, verify digest");
		if self.trailer.digest != Digest(hasher.finalize().as_bytes().to_vec()) {
			return Err(ErrorKind::DirectoryIntegrity("digest").into());
		}

		Ok(())
	}
}
