use std::{
	io::{Error, Result, Write},
	mem::take,
};

use blake3::Hasher;
use deku::DekuContainerWrite;
use ed25519_dalek::Signer;
use ozarc::framing::SKIPPABLE_FRAME_OVERHEAD;
use tracing::{debug, instrument, trace};

use crate::{
	constants::{ZARC_DIRECTORY_VERSION, ZARC_FILE_VERSION},
	directory::{Edition, Element, ElementFrame, Timestamp},
	integrity::{Digest, DigestType, PublicKey, Signature, SignatureType},
	trailer::Trailer,
};

use super::Encoder;

impl<'writer, W: Write> Encoder<'writer, W> {
	#[instrument(level = "trace", skip(buf, hasher))]
	fn write_element(buf: &mut Vec<u8>, hasher: &mut Hasher, element: &Element) -> Result<()> {
		let frame = ElementFrame::create(element).map_err(Error::other)?;
		let bytes = frame.to_bytes().map_err(Error::other)?;
		buf.write_all(&bytes)?;
		hasher.update(&bytes);
		trace!(
			kind = ?element.kind(),
			length = %bytes.len(),
			bytes = %format!("{bytes:02x?}"),
			"wrote element"
		);
		Ok(())
	}

	/// Write the directory and trailer.
	///
	/// Flushes the writer and drops all state.
	///
	/// Discards the private key and returns the public key.
	#[instrument(level = "debug", skip(self))]
	pub fn finalise(mut self) -> Result<PublicKey> {
		let mut directory = Vec::new();
		let mut hasher = Hasher::new();

		let public_key = PublicKey(self.key.verifying_key().as_bytes().to_vec());
		let digest_type = DigestType::Blake3;
		let signature_type = SignatureType::Ed25519;

		Self::write_element(
			&mut directory,
			&mut hasher,
			&Element::Edition(Box::new(Edition {
				number: self.edition,
				public_key: public_key.clone(),
				written_at: Timestamp::now(),
				digest_type,
				signature_type,
				user_metadata: Default::default(),
			})),
		)?;

		for (name, indices) in take(&mut self.files_by_name) {
			debug!(?name, "write file and frame elements");

			for index in indices {
				let Some(file) = self.files.get_mut(index).and_then(Option::take) else {
					// this shouldn't happen, but it's cheap to just skip instead of unwrapping
					continue;
				};

				// we always want to insert a frame element before the linked file element
				if let Some(digest) = &file.digest {
					// if we've already written it, this will be None
					if let Some(frame) = self.frames.remove(digest) {
						Self::write_element(
							&mut directory,
							&mut hasher,
							&Element::Frame(Box::new(frame)),
						)?;
					}
				}

				Self::write_element(&mut directory, &mut hasher, &Element::File(Box::new(file)))?;
			}
		}

		// we should have written every frame, but just in case
		// (or if user inserted frames not linked to files)
		for frame in take(&mut self.frames).into_values() {
			Self::write_element(
				&mut directory,
				&mut hasher,
				&Element::Frame(Box::new(frame)),
			)?;
		}

		let digest = hasher.finalize();
		trace!(?digest, "hashed directory");
		let digest = digest.as_bytes();
		let signature = self.key.try_sign(digest).map_err(Error::other)?;
		trace!(?signature, "signed directory hash");

		let bytes = self.write_compressed_frame(&directory)?;
		trace!(%bytes, "wrote directory");

		let mut trailer = Trailer {
			file_version: ZARC_FILE_VERSION,
			directory_version: ZARC_DIRECTORY_VERSION,
			digest_type,
			signature_type,
			directory_offset: 0,
			directory_uncompressed_size: directory.len() as _,
			public_key: public_key.clone(),
			digest: Digest(digest.to_vec()),
			signature: Signature(signature.to_vec()),
		};
		trailer.directory_offset = -((bytes + SKIPPABLE_FRAME_OVERHEAD + trailer.len()) as i64);
		trace!(?trailer, "built trailer");

		let trailer_bytes = trailer.to_bytes();
		trace!(
			bytes = %format!("{trailer_bytes:02x?}"),
			length = %trailer_bytes.len(),
			"serialised trailer"
		);

		let bytes = self.write_skippable_frame(0xF, trailer_bytes)?;
		trace!(%bytes, "wrote trailer");

		self.writer.flush()?;
		trace!("flushed writer");

		Ok(public_key)
	}
}
