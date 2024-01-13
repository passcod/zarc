use std::io::{Error, Result, Write};

use tracing::{instrument, trace};

use crate::directory::File;

use super::Encoder;

// TODO: more ergonomic APIs, e.g. from a File
// TODO: builder API for user metadata?

impl<'writer, W: Write> Encoder<'writer, W> {
	/// Add a file entry.
	#[instrument(level = "trace", skip(self))]
	pub fn add_file_entry(&mut self, entry: File) -> Result<()> {
		if let Some(hash) = &entry.digest {
			if !self.frames.contains_key(hash) {
				return Err(Error::other(
					"cannot add file entry referencing unknown data frame",
				));
			}
		}

		let name = entry.name.clone();
		let digest = entry.digest.clone();

		self.files.push(Some(entry));
		let index = self.files.len() - 1;
		trace!(index, "added file entry");

		self.files_by_name
			.entry(name)
			.or_insert_with(Vec::new)
			.push(index);
		if let Some(digest) = digest {
			self.files_by_digest
				.entry(digest)
				.or_insert_with(Vec::new)
				.push(index);
		}

		Ok(())
	}
}
