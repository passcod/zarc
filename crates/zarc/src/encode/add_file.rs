use std::{
	ffi::OsStr,
	io::{Error, Result, Write},
	path::Path,
};

use tracing::{instrument, trace};

use crate::{
	directory::{
		AttributeValue, CborString, File, Pathname, PosixOwner, SpecialFile, SpecialFileKind,
		Timestamp, Timestamps,
	},
	integrity::Digest,
	metadata::encode::build_filemap,
};

use super::Encoder;

// TODO: more ergonomic APIs, e.g. from a File

impl<'writer, W: Write> Encoder<'writer, W> {
	/// Add a file entry.
	#[instrument(level = "trace", skip(self))]
	pub fn add_file_entry(&mut self, entry: impl Into<File> + std::fmt::Debug) -> Result<()> {
		let entry = entry.into();

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

	/// Get a builder for a file entry.
	///
	/// Don't forget to set the digest to the content frame!
	#[instrument(level = "trace", skip(self))]
	pub fn build_file(&self, name: impl Into<Pathname> + std::fmt::Debug) -> FileBuilder {
		FileBuilder(File {
			edition: self.edition,
			name: name.into(),
			digest: Default::default(),
			mode: Default::default(),
			user: Default::default(),
			group: Default::default(),
			timestamps: Default::default(),
			special: Default::default(),
			user_metadata: Default::default(),
			attributes: Default::default(),
			extended_attributes: Default::default(),
		})
	}

	/// Start building a file from an existing file.
	///
	/// This will read the metadata of a file on the filesystem and return a [`FileBuilder`] to add
	/// or change metadata before adding it to the encoder.
	///
	/// Don't forget to set the digest to the content frame!
	#[instrument(level = "trace", skip(self))]
	pub fn build_file_with_metadata(
		&self,
		path: impl AsRef<Path> + std::fmt::Debug,
		follow_symlinks: bool,
	) -> std::io::Result<FileBuilder> {
		let path = path.as_ref();
		build_filemap(self.edition, path, follow_symlinks).map(FileBuilder)
	}
}

/// Builder for a file entry.
///
/// Create with [`Encoder::build_file()`], then insert into the Encoder with
/// [`Encoder::add_file_entry()`].
#[derive(Clone, Debug)]
pub struct FileBuilder(pub File);

// TODO: symlinks and hardlinks

impl FileBuilder {
	/// Set the digest of a content frame.
	///
	/// This doesn't check that the digest is valid or that the content frame exists, but that will
	/// be checked later when the file is added to the encoder.
	pub fn digest(&mut self, digest: impl Into<Digest>) -> &mut Self {
		self.0.digest = Some(digest.into());
		self
	}

	/// Make this a directory.
	///
	/// This will clear the digest if it was set.
	pub fn directory(&mut self) -> &mut Self {
		self.0.digest = None;
		self.0.special = Some(SpecialFile {
			kind: Some(SpecialFileKind::Directory),
			..Default::default()
		});
		self
	}

	/// Set the POSIX mode of the file.
	///
	/// This does the same thing regardless of platform, so it can be used to set the mode of files
	/// even when running on Windows if the desired value is known.
	pub fn mode(&mut self, mode: u32) -> &mut Self {
		self.0.mode = Some(mode);
		self
	}

	/// Set the user that owns the file by name.
	pub fn user_name(&mut self, username: impl AsRef<OsStr>) -> &mut Self {
		let name = CborString::from(username.as_ref());
		if let Some(user) = self.0.user.as_mut() {
			user.name = Some(name);
		} else {
			self.0.user = Some(PosixOwner {
				name: Some(name),
				..Default::default()
			})
		}
		self
	}

	/// Set the user that owns the file by ID.
	pub fn user_id(&mut self, id: u64) -> &mut Self {
		if let Some(user) = self.0.user.as_mut() {
			user.id = Some(id);
		} else {
			self.0.user = Some(PosixOwner {
				id: Some(id),
				..Default::default()
			})
		}
		self
	}

	/// Set the group that owns the file by name.
	pub fn group_name(&mut self, groupname: impl AsRef<OsStr>) -> &mut Self {
		let name = CborString::from(groupname.as_ref());
		if let Some(group) = self.0.group.as_mut() {
			group.name = Some(name);
		} else {
			self.0.group = Some(PosixOwner {
				name: Some(name),
				..Default::default()
			})
		}
		self
	}

	/// Set the group that owns the file by ID.
	pub fn group_id(&mut self, id: u64) -> &mut Self {
		if let Some(group) = self.0.group.as_mut() {
			group.id = Some(id);
		} else {
			self.0.group = Some(PosixOwner {
				id: Some(id),
				..Default::default()
			})
		}
		self
	}

	/// Set the timestamps of the file.
	pub fn timestamps(&mut self, timestamps: impl Into<Timestamps>) -> &mut Self {
		self.0.timestamps = Some(timestamps.into());
		self
	}

	/// Set the accessed timestamp of the file.
	pub fn time_accessed(&mut self, timestamps: impl Into<Timestamp>) -> &mut Self {
		if let Some(ts) = self.0.timestamps.as_mut() {
			ts.accessed = Some(timestamps.into());
		} else {
			self.0.timestamps = Some(Timestamps {
				accessed: Some(timestamps.into()),
				..Default::default()
			})
		}
		self
	}

	/// Set the modified timestamp of the file.
	pub fn time_modified(&mut self, timestamps: impl Into<Timestamp>) -> &mut Self {
		if let Some(ts) = self.0.timestamps.as_mut() {
			ts.modified = Some(timestamps.into());
		} else {
			self.0.timestamps = Some(Timestamps {
				modified: Some(timestamps.into()),
				..Default::default()
			})
		}
		self
	}

	/// Set the created timestamp of the file.
	pub fn time_created(&mut self, timestamps: impl Into<Timestamp>) -> &mut Self {
		if let Some(ts) = self.0.timestamps.as_mut() {
			ts.created = Some(timestamps.into());
		} else {
			self.0.timestamps = Some(Timestamps {
				created: Some(timestamps.into()),
				..Default::default()
			})
		}
		self
	}

	/// Add user metadata.
	pub fn user_metadata(
		&mut self,
		key: impl Into<String>,
		value: impl Into<AttributeValue>,
	) -> &mut Self {
		self.0
			.user_metadata
			.get_or_insert_with(Default::default)
			.insert(key.into(), value.into());
		self
	}

	/// Add an attribute.
	///
	/// See [`file_attributes`](crate::metadata::encode::file_attributes) for a list of attributes.
	pub fn attribute(
		&mut self,
		key: impl Into<String>,
		value: impl Into<AttributeValue>,
	) -> &mut Self {
		self.0
			.attributes
			.get_or_insert_with(Default::default)
			.insert(key.into(), value.into());
		self
	}

	/// Add an extended attribute.
	pub fn extended_attribute(
		&mut self,
		key: impl Into<String>,
		value: impl Into<AttributeValue>,
	) -> &mut Self {
		self.0
			.extended_attributes
			.get_or_insert_with(Default::default)
			.insert(key.into(), value.into());
		self
	}
}

impl From<FileBuilder> for File {
	fn from(builder: FileBuilder) -> Self {
		builder.0
	}
}
