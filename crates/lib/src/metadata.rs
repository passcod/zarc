//! Helpers to read/write metadata for the Filemap.

use std::{
	collections::HashMap,
	fs::{self, Metadata},
	path::Path,
	time::SystemTime,
};

use tracing::{instrument, trace};

use crate::format::{
	AttributeValue, Digest, FilemapEntry, Pathname, PosixOwner, SpecialFile, SpecialFileKind,
	Timestamps,
};

/// Build a [`FilemapEntry`] from a filename.
///
/// Give `frame_hash` to reference framed content.
///
/// This will perform syscalls; these are logged at trace level. To get more control you can use
/// the individual functions [in this module][self].
///
/// [`readdir(3)`]: https://man.archlinux.org/man/readdir.3
#[instrument(level = "trace")]
pub fn build_filemap(
	filename: &Path,
	follow_links: bool,
	frame_hash: Option<Digest>,
) -> std::io::Result<FilemapEntry> {
	let name = Pathname::from_normal_components(filename);

	trace!("reading immediate metadata");
	let symeta = fs::symlink_metadata(filename)?;
	let is_symlink = symeta.is_symlink();

	let link_target = if is_symlink {
		trace!("reading link target");
		Some(fs::read_link(filename)?)
	} else {
		None
	};

	let meta = if follow_links && is_symlink {
		trace!("reading metadata");
		fs::metadata(filename)?
	} else {
		symeta
	};
	trace!(?name, ?meta, "retrieved file metadata");

	let file_type = meta.file_type();
	let perms = meta.permissions();

	Ok(FilemapEntry {
		frame_hash,
		name,
		user: owner_user(&meta),
		group: owner_group(&meta),
		mode: posix_mode(&meta),
		readonly: Some(perms.readonly()),
		special: if file_type.is_dir() {
			Some(SpecialFile {
				kind: Some(SpecialFileKind::Directory),
				link_target: None,
			})
		} else if is_symlink {
			Some(SpecialFile {
				kind: Some(SpecialFileKind::Link),
				link_target: link_target.map(|path| path.as_path().into()),
			})
		} else {
			None
		},
		timestamps: Some(timestamps(&meta)),
		attributes: file_attributes(&meta),
		extended_attributes: None,
		user_metadata: None,
	})
}

/// Get the timestamps of the file.
#[instrument(level = "trace")]
pub fn timestamps(meta: &Metadata) -> Timestamps {
	Timestamps {
		inserted: Some(SystemTime::now()),
		created: meta.created().ok(),
		modified: meta.modified().ok(),
		accessed: meta.accessed().ok(),
	}
}

/// Get the owning user of the file.
///
/// On non-unix, always returns `None`.
#[instrument(level = "trace")]
pub fn owner_user(meta: &Metadata) -> Option<PosixOwner> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		Some(PosixOwner {
			id: Some(meta.uid() as _),
			name: None,
		})
	}

	#[cfg(not(unix))]
	{
		None
	}
}

/// Get the owning group of the file.
///
/// On non-unix, always returns `None`.
#[instrument(level = "trace")]
pub fn owner_group(meta: &Metadata) -> Option<PosixOwner> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		Some(PosixOwner {
			id: Some(meta.gid() as _),
			name: None,
		})
	}

	#[cfg(not(unix))]
	{
		None
	}
}

/// Get the mode of the file.
///
/// On non-unix, always returns `None`.
#[instrument(level = "trace")]
pub fn posix_mode(meta: &Metadata) -> Option<u32> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		Some(meta.mode())
	}

	#[cfg(not(unix))]
	{
		None
	}
}

/// Get attributes for a file, given its path and [`Metadata`].
///
/// ## Windows
///
/// Translates relevant `FILE_ATTRIBUTE_*` flags to booleans at string keys, prefixed by `win32.`:
/// - `hidden` for `FILE_ATTRIBUTE_HIDDEN`
/// - `system` for `FILE_ATTRIBUTE_SYSTEM`
/// - `archive` for `FILE_ATTRIBUTE_ARCHIVE`
/// - `temporary` for `FILE_ATTRIBUTE_TEMPORARY`
/// - `sparse` for `FILE_ATTRIBUTE_SPARSE`
/// - `compressed` for `FILE_ATTRIBUTE_COMPRESSED`
/// - `not-content-indexed` for `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` (opts the file out of content
///   indexing from Windows' crawlers, e.g. for the search functionality in Explorer and Start)
/// - `encrypted` for `FILE_ATTRIBUTE_ENCRYPTED`
#[instrument(level = "trace")]
pub fn file_attributes(meta: &Metadata) -> Option<HashMap<String, AttributeValue>> {
	#[cfg(windows)]
	{
		use std::os::windows::fs::MetadataExt;
		use windows::Win32::Storage::FileSystem;

		let attrs = meta.file_attributes();

		Some(
			[
				("hidden", attrs & FileSystem::FILE_ATTRIBUTE_HIDDEN != 0),
				("system", attrs & FileSystem::FILE_ATTRIBUTE_SYSTEM != 0),
				("archive", attrs & FileSystem::FILE_ATTRIBUTE_ARCHIVE != 0),
				(
					"temporary",
					attrs & FileSystem::FILE_ATTRIBUTE_TEMPORARY != 0,
				),
				("sparse", attrs & FileSystem::FILE_ATTRIBUTE_SPARSE != 0),
				(
					"compressed",
					attrs & FileSystem::FILE_ATTRIBUTE_COMPRESSED != 0,
				),
				(
					"not-content-indexed",
					attrs & FileSystem::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED != 0,
				),
				(
					"encrypted",
					attrs & FileSystem::FILE_ATTRIBUTE_ENCRYPTED != 0,
				),
			]
			.into_iter()
			.map(|(k, v)| (format!("win32.{k}"), AttributeValue::Boolean(v)))
			.collect(),
		)
	}

	#[cfg(not(windows))]
	{
		None
	}
}
