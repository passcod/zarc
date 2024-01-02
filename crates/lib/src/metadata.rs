//! Helpers to read/write metadata for the Filemap.

use std::{
	collections::HashMap,
	fs::{self, Metadata},
	io::Result,
	path::Path,
	time::SystemTime,
};

use tracing::{error, instrument, trace};

use crate::format::{
	AttributeValue, CborString, Digest, FilemapEntry, Pathname, PosixOwner, SpecialFile,
	SpecialFileKind, Timestamps,
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
	path: &Path,
	follow_links: bool,
	frame_hash: Option<Digest>,
) -> Result<FilemapEntry> {
	let name = Pathname::from_normal_components(path);

	trace!("reading immediate metadata");
	let symeta = fs::symlink_metadata(path)?;
	let is_symlink = symeta.is_symlink();

	let link_target = if is_symlink {
		trace!("reading link target");
		Some(fs::read_link(path)?)
	} else {
		None
	};

	let meta = if follow_links && is_symlink {
		trace!("reading metadata");
		fs::metadata(path)?
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
		attributes: file_attributes(path, &meta)?,
		extended_attributes: file_extended_attributes(path)?,
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
/// Returns `Ok(None)` on unsupported systems.
///
/// ## Linux
///
/// Translates present [`lsattr`/`chattr`][chattr] flags to boolean true at string keys,
/// prefixed by `linux.`. Some flags are not translated; this list is exhaustive:
///
/// - `append-only` for `APPEND` or [the `a` flag](https://man.archlinux.org/man/chattr.1#a)
/// - `casefold` for `CASEFOLD` or [the `F` flag](https://man.archlinux.org/man/chattr.1#F)
/// - `compressed` for `COMPR` or [the `c` flag](https://man.archlinux.org/man/chattr.1#c)
/// - `delete-undo` for `UNRM` or [the `u` flag](https://man.archlinux.org/man/chattr.1#u)
/// - `delete-zero` for `SECRM` or [the `s` flag](https://man.archlinux.org/man/chattr.1#s)
/// - `dir-sync` for `DIRSYNC` or [the `D` flag](https://man.archlinux.org/man/chattr.1#D)
/// - `encrypted` for `ENCRYPT` or [the `E` flag](https://man.archlinux.org/man/chattr.1#E)
/// - `file-sync` for `SYNC` or [the `S` flag](https://man.archlinux.org/man/chattr.1#S)
/// - `immutable` for `IMMUTABLE` or [the `i` flag](https://man.archlinux.org/man/chattr.1#i)
/// - `no-atime` for `NOATIME` or [the `A` flag](https://man.archlinux.org/man/chattr.1#A)
/// - `no-backup` for `NODUMP` or [the `d` flag](https://man.archlinux.org/man/chattr.1#d)
/// - `no-cow` for `NOCOW` or [the `C` flag](https://man.archlinux.org/man/chattr.1#C)
/// - `not-compressed` for `NOCOMPR` or [the `m` flag](https://man.archlinux.org/man/chattr.1#m)
///
/// ## Windows
///
/// Translates present [`FILE_ATTRIBUTE_*`][win32-file-attrs] flags to boolean true at string keys,
/// prefixed by `win32.`. Some flags are not translated; this list is exhaustive:
///
/// - `archive` for `FILE_ATTRIBUTE_ARCHIVE`
/// - `compressed` for `FILE_ATTRIBUTE_COMPRESSED`
/// - `encrypted` for `FILE_ATTRIBUTE_ENCRYPTED`
/// - `hidden` for `FILE_ATTRIBUTE_HIDDEN`
/// - `not-content-indexed` for `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` (opts the file out of content
///   indexing from Windows' crawlers, e.g. for the search functionality in Explorer and Start)
/// - `sparse` for `FILE_ATTRIBUTE_SPARSE`
/// - `system` for `FILE_ATTRIBUTE_SYSTEM`
/// - `temporary` for `FILE_ATTRIBUTE_TEMPORARY`
///
/// [chattr]: https://man.archlinux.org/man/chattr.1
/// [win32-file-attrs]: https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
#[instrument(level = "trace")]
pub fn file_attributes(
	path: &Path,
	meta: &Metadata,
) -> Result<Option<HashMap<String, AttributeValue>>> {
	#[cfg(target_os = "linux")]
	{
		use e2p_fileflags::{FileFlags, Flags};
		let flags = path.flags()?;
		Ok(Some(
			[
				("append-only", flags.contains(Flags::APPEND)),
				("casefold", flags.contains(Flags::CASEFOLD)),
				("compressed", flags.contains(Flags::COMPR)),
				("delete-undo", flags.contains(Flags::UNRM)),
				("delete-zero", flags.contains(Flags::SECRM)),
				("dir-sync", flags.contains(Flags::DIRSYNC)),
				("encrypted", flags.contains(Flags::ENCRYPT)),
				("file-sync", flags.contains(Flags::SYNC)),
				("immutable", flags.contains(Flags::IMMUTABLE)),
				("no-atime", flags.contains(Flags::NOATIME)),
				("no-backup", flags.contains(Flags::NODUMP)),
				("no-cow", flags.contains(Flags::NOCOW)),
				("not-compressed", flags.contains(Flags::NOCOMPR)),
			]
			.into_iter()
			.filter(|(_, v)| *v)
			.map(|(k, _)| (format!("linux.{k}"), AttributeValue::Boolean(true)))
			.collect(),
		))
	}

	#[cfg(windows)]
	{
		use std::os::windows::fs::MetadataExt;
		use windows::Win32::Storage::FileSystem;

		let attrs = meta.file_attributes();

		Ok(Some(
			[
				("archive", attrs & FileSystem::FILE_ATTRIBUTE_ARCHIVE != 0),
				(
					"compressed",
					attrs & FileSystem::FILE_ATTRIBUTE_COMPRESSED != 0,
				),
				(
					"encrypted",
					attrs & FileSystem::FILE_ATTRIBUTE_ENCRYPTED != 0,
				),
				("hidden", attrs & FileSystem::FILE_ATTRIBUTE_HIDDEN != 0),
				(
					"not-content-indexed",
					attrs & FileSystem::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED != 0,
				),
				("system", attrs & FileSystem::FILE_ATTRIBUTE_SYSTEM != 0),
				("sparse", attrs & FileSystem::FILE_ATTRIBUTE_SPARSE != 0),
				(
					"temporary",
					attrs & FileSystem::FILE_ATTRIBUTE_TEMPORARY != 0,
				),
			]
			.into_iter()
			.filter(|(_, v)| *v)
			.map(|(k, _)| (format!("win32.{k}"), AttributeValue::Boolean(true)))
			.collect(),
		))
	}

	#[cfg(not(any(target_os = "linux", windows)))]
	{
		Ok(None)
	}
}

/// Get attributes for a file, given its path.
///
/// Returns `Ok(None)` on unsupported systems.
///
/// Supported:
/// - Android
/// - FreeBSD
/// - Linux
/// - MacOS
/// - NetBSD
///
#[instrument(level = "trace")]
pub fn file_extended_attributes(path: &Path) -> Result<Option<HashMap<String, AttributeValue>>> {
	if xattr::SUPPORTED_PLATFORM {
		let list = xattr::list(path)?;
		let size_hint = list.size_hint();
		let mut map = HashMap::with_capacity(size_hint.1.unwrap_or(size_hint.0));
		for osname in list {
			match osname.to_str() {
				None => error!(?osname, ?path, "not storing non-Unicode xattr"),
				Some(name) => {
					if let Some(value) = xattr::get(path, &osname)? {
						map.insert(name.to_string(), CborString::from_maybe_utf8(value).into());
					}
				}
			}
		}

		Ok(Some(map))
	} else {
		Ok(None)
	}
}
