//! Helpers to write file metadata when decoding [`File`](directory::File)s.

use std::{
	fs::{File as FsFile, FileTimes, Permissions},
	os::fd::AsRawFd,
};

use tracing::{instrument, trace};

use crate::directory::{File, Timestamps};

/// Set the timestamps of the file.
#[instrument(level = "trace")]
pub fn set_timestamps(file: &FsFile, ts: &Timestamps) -> std::io::Result<()> {
	// On Windows, creation date is supported by std.
	// On Linux, birthtime can't be set.
	// On Apple/BSD, it should be able to:
	// https://github.com/ronomon/utimes/blob/master/binding.cc
	// but `nix` doesn't have setattrlist

	file.set_times(ts.into())
}

impl From<&Timestamps> for FileTimes {
	fn from(ts: &Timestamps) -> Self {
		let mut ft = Self::new();
		if let Some(accessed) = ts.accessed {
			ft = ft.set_accessed(accessed.into());
		}
		if let Some(modified) = ts.modified {
			ft = ft.set_modified(modified.into());
		}
		#[cfg(windows)]
		if let Some(created) = ts.created {
			use std::os::windows::fs::FileTimesExt;
			ft = ft.set_created(created.into());
		}

		ft
	}
}

/// Set the permissions of a file.
///
/// This uses `readonly` from attributes on Windows, `mode` if present on unix, and finally
/// `readonly` on unix if `mode` wasn't there.
#[instrument(level = "trace")]
pub fn set_permissions(permissions: &mut Permissions, meta: &File) -> std::io::Result<()> {
	let readonly = meta.attributes.as_ref().and_then(|attrs| {
		attrs
			.get("readonly")
			.or_else(|| attrs.get("win32.readonly"))
			.and_then(|v| v.as_bool())
	});

	#[cfg(windows)]
	{
		if let Some(readonly) = readonly {
			permissions.set_readonly(readonly)
		}
	}

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		if let Some(mode) = meta.mode {
			permissions.set_mode(mode);
		} else if let Some(readonly) = readonly {
			permissions.set_readonly(readonly);
		}
	}

	Ok(())
}

/// Set the ownership of a file.
///
/// This uses `owner` and `group` if present, otherwise it does nothing.
///
/// On non-Unix systems, this does nothing.
#[instrument(level = "trace")]
pub fn set_ownership(file: &FsFile, meta: &File) -> std::io::Result<()> {
	#[cfg(unix)]
	{
		let uid = meta
			.user
			.as_ref()
			.map(|user| user.to_real_uid())
			.transpose()?
			.flatten();

		let gid = meta
			.group
			.as_ref()
			.map(|group| group.to_real_gid())
			.transpose()?
			.flatten();

		let fd = file.as_raw_fd();
		trace!(%fd, ?uid, ?gid, "setting ownership");
		nix::unistd::fchown(fd, uid, gid)?;
	}

	Ok(())
}
