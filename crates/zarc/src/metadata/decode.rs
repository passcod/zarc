//! Helpers to write file metadata when decoding [`File`](directory::File)s.

use std::fs::{File, FileTimes};

use tracing::instrument;

use crate::directory::Timestamps;

/// Set the timestamps of the file.
#[instrument(level = "trace")]
pub fn set_timestamps(file: &File, ts: &Timestamps) -> std::io::Result<()> {
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
