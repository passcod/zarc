use std::{
	fs::{DirBuilder, File, create_dir_all},
	io::Write,
	path::PathBuf,
};

use clap::{Parser, ValueHint};
use miette::IntoDiagnostic;
use regex::Regex;
use tracing::{error, info, warn};
use zarc::decode::Decoder;

#[derive(Debug, Clone, Parser)]
pub struct UnpackArgs {
	/// Input file.
	#[arg(
		value_hint = ValueHint::AnyPath,
		value_name = "PATH",
	)]
	pub input: PathBuf,

	/// Filter files by name (with a regex).
	///
	/// Can be given multiple times, and files will be matched if they match any of the regexes.
	#[arg(long, value_name = "REGEX")]
	pub filter: Vec<Regex>,
}

pub(crate) fn unpack(args: UnpackArgs) -> miette::Result<()> {
	info!("initialise decoder");
	let mut zarc = Decoder::open(args.input)?;
	zarc.read_directory()?;
	let zarc = zarc;

	for entry in zarc.files() {
		let name = entry.name.to_path().display().to_string();
		if !args.filter.is_empty() {
			if !args.filter.iter().any(|filter| filter.is_match(&name)) {
				continue;
			}
		}

		if entry.is_dir() {
			info!(path=?entry.name.to_path(), "unpack dir");
			let mut dir = DirBuilder::new();
			dir.recursive(true);
			#[cfg(unix)]
			if let Some(mode) = entry.mode {
				use std::os::unix::fs::DirBuilderExt;
				dir.mode(mode);
			}
			dir.create(entry.name.to_path()).into_diagnostic()?;
		} else if entry.is_normal() {
			if let Some(digest) = &entry.digest {
				extract_file(entry, digest, &zarc)?;
			}
		}
	}

	Ok(())
}

fn extract_file(
	entry: &zarc::directory::File,
	digest: &zarc::integrity::Digest,
	zarc: &Decoder<PathBuf>,
) -> miette::Result<()> {
	info!(path=?entry.name.to_path(), digest=%bs64::encode(digest.as_slice()), "unpack file");
	let path = entry.name.to_path();

	if let Some(dir) = path.parent() {
		// create parent dir just in case its entry wasn't in the zarc
		create_dir_all(dir).into_diagnostic()?;
	}

	let mut file = File::create(path).into_diagnostic()?;
	let Some(mut frame) = zarc.read_content_frame(&digest).into_diagnostic()? else {
		warn!("frame not found");
		return Ok(());
	};

	for bytes in &mut frame {
		file.write_all(&bytes.into_diagnostic()?).unwrap();
	}
	if !frame.verify().unwrap_or(false) {
		error!(path=?entry.name, "frame verification failed!");
	}

	Ok(())
}
