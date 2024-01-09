use std::{fs::File, io::Write, path::PathBuf};

use clap::{Parser, ValueHint};
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
	let mut zarc = Decoder::new(args.input)?;

	info!("prepare and check the file");
	zarc.prepare()?;

	// drop the mutability once we don't need it
	let zarc = zarc;

	zarc.with_filemap(|entry| {
		let name = entry.name.to_path().display().to_string();
		if !args.filter.is_empty() {
			if !args.filter.iter().any(|filter| filter.is_match(&name)) {
				return;
			}
		}

		if let Some(digest) = &entry.frame_hash {
			info!(path=?entry.name.to_path(), digest=%bs64::encode(digest.as_slice()), "unpack file");
			let mut file = File::create(entry.name.to_path()).unwrap();
			let Some(mut frame) = zarc.read_content_frame(&digest).unwrap() else {
				warn!("frame not found");
				return;
			};

			for bytes in &mut frame {
				file.write_all(&bytes.unwrap()).unwrap();
			}
			if !frame.verify().unwrap_or(false) {
				error!(path=?entry.name, "frame verification failed!");
			}
		}
	});

	Ok(())
}
