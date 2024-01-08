use std::{fs::File, io::Write, path::PathBuf};

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
	info!(path=?args.input, "open input file");
	let mut file = File::open(args.input).into_diagnostic()?;

	info!("initialise decoder");
	let mut zarc = Decoder::new(&mut file)?;

	info!("prepare and check the file");
	zarc.prepare()?;

	// TODO: right now streaming the filemap requires a mutable reference to the decoder, but
	// unpacking frames also requires a mutable reference to the decoder. This is a problem;
	// but more fundamentally we can't stream from two places in the file at once. It would be
	// nice to, though. Perhaps a trait that can be implemented for File to open arbitrary ones.
	let filemap = zarc.filemap()?.into_iter().filter(|entry| {
		let name = entry.name.to_path().display().to_string();
		if !args.filter.is_empty() {
			if !args.filter.iter().any(|filter| filter.is_match(&name)) {
				return false;
			}
		}

		true
	});

	for entry in filemap {
		if let Some(digest) = entry.frame_hash {
			info!(path=?entry.name.to_path(), digest=%bs64::encode(digest.as_slice()), "unpack file");
			let mut file = File::create(entry.name.to_path()).into_diagnostic()?;
			let Some(mut frame) = zarc.decompress_frame(&digest)? else {
				warn!("frame not found");
				continue;
			};

			for bytes in &mut frame {
				file.write_all(&bytes?).into_diagnostic()?;
			}
			if !frame.verify().unwrap_or(false) {
				error!(path=?entry.name, "frame verification failed!");
			}
		}
	}

	Ok(())
}
