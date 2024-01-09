use std::path::PathBuf;

use clap::{Parser, ValueHint};
use regex::Regex;
use tracing::info;
use zarc::{decode::Decoder, format::SpecialFileKind};

#[derive(Debug, Clone, Parser)]
pub struct ListFilesArgs {
	/// Input file.
	#[arg(
		value_hint = ValueHint::AnyPath,
		value_name = "PATH",
	)]
	pub input: PathBuf,

	/// List only files.
	#[arg(long)]
	pub only_files: bool,

	/// Indicate filetypes with suffixes.
	///
	/// Directories are marked with a '/' suffix, symlinks with `@`, hardlinks with `#`.
	#[arg(long)]
	pub decorate: bool,

	/// Filter files by name (with a regex).
	///
	/// Can be given multiple times, and files will be matched if they match any of the regexes.
	#[arg(long, value_name = "REGEX")]
	pub filter: Vec<Regex>,
}

pub(crate) fn list_files(args: ListFilesArgs) -> miette::Result<()> {
	info!("initialise decoder");
	let mut zarc = Decoder::new(args.input)?;

	info!("prepare and check the file");
	zarc.prepare()?;

	// drop the mutability once we don't need it
	let zarc = zarc;

	info!("list files");
	zarc.with_filemap(|entry| {
		if args.only_files && entry.special.is_some() {
			return;
		}

		let name = entry.name.to_path().display().to_string();
		if !args.filter.is_empty() {
			if !args.filter.iter().any(|filter| filter.is_match(&name)) {
				return;
			}
		}

		print!("{name}");
		match entry.special.as_ref().and_then(|sp| sp.kind) {
			Some(SpecialFileKind::Directory) => print!("/"),
			Some(kind) if kind.is_symlink() => print!("@"),
			Some(kind) if kind.is_hardlink() => print!("#"),
			_ => (),
		}

		println!("");
	});

	Ok(())
}
