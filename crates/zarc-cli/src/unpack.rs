use std::{fs::File, path::PathBuf};

use clap::{Parser, ValueHint};
use miette::IntoDiagnostic;
use tracing::info;
use zarc::decode::Decoder;

#[derive(Debug, Clone, Parser)]
pub struct UnpackArgs {
	/// Input file.
	#[arg(
		value_hint = ValueHint::AnyPath,
		value_name = "PATH",
	)]
	pub input: PathBuf,
}

pub(crate) fn unpack(args: UnpackArgs) -> miette::Result<()> {
	info!(path=?args.input, "open input file");
	let mut file = File::open(args.input).into_diagnostic()?;

	info!("initialise decoder");
	let mut zarc = Decoder::new(&mut file)?;

	zarc.read_header()?;
	zarc.read_unintended_magic()?;
	zarc.read_eof_trailer()?;
	zarc.read_directory_header()?;
	dbg!(zarc.directory_size());

	Ok(())
}