use std::path::PathBuf;

use clap::{Parser, ValueHint};

/// TBC
#[derive(Debug, Clone, Parser)]
#[command(
	name = "zarc",
	bin_name = "zarc",
	author,
	version,
	after_help = "Want more detail? Try the long '--help' flag!",
	after_long_help = "Didn't expect this much output? Use the short '-h' flag to get short help."
)]
#[cfg_attr(debug_assertions, command(before_help = "⚠ DEBUG BUILD ⚠"))]
pub struct Args {
	/// Output file.
	#[arg(long,
		value_hint = ValueHint::AnyPath,
		value_name = "PATH",
	)]
	pub output: PathBuf,

	/// Paths to pack.
	#[arg(
		value_hint = ValueHint::AnyPath,
		value_name = "PATH",
	)]
	pub paths: Vec<PathBuf>,
}
