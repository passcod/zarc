use std::{fmt::Debug, path::PathBuf};

use clap::{ArgAction, Parser, Subcommand, ValueHint};

use crate::{debug::DebugArgs, pack::PackArgs};

/// Zarc: a novel archive format and tool.
///
/// Zarc is a file archive format that uses both Zstd compression and the Zstd file format. It is
/// designed as a replacement for tar and zip rather than zstd, gzip, bzip2, or xz. This is the
/// reference implementation.
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
	/// Set diagnostic log level
	///
	/// This enables diagnostic logging, which is useful for investigating bugs or gaining more
	/// insight into Zarc encoding and decoding. Use multiple times to increase verbosity.
	///
	/// Goes up to '-vvvv'. When submitting bug reports, default to a '-vvv' log level.
	///
	/// You may want to use with '--log-file' to avoid polluting your terminal.
	///
	/// If $RUST_LOG is set, this flag is ignored.
	#[arg(
		long,
		short,
		action = ArgAction::Count,
		num_args = 0,
	)]
	pub verbose: Option<u8>,

	/// Write diagnostic logs to a file
	///
	/// This writes diagnostic logs to a file, instead of the terminal, in JSON format. If a log
	/// level was not already specified, this will set it to '-vvv'.
	///
	/// If a path is not provided, the default is the working directory. Note that with
	/// '--ignore-nothing', the write events to the log will likely get picked up by Watchexec,
	/// causing a loop; prefer setting a path outside of the watched directory.
	///
	/// If the path provided is a directory, a file will be created in that directory. The file name
	/// will be the current date and time, in the format 'zarc.YYYY-MM-DDTHH-MM-SSZ.log'.
	#[arg(
		long,
		num_args = 0..=1,
		default_missing_value = ".",
		value_hint = ValueHint::AnyPath,
		value_name = "PATH",
	)]
	pub log_file: Option<PathBuf>,

	/// What to do
	#[command(subcommand)]
	pub action: Action,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Action {
	/// Pack files into a Zarc archive.
	Pack(PackArgs),

	/// Walk a Zarc and print detailed information about its structure.
	Debug(DebugArgs),
}
