use std::{
	env::var,
	fs::File,
	path::{Component, PathBuf},
};

use clap::{Parser, ValueHint};
use rand::rngs::OsRng;
use tracing::{debug, info, warn};
use zarc::format::{CborString, FilemapEntry, Pathname};

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

	/// Files to pack.
	#[arg(
		value_hint = ValueHint::AnyPath,
		value_name = "PATH",
	)]
	pub files: Vec<PathBuf>,
}

const DEFENSIVE_HEADER: &'static str = "STOP! THIS IS A ZARC ARCHIVE THAT HAS BEEN UNCOMPRESSED WITH RAW ZSTD\r\n\r\nSee https://github.com/passcod/zarc to unpack correctly.\r\n\r\n";

fn main() {
	if var("RUST_LOG").is_ok() {
		match tracing_subscriber::fmt::try_init() {
			Ok(_) => {
				warn!(RUST_LOG=%var("RUST_LOG").unwrap(), "logging configured from RUST_LOG");
			}
			Err(e) => eprintln!("Failed to initialise logging with RUST_LOG\n{e}"),
		}
	}

	debug!("parsing arguments");
	let args = Args::parse();
	debug!(?args, "got arguments");

	info!(path=?args.output, "create output file");
	let mut file = File::create(args.output).unwrap();

	info!("initialise encoder");
	let mut csprng = OsRng;
	let mut zarc = zarc::encode::Encoder::new(&mut file, &mut csprng, &DEFENSIVE_HEADER).unwrap();

	debug!("enable zstd checksums");
	zarc.set_zstd_parameter(zarc::encode::ZstdParameter::ChecksumFlag(true))
		.unwrap();

	for filename in &args.files {
		info!("read {filename:?}");
		let file = std::fs::read(&filename).unwrap();
		let hash = zarc.add_data_frame(&file).unwrap();
		zarc.add_file_entry(FilemapEntry {
			frame_hash: Some(hash),
			name: Pathname(
				filename
					.components()
					.filter_map(|c| {
						if let Component::Normal(comp) = c {
							// TODO: better, with binary and to_str()
							Some(CborString::String(comp.to_string_lossy().into()))
						} else {
							None
						}
					})
					.collect(),
			),
			user: None,
			group: None,
			mode: None,
			readonly: Some(false),
			special: None,
			timestamps: None,
			attributes: Default::default(),
			extended_attributes: Default::default(),
			user_metadata: Default::default(),
		})
		.unwrap();
	}

	info!("finalising zarc");
	zarc.finalise().unwrap();
}
