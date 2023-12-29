#![warn(clippy::unwrap_used)]
#![deny(rust_2018_idioms)]

use std::env::var;

use clap::Parser;
use tracing::{debug, warn};

mod args;
mod pack;

fn main() -> std::io::Result<()> {
	if var("RUST_LOG").is_ok() {
		match tracing_subscriber::fmt::try_init() {
			Ok(_) => {
				warn!(RUST_LOG=%var("RUST_LOG").unwrap(), "logging configured from RUST_LOG");
			}
			Err(e) => eprintln!("Failed to initialise logging with RUST_LOG\n{e}"),
		}
	}

	debug!("parsing arguments");
	let args = args::Args::parse();
	debug!(?args, "got arguments");
	pack::pack(args)
}
