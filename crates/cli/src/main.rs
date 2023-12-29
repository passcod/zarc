#![warn(clippy::unwrap_used)]
#![deny(rust_2018_idioms)]

use std::io::Result;

use clap::Parser;
use tracing::{debug, warn};

use crate::args::Action;

mod args;
mod debug;
mod logs;
mod pack;

fn main() -> Result<()> {
	let logs_on = logs::from_env()?;

	debug!("parsing arguments");
	let args = args::Args::parse();

	if logs_on {
		warn!("ignoring logging options from args");
	} else {
		logs::from_args(&args)?;
	}

	debug!(?args, "got arguments");

	match args.action {
		Action::Pack(args) => pack::pack(args),
		Action::Debug(args) => debug::debug(args),
	}
}
