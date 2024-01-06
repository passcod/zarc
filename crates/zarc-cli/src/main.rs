#![warn(clippy::unwrap_used)]
#![deny(rust_2018_idioms)]

use clap::Parser;
use miette::IntoDiagnostic;
use tracing::{debug, warn};

use crate::args::Action;

mod args;
mod debug;
mod logs;
mod pack;
mod unpack;

fn main() -> miette::Result<()> {
	let logs_on = logs::from_env().into_diagnostic()?;

	debug!("parsing arguments");
	let args = args::Args::parse();

	if logs_on {
		warn!("ignoring logging options from args");
	} else {
		logs::from_args(&args).into_diagnostic()?;
	}

	debug!(?args, "got arguments");

	match args.action {
		Action::Pack(args) => pack::pack(args).into_diagnostic(),
		Action::Unpack(args) => unpack::unpack(args),
		Action::Debug(args) => debug::debug(args).into_diagnostic(),
	}
}
