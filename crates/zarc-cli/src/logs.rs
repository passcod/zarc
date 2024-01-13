use std::{
	env::var,
	fs::{metadata, File},
	io::{Error, Result},
	sync::Mutex,
};

use tracing::info;

use crate::args::Args;

pub fn from_env() -> Result<bool> {
	if var("RUST_LOG").is_ok() {
		tracing_subscriber::fmt::try_init().map_err(Error::other)?;
		Ok(true)
	} else {
		Ok(false)
	}
}

pub fn from_args(args: &Args) -> Result<()> {
	let verbosity = args.verbose.unwrap_or(0);
	if verbosity > 0 {
		let log_file = if let Some(file) = &args.log_file {
			let is_dir = metadata(file).map_or(false, |info| info.is_dir());
			let path = if is_dir {
				let filename = format!(
					"zarc.{}.log",
					chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ")
				);
				file.join(filename)
			} else {
				file.to_owned()
			};

			// TODO: use tracing-appender instead
			Some(File::create(path)?)
		} else {
			None
		};

		let mut builder = tracing_subscriber::fmt().with_env_filter(match verbosity {
			0 => unreachable!("checked by if earlier"),
			1 => "warn",
			2 => "info",
			3 => "debug",
			_ => "trace",
		});

		if verbosity > 2 {
			use tracing_subscriber::fmt::format::FmtSpan;
			builder = builder.with_span_events(FmtSpan::NEW | FmtSpan::CLOSE);
		}

		match if let Some(writer) = log_file {
			builder.json().with_writer(Mutex::new(writer)).try_init()
		} else if verbosity > 3 {
			builder.pretty().try_init()
		} else {
			builder.try_init()
		} {
			Ok(_) => info!("logging initialised"),
			Err(e) => eprintln!("Failed to initialise logging, continuing with none\n{e}"),
		}
	}

	Ok(())
}
