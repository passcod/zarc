use std::{
	collections::HashMap,
	fs::{File, Metadata},
	path::{Component, PathBuf},
	time::SystemTime,
};

use clap::{Parser, ValueHint};
use rand::rngs::OsRng;
use tracing::{debug, info};
use walkdir::WalkDir;
use zarc::{
	encode::{Encoder, ZstdParameter},
	format::{AttributeValue, CborString, Digest, FilemapEntry, Pathname, PosixOwner, Timestamps},
};

#[derive(Debug, Clone, Parser)]
pub struct PackArgs {
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

	/// Compression level.
	#[arg(long)]
	pub level: Option<i32>,
}

const DEFENSIVE_HEADER: &'static str = "STOP! THIS IS A ZARC ARCHIVE THAT HAS BEEN UNCOMPRESSED WITH RAW ZSTD\r\n\r\nSee https://github.com/passcod/zarc to unpack correctly.\r\n\r\n";

pub(crate) fn pack(args: PackArgs) -> std::io::Result<()> {
	info!(path=?args.output, "create output file");
	let mut file = File::create(args.output)?;

	info!("initialise encoder");
	let mut csprng = OsRng;
	let mut zarc = Encoder::new(&mut file, &mut csprng, &DEFENSIVE_HEADER)?;

	debug!("enable zstd checksums");
	zarc.set_zstd_parameter(ZstdParameter::ChecksumFlag(true))?;

	if let Some(level) = args.level {
		debug!(%level, "set compression level");
		zarc.set_zstd_parameter(ZstdParameter::CompressionLevel(level))?;
	}

	for path in &args.paths {
		info!("walk {path:?}");
		for entry in WalkDir::new(path).follow_links(true) {
			let file = match entry {
				Ok(file) => file,
				Err(err) => {
					eprintln!("read error: {err}");
					continue;
				}
			};

			let filename = file.path();
			debug!("read {filename:?}");

			let meta = file.metadata()?;
			if !meta.is_file() {
				continue;
			}

			let file = std::fs::read(&filename)?;
			let hash = zarc.add_data_frame(&file)?;
			let name = Pathname(
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
			);

			zarc.add_file_entry(filemap(name, &meta, hash)?)?;
		}
	}

	info!("finalising zarc");
	let public_key = zarc.finalise()?;
	println!("zarc public key: {}", bs64::encode(&public_key));
	Ok(())
}

pub(crate) fn filemap(
	name: Pathname,
	meta: &Metadata,
	hash: Digest,
) -> std::io::Result<FilemapEntry> {
	let perms = meta.permissions();
	Ok(FilemapEntry {
		frame_hash: Some(hash),
		name,
		user: owner_user(&meta),
		group: owner_group(&meta),
		mode: posix_mode(&meta),
		readonly: Some(perms.readonly()),
		special: None,
		timestamps: Some(Timestamps {
			inserted: Some(SystemTime::now()),
			created: meta.created().ok(),
			modified: meta.modified().ok(),
			accessed: meta.accessed().ok(),
		}),
		attributes: file_attributes(&meta),
		extended_attributes: None,
		user_metadata: None,
	})
}

#[cfg(unix)]
pub(crate) fn owner_user(meta: &Metadata) -> Option<PosixOwner> {
	use std::os::unix::fs::MetadataExt;
	Some(PosixOwner {
		id: Some(meta.uid() as _),
		name: None,
	})
}

#[cfg(not(unix))]
pub(crate) fn owner_user(_meta: &Metadata) -> Option<PosixOwner> {
	None
}

#[cfg(unix)]
pub(crate) fn owner_group(meta: &Metadata) -> Option<PosixOwner> {
	use std::os::unix::fs::MetadataExt;
	Some(PosixOwner {
		id: Some(meta.gid() as _),
		name: None,
	})
}

#[cfg(not(unix))]
pub(crate) fn owner_group(_meta: &Metadata) -> Option<PosixOwner> {
	None
}

#[cfg(unix)]
pub(crate) fn posix_mode(meta: &Metadata) -> Option<u32> {
	use std::os::unix::fs::MetadataExt;
	Some(meta.mode())
}

#[cfg(not(unix))]
pub(crate) fn posix_mode(_meta: &Metadata) -> Option<u32> {
	None
}

#[cfg(windows)]
pub(crate) fn file_attributes(meta: &Metadata) -> Option<HashMap<String, AttributeValue>> {
	use std::os::windows::fs::MetadataExt;
	use windows::Win32::Storage::FileSystem;

	let attrs = meta.file_attributes();

	Some(
		[
			("hidden", attrs & FileSystem::FILE_ATTRIBUTE_HIDDEN != 0),
			("system", attrs & FileSystem::FILE_ATTRIBUTE_SYSTEM != 0),
			("archive", attrs & FileSystem::FILE_ATTRIBUTE_ARCHIVE != 0),
			(
				"temporary",
				attrs & FileSystem::FILE_ATTRIBUTE_TEMPORARY != 0,
			),
			("sparse", attrs & FileSystem::FILE_ATTRIBUTE_SPARSE != 0),
			(
				"compressed",
				attrs & FileSystem::FILE_ATTRIBUTE_COMPRESSED != 0,
			),
			(
				"not-content-indexed",
				attrs & FileSystem::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED != 0,
			),
			(
				"encrypted",
				attrs & FileSystem::FILE_ATTRIBUTE_ENCRYPTED != 0,
			),
		]
		.into_iter()
		.map(|(k, v)| (format!("win32.{k}"), AttributeValue::Boolean(v)))
		.collect(),
	)
}

#[cfg(not(windows))]
pub(crate) fn file_attributes(_meta: &Metadata) -> Option<HashMap<String, AttributeValue>> {
	None
}
