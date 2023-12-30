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
	encode::{Encoder, ZstdParameter, ZstdStrategy},
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
	///
	/// Can be negative (disables compression), or up to 20 (22 with an ultra strategy).
	#[arg(
		long,
		allow_negative_numbers = true,
		value_parser = clap::value_parser!(i32).range((-1<<17)..22),
	)]
	pub level: Option<i32>,

	/// Zstd parameter.
	///
	/// Some values take a boolean, others take an unsigned integer, and the Strategy parameter
	/// takes a string. By default, ChecksumFlag is true, and all others are at zstd default.
	///
	/// This is an advanced API and not all values will produce valid Zarcs, caution advised.
	#[arg(
		long,
		value_name = "PARAM=VALUE",
		value_parser = ParseZstdParam,
	)]
	pub zstd: Vec<ZstdParameter>,

	/// Disable compression completely.
	///
	/// This will write all file content uncompressed, not even going through zstd at all.
	///
	/// Use this if you want to compress the entire zarc externally.
	#[arg(long)]
	pub store: bool,
}

#[derive(Clone)]
struct ParseZstdParam;

const ZSTD_PARAM_LIST_BOOL: [&str; 4] = [
	"EnableLongDistanceMatching",
	"ContentSizeFlag",
	"ChecksumFlag",
	"DictIdFlag",
];

const ZSTD_PARAM_LIST_U32: [&str; 13] = [
	"WindowLog",
	"HashLog",
	"ChainLog",
	"SearchLog",
	"MinMatch",
	"TargetLength",
	"LdmHashLog",
	"LdmMinMatch",
	"LdmBucketSizeLog",
	"LdmHashRateLog",
	"NbWorkers",
	"JobSize",
	"OverlapSizeLog",
];

const ZSTD_STRATEGY_NAMES: [&str; 9] = [
	"fast", "dfast", "greedy", "lazy", "lazy2", "btlazy2", "btopt", "btultra", "btultra2",
];

impl clap::builder::TypedValueParser for ParseZstdParam {
	type Value = ZstdParameter;

	fn parse_ref(
		&self,
		cmd: &clap::Command,
		arg: Option<&clap::Arg>,
		value: &std::ffi::OsStr,
	) -> Result<Self::Value, clap::Error> {
		use clap::{builder::*, error::*};
		let val = StringValueParser::new().parse_ref(cmd, arg, value)?;

		let (left, right) = val.split_once('=').ok_or_else(|| {
			let mut err =
				Error::raw(ErrorKind::ValueValidation, "expected a key=value pair").with_cmd(cmd);
			if let Some(arg) = arg {
				err.insert(
					ContextKind::InvalidArg,
					ContextValue::String(arg.to_string()),
				);
			}
			err
		})?;

		match left {
			"Strategy" => Ok(ZstdParameter::Strategy(match right {
				"fast" => ZstdStrategy::ZSTD_fast,
				"dfast" => ZstdStrategy::ZSTD_dfast,
				"greedy" => ZstdStrategy::ZSTD_greedy,
				"lazy" => ZstdStrategy::ZSTD_lazy,
				"lazy2" => ZstdStrategy::ZSTD_lazy2,
				"btlazy2" => ZstdStrategy::ZSTD_btlazy2,
				"btopt" => ZstdStrategy::ZSTD_btopt,
				"btultra" => ZstdStrategy::ZSTD_btultra,
				"btultra2" => ZstdStrategy::ZSTD_btultra2,
				_ => {
					return Err(Error::raw(
						ErrorKind::ValueValidation,
						"unknown Strategy value",
					))
				}
			})),
			flag if ZSTD_PARAM_LIST_BOOL.contains(&flag) => {
				let val: bool =
					BoolishValueParser::new().parse_ref(cmd, arg, &std::ffi::OsStr::new(right))?;
				Ok(match flag {
					"EnableLongDistanceMatching" => ZstdParameter::EnableLongDistanceMatching(val),
					"ContentSizeFlag" => ZstdParameter::ContentSizeFlag(val),
					"ChecksumFlag" => ZstdParameter::ChecksumFlag(val),
					"DictIdFlag" => ZstdParameter::DictIdFlag(val),
					_ => unreachable!(),
				})
			}
			tune if ZSTD_PARAM_LIST_U32.contains(&tune) => {
				let val: u64 = RangedU64ValueParser::new()
					.range(0..(u32::MAX as _))
					.parse_ref(cmd, arg, &std::ffi::OsStr::new(right))?;
				let val = u32::try_from(val).unwrap(); // UNWRAP: checked by range
				Ok(match tune {
					"WindowLog" => ZstdParameter::WindowLog(val),
					"HashLog" => ZstdParameter::HashLog(val),
					"ChainLog" => ZstdParameter::ChainLog(val),
					"SearchLog" => ZstdParameter::SearchLog(val),
					"MinMatch" => ZstdParameter::MinMatch(val),
					"TargetLength" => ZstdParameter::TargetLength(val),
					"LdmHashLog" => ZstdParameter::LdmHashLog(val),
					"LdmMinMatch" => ZstdParameter::LdmMinMatch(val),
					"LdmBucketSizeLog" => ZstdParameter::LdmBucketSizeLog(val),
					"LdmHashRateLog" => ZstdParameter::LdmHashRateLog(val),
					"NbWorkers" => ZstdParameter::NbWorkers(val),
					"JobSize" => ZstdParameter::JobSize(val),
					"OverlapSizeLog" => ZstdParameter::OverlapSizeLog(val),
					_ => unreachable!(),
				})
			}
			_ => Err(Error::raw(ErrorKind::ValueValidation, "unknown parameter")),
		}
	}

	fn possible_values(
		&self,
	) -> Option<Box<dyn Iterator<Item = clap::builder::PossibleValue> + '_>> {
		Some(Box::new(
			ZSTD_PARAM_LIST_BOOL
				.iter()
				.map(|name| clap::builder::PossibleValue::new(format!("{name}=true")))
				.chain(
					ZSTD_PARAM_LIST_U32
						.iter()
						.map(|name| clap::builder::PossibleValue::new(format!("{name}=0"))),
				)
				.chain(
					ZSTD_STRATEGY_NAMES.iter().map(|value| {
						clap::builder::PossibleValue::new(format!("Strategy={value}"))
					}),
				),
		))
	}
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

	for param in args.zstd {
		debug!(?param, "set zstd parameter");
		zarc.set_zstd_parameter(param)?;
	}

	if args.store {
		zarc.enable_compression(false);
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
