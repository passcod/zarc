use std::{fs::File, path::PathBuf};

use base64ct::{Base64, Encoding};
use clap::{Parser, ValueHint};
use tracing::{debug, info};
use walkdir::WalkDir;
use zarc::encode::{Encoder, ZstdParameter, ZstdStrategy};

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
	/// Use this if you want to compress the entire Zarc externally.
	#[arg(long)]
	pub store: bool,

	/// Follow symlinks.
	///
	/// This destroys symlinks inside the Zarc: when unpacked, files will be duplicated.
	///
	/// You may want '--follow-external-symlinks' instead.
	#[arg(long, short = 'L')]
	pub follow_symlinks: bool,

	/// Follow external symlinks.
	///
	/// By default, zarc stores all symlinks as symlinks. If symlinks point to content external to
	/// the Zarc, the symlink when unpacked may point somewhere different or break.
	///
	/// With this flag, zarc will evaluate symlinks and store them as symlinks if they are relative
	/// symlinks that point to other files in the Zarc, but will follow symlinks (and flatten them
	/// into stored files) if they are absolute or relative but pointing "outside" of the Zarc.
	///
	/// See also the variant '--follow-and-store-external-symlinks'.
	#[arg(long, hide = true)]
	pub follow_external_symlinks: bool,

	/// Follow external symlinks, but also store the symlink target.
	///
	/// Like '--follow-external-symlinks', but stores the symlink's original external target path
	/// alongside the stored file content. When unpacking, Zarc can decide to restore external symlinks
	/// or to unpack the stored content.
	#[arg(long, hide = true)]
	pub follow_and_store_external_symlinks: bool,
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
					BoolishValueParser::new().parse_ref(cmd, arg, std::ffi::OsStr::new(right))?;
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
					.parse_ref(cmd, arg, std::ffi::OsStr::new(right))?;

				#[allow(clippy::unwrap_used)] // UNWRAP: checked by range
				let val = u32::try_from(val).unwrap();

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

pub(crate) fn pack(args: PackArgs) -> std::io::Result<()> {
	info!(path=?args.output, "create output file");
	let mut file = File::create(args.output)?;

	info!("initialise encoder");
	let mut zarc = Encoder::new(&mut file)?;

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
		debug!("disable compression for content");
		zarc.enable_compression(false);
	}

	for path in &args.paths {
		info!("walk {path:?}");
		for entry in WalkDir::new(path).follow_links(args.follow_symlinks) {
			let entry = match entry {
				Ok(file) => file,
				Err(err) => {
					eprintln!("read error: {err}");
					continue;
				}
			};

			let filename = entry.path();
			debug!("read {filename:?}");

			let mut file = zarc.build_file_with_metadata(filename, args.follow_symlinks)?;
			if entry.file_type().is_file() {
				let content = std::fs::read(filename)?;
				file.digest(zarc.add_data_frame(&content)?);
			}
			zarc.add_file_entry(file)?;
		}
	}

	info!("finalising zarc");
	let digest = zarc.finalise()?;

	println!("digest: {}", Base64::encode_string(&digest));
	Ok(())
}
