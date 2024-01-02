use std::{
	io::{Error, Result},
	path::PathBuf,
};

use blake3::Hash;
use clap::{Parser, ValueHint};
use deku::DekuContainerRead;
use ed25519_dalek::{Signature, VerifyingKey};
use tracing::error;
use umask::Mode;
use zarc::{
	format::{
		CborString, LinkTarget, PosixOwner, ZarcDirectory, ZarcDirectoryHeader, ZarcEofTrailer,
		ZarcHeader,
	},
	zstd::parser::{
		SkippableFrame, ZstandardBlock, ZstandardBlockHeader, ZstandardBlockType, ZstandardFrame,
		SKIPPABLE_FRAME_MAGIC, ZSTANDARD_FRAME_MAGIC,
	},
};
use zstd_safe::DCtx;

#[derive(Debug, Clone, Parser)]
pub struct DebugArgs {
	/// Input file.
	#[arg(
		value_hint = ValueHint::AnyPath,
		value_name = "PATH",
	)]
	pub input: PathBuf,

	/// Don't attempt to decode Zarc headers and data.
	#[arg(long, short = 'R')]
	pub raw: bool,

	/// Print raw frame and block data.
	#[arg(long, short = 'd')]
	pub with_data: bool,

	/// Decompress frame data.
	#[arg(long, short = 'D')]
	pub decompress: bool,

	/// Stop after N frames.
	#[arg(long, short = 'n')]
	pub limit: Option<usize>,
}

pub(crate) fn debug(args: DebugArgs) -> Result<()> {
	let file = std::fs::read(&args.input)?;

	let mut input = &file[..];
	let mut frame = 0;
	let mut zarc = false;
	let mut directory_header = None;
	while let Ok((rest, is_zarc, dh)) =
		parse_frame(&args, frame, &input, zarc, directory_header.as_ref()).map_err(|err| {
			eprintln!("fatal error: {err}");
		}) {
		input = rest;
		frame += 1;

		directory_header = dh;
		if !args.raw {
			zarc = zarc || is_zarc;
		}

		if rest.is_empty() {
			break;
		}

		if let Some(limit) = args.limit {
			if frame >= limit {
				break;
			}
		}

		println!("");
	}

	Ok(())
}

fn parse_frame<'input>(
	args: &DebugArgs,
	n: usize,
	input: &'input [u8],
	zarc: bool,
	previous_frame_is_directory_header: Option<&ZarcDirectoryHeader>,
) -> Result<(&'input [u8], bool, Option<ZarcDirectoryHeader>)> {
	let Some(start_magic) = input.get(0..4) else {
		return Err(Error::other(
			"input too short: must be at least 12 bytes, but we found less than 4",
		));
	};

	println!("frame: {n}");
	print!("  magic: {start_magic:02x?}");

	if start_magic == ZSTANDARD_FRAME_MAGIC {
		println!(" (zstandard frame)");
		let ((rest, _), frame) = ZstandardFrame::from_bytes((input, 0))?;

		println!("  descriptor: {s:08b} (0x{s:02X})", s = input[5]);
		println!(
			"    single segment: {}",
			frame.frame_descriptor.single_segment
		);
		println!("    has checksum: {}", frame.frame_descriptor.checksum);
		println!("    unused bit: {}", frame.frame_descriptor.unused_bit);
		println!("    reserved bit: {}", frame.frame_descriptor.reserved_bit);
		println!(
			"    fcs size flag: {f} (0b{f:02b})",
			f = frame.frame_descriptor.fcs_size
		);
		println!(
			"      actual size: {} bytes",
			frame.frame_descriptor.fcs_length()
		);
		println!(
			"    did size flag: {f} (0b{f:02b})",
			f = frame.frame_descriptor.did_size
		);
		println!(
			"      actual size: {} bytes",
			frame.frame_descriptor.did_length()
		);

		if let Some(w) = frame.window_descriptor {
			println!("  window descriptor: {w} (0x{w:02X})");
		}

		if !frame.did.is_empty() {
			println!("  dictionary id: {d} ({d:08X})", d = frame.dictionary_id());
		}

		println!(
			"  uncompressed size: {} bytes ({:02x?})",
			frame.uncompressed_size(),
			frame.frame_content_size
		);

		if let Some(k) = frame.checksum {
			println!("  checksum: 0x{k:08X}");
		}

		if frame.blocks.is_empty() {
			println!("  no blocks");
		} else {
			println!("");
		}

		for (m, block) in frame.blocks.iter().enumerate() {
			println!("  block: {m} ({:?})", block.header.block_type);

			if let Some(count) = block.header.rle_count() {
				println!("    byte: 0x{:02X}", block.data[0]);
				println!("    count: {count} (0x{count:04X})");
			} else {
				println!(
					"    size: {s} bytes (0x{s:03X})",
					s = block.header.actual_size()
				);
			}

			if args.with_data {
				println!("    data: {data:02x?}", data = block.data);
			}
		}

		if args.decompress {
			println!("");

			let mut zstd =
				DCtx::try_create().ok_or_else(|| Error::other("failed allocating zstd context"))?;
			zstd.init().map_err(map_zstd_error)?;

			let mut buf: Vec<u8> = Vec::with_capacity(
				usize::try_from(
					(1024 * 128)
						.max(frame.uncompressed_size() + 1024.max(frame.uncompressed_size() / 10)),
				)
				.expect("too large for this arch"),
			);
			match zstd.decompress(&mut buf, &input).map_err(map_zstd_error) {
				Ok(bytes) => {
					println!("  decompressed: {buf:02x?} ({bytes} bytes)");
				}
				Err(err) => {
					println!("  decompression failed: {err}");
				}
			}
		}

		if zarc {
			println!("");

			if n == 1 {
				if let Some(magic_repeat) = frame.blocks.get(0) {
					if let Ok((_, zarc_magic)) = ZarcHeader::from_bytes((&magic_repeat.data, 0))
						.map_err(|_| {
							println!(
								"  zarc: !!! expected magic in first block, but found none !!!"
							);
						}) {
						println!(
							"  zarc: unintended magic (file format v{})",
							zarc_magic.file_version
						);

						if let Some(ZstandardBlock {
							header:
								header @ ZstandardBlockHeader {
									block_type: ZstandardBlockType::Rle,
									..
								},
							data,
						}) = frame.blocks.get(1)
						{
							if data == &[0] && header.rle_count() == Some(0) {
								println!("    has defensive null-byte zero-count RLE block");
							}
						}
					}
				} else {
					println!("  zarc: !!! expected magic in first block, but found none !!!");
				}
			} else if let Some(header) = previous_frame_is_directory_header {
				let mut zstd = DCtx::try_create()
					.ok_or_else(|| Error::other("failed allocating zstd context"))?;
				zstd.init().map_err(map_zstd_error)?;

				let mut buf: Vec<u8> =
					Vec::with_capacity(
						usize::try_from((1024 * 128).max(
							frame.uncompressed_size() + 1024.max(frame.uncompressed_size() / 10),
						))
						.expect("too large for this arch"),
					);
				let bytes = match zstd.decompress(&mut buf, &input).map_err(map_zstd_error) {
					Ok(bytes) => bytes,
					Err(err) => {
						println!("  zarc (directory): !!! failed to decompress frame: {err}");
						return Ok((rest, false, None));
					}
				};

				if let Ok(directory) = minicbor::decode::<ZarcDirectory>(&buf).map_err(|err| {
					error!("failed to parse zarc directory: {err}");
				}) {
					println!(
						"  zarc: directory (directory format v{}) ({bytes} bytes)",
						directory.version
					);

					println!("    hash algorithm: {:?}", directory.hash_algorithm);
					if let Ok(hash) = header.hash.as_slice().try_into() {
						let directory_hash = blake3::hash(&buf);
						let header_hash = Hash::from_bytes(hash);
						if directory_hash == header_hash {
							println!("      directory digest: valid ✅");
						} else {
							println!("      directory digest: invalid ❌",);
						}
					} else {
						println!(
							"      !!! failed to parse hash: expected {} bytes, found {} !!!",
							blake3::KEY_LEN,
							header.hash.len()
						);
					}

					println!("    signature scheme: {:?}", directory.signature_scheme);
					let header_sig = Signature::try_from(header.sig.as_slice())
						.map_err(|err| {
							println!("      !!! failed to parse signature: {err}");
						})
						.ok();

					println!("    public key: {}", bs64::encode(&directory.public_key));

					let key = VerifyingKey::try_from(directory.public_key.as_slice())
						.map_err(|err| {
							println!("      !!! failed to parse public key: {err}");
						})
						.ok();
					if key.map_or(false, |k| k.is_weak()) {
						println!("      !!! key is valid but weak !!!");
					}
					if let Some(check) =
						header_sig.and_then(|sig| key.map(|k| k.verify_strict(&header.hash, &sig)))
					{
						match check {
							Ok(_) => println!("      directory signature: valid ✅"),
							Err(err) => println!("      directory signature: invalid ❌ ({err})"),
						}
					}

					println!("    created at: {}", directory.written_at);

					println!("    files: {}", directory.filemap.len());
					for (i, file) in directory.filemap.iter().enumerate() {
						if let Some(hash) = &file.frame_hash {
							println!("      file {i}: {}", bs64::encode(&hash));
						} else {
							if let Some(special) = &file.special {
								println!("      file {i}: {:?}", special.kind);
								match &special.link_target {
									Some(LinkTarget::Components(path)) => {
										println!("        target: ({} components)", path.len());
										for component in path {
											match component {
												CborString::Binary(b) => println!(
													"          {b:02x?} ({})",
													String::from_utf8_lossy(&b)
												),
												CborString::Text(t) => println!("          {t}"),
											}
										}
									}
									Some(LinkTarget::FullPath(path)) => match path {
										CborString::Binary(b) => println!(
											"        target: {b:02x?} ({})",
											String::from_utf8_lossy(&b)
										),
										CborString::Text(t) => println!("        target: {t}"),
									},
									None => {}
								}
							} else {
								println!("      file {i}: unknown");
							}
						}

						println!("        path: ({} components)", file.name.0.len());
						for component in &file.name.0 {
							match component {
								CborString::Binary(b) => {
									println!("          {b:02x?} ({})", String::from_utf8_lossy(b))
								}
								CborString::Text(t) => println!("          {t}"),
							}
						}

						if let Some(n) = file.version_added {
							println!("        version added: -{}", (n + 1));
						}

						if let Some(ro) = file.readonly {
							println!("        readonly: {ro}");
						}

						if let Some(mode) = file.mode {
							println!("        posix mode: {mode:08o} ({})", Mode::from(mode));
						}

						if let Some(PosixOwner { id, name }) = &file.user {
							print!("        posix user:");
							if let Some(id) = id {
								print!(" id={id}");
							}
							if let Some(name) = name {
								match name {
									CborString::Binary(b) => {
										print!(" name={} ({b:02x?})", String::from_utf8_lossy(b))
									}
									CborString::Text(t) => print!(" name={t}"),
								}
							}
							println!("");
						}

						if let Some(PosixOwner { id, name }) = &file.group {
							print!("        posix group:");
							if let Some(id) = id {
								print!(" id={id}");
							}
							if let Some(name) = name {
								match name {
									CborString::Binary(b) => {
										print!(" name={} ({b:02x?})", String::from_utf8_lossy(b))
									}
									CborString::Text(t) => print!(" name={t}"),
								}
							}
							println!("");
						}

						if let Some(ts) = &file.timestamps {
							println!("        timestamps:");
							if let Some(inserted) = ts.inserted {
								println!("          inserted: {inserted}");
							}
							if let Some(created) = ts.created {
								println!("          created: {created}");
							}
							if let Some(modified) = ts.modified {
								println!("          modified: {modified}");
							}
							if let Some(accessed) = ts.accessed {
								println!("          accessed: {accessed}");
							}
						}

						if let Some(meta) = &file.attributes {
							if meta.is_empty() {
								println!("        attributes: present, but empty");
							} else {
								println!("        attributes:");
								for (k, v) in meta {
									println!("          {k}: {v:?}");
								}
							}
						}

						if let Some(meta) = &file.extended_attributes {
							if meta.is_empty() {
								println!("        extended attributes: present, but empty");
							} else {
								println!("        extended attributes:");
								for (k, v) in meta {
									println!("          {k}: {v:?}");
								}
							}
						}

						if let Some(meta) = &file.user_metadata {
							if meta.is_empty() {
								println!("        user metadata: present, but empty");
							} else {
								println!("        user metadata:");
								for (k, v) in meta {
									println!("          {k}: {v:?}");
								}
							}
						}
					}

					println!("    frames: {}", directory.framelist.len());
					for (i, file) in directory.framelist.iter().enumerate() {
						println!("      frame {i}: {}", bs64::encode(&file.frame_hash));
						println!("        offset: {} bytes", file.offset);
						println!(
							"        uncompressed size: {} bytes",
							file.uncompressed_size
						);
						if let Some(n) = file.version_added {
							println!("        version added: -{}", (n + 1));
						}

						print!("        signature: {}", bs64::encode(&file.signature));
						let sig = Signature::try_from(file.signature.as_slice())
							.map_err(|err| {
								println!("\n          !!! failed to parse signature: {err}");
							})
							.ok();
						if let Some(check) =
							sig.and_then(|sig| key.map(|k| k.verify_strict(&file.frame_hash, &sig)))
						{
							match check {
								Ok(_) => println!(" (✅)"),
								Err(err) => {
									println!("\n          !!! signature invalid ❌ ({err})")
								}
							}
						} else {
							println!("");
						}
					}

					if let Some(meta) = directory.user_metadata {
						if meta.is_empty() {
							println!("    user metadata: present, but empty");
						} else {
							println!("    user metadata:");
							for (k, v) in meta {
								println!("      {k}: {v:?}");
							}
						}
					}

					if let Some(versions) = directory.prior_versions {
						if versions.is_empty() {
							println!("    versions: present, but empty");
						} else {
							println!("    versions: {}", versions.len());
							for (n, version) in versions.iter().enumerate() {
								println!("      {}: -{}", (n + 1), version.written_at);
								println!("        hash algorithm: {:?}", version.hash_algorithm);
								println!(
									"        signature scheme: {:?}",
									version.signature_scheme
								);
								println!(
									"        public key: {}",
									bs64::encode(&version.public_key)
								);

								if let Some(meta) = &version.user_metadata {
									if meta.is_empty() {
										println!("        user metadata: present, but empty");
									} else {
										println!("        user metadata:");
										for (k, v) in meta {
											println!("          {k}: {v:?}");
										}
									}
								}
							}
						}
					}
				}
			}
		}

		Ok((rest, false, None))
	} else if &start_magic[1..4] == SKIPPABLE_FRAME_MAGIC {
		println!(" (skippable frame)");
		let ((rest, _), frame) = SkippableFrame::from_bytes((input, 0))?;

		let nibble = start_magic[0] << 4 >> 4;
		println!("  nibble: 0x{nibble:X}");
		println!("  length: {s} (0x{s:08X})", s = frame.size());

		if args.with_data {
			println!("  data: {data:02x?}", data = frame.data);
		}

		if !args.raw {
			if n == 0 && nibble == 0 {
				if let Ok((_, zarc_magic)) =
					ZarcHeader::from_bytes((&frame.data, 0)).map_err(|err| {
						error!("failed to parse zarc header: {err}");
					}) {
					println!("  zarc: header (file format v{})", zarc_magic.file_version);

					return Ok((rest, true, None));
				}
			}

			if zarc && nibble == 0xF {
				if let Ok((_, directory_header)) = ZarcDirectoryHeader::from_bytes((&frame.data, 0))
					.map_err(|err| {
						error!("failed to parse zarc directory header: {err}");
					}) {
					println!(
						"  zarc: directory header (file format v{})",
						directory_header.file_version
					);
					println!(
						"    uncompressed size: {} bytes",
						directory_header.directory_size
					);
					println!("    digest: {}", bs64::encode(&directory_header.hash));
					println!("    signature: {}", bs64::encode(&directory_header.sig));

					return Ok((rest, true, Some(directory_header)));
				}
			}

			if zarc && nibble == 0xE {
				if let Ok((_, trailer)) =
					ZarcEofTrailer::from_bytes((&frame.data, 0)).map_err(|err| {
						error!("failed to parse zarc eof trailer: {err}");
					}) {
					println!("  zarc: eof trailer");
					println!(
						"    directory offset: {} bytes from end",
						16 + trailer.directory_frames_size
					);
				}
			}
		}

		Ok((rest, false, None))
	} else {
		return Err(Error::other("unknown magic"));
	}
}

fn map_zstd_error(code: usize) -> Error {
	let msg = zstd_safe::get_error_name(code);
	Error::other(msg)
}
