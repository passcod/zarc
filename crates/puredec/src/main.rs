use std::{
	fs::File,
	io::{Read, Seek, SeekFrom},
	path::PathBuf,
};

use clap::{Parser, ValueHint};
use ruzstd::frame_decoder::BlockDecodingStrategy;
use tracing::{debug, info};

/// ruzstd decoder tool
#[derive(Debug, Clone, Parser)]
pub struct Args {
	#[arg(
		value_hint = ValueHint::AnyPath,
		value_name = "PATH",
	)]
	pub input: PathBuf,
}

#[allow(unused_must_use)]
fn main() {
	tracing_subscriber::fmt::init();

	let args = Args::parse();
	debug!(?args, "got arguments");

	info!(path=?args.input, "open input file");
	let mut file = File::open(args.input).unwrap();

	match ruzstd::frame::read_frame_header(&mut file) {
		Ok((frame, _)) => {
			dbg!(
				frame.header.window_size(),
				frame.header.dictionary_id(),
				frame.header.frame_content_size(),
			);
			let d = frame.header.descriptor;
			dbg!(
				d.frame_content_size_flag(),
				d.reserved_flag(),
				d.single_segment_flag(),
				d.content_checksum_flag(),
				d.dict_id_flag(),
				d.frame_content_size_bytes(),
				d.dictionary_id_bytes(),
			);

			let mut buf = [0_u8; 3];
			file.read_exact(&mut buf).unwrap();
			file.seek(SeekFrom::Current(-3)).unwrap();
			println!("{:08b} {:08b} {:08b}", buf[0], buf[1], buf[2]);

			let mut block_dec = ruzstd::decoding::block_decoder::new();
			let (block_header, _) = block_dec.read_block_header(&mut file).unwrap();
			dbg!(
				block_header.last_block,
				block_header.block_type,
				block_header.decompressed_size,
				block_header.content_size,
			);
		}
		Err(skip) => {
			eprintln!("skip frame {skip:?}");
		}
	}

	info!("init ruzstd");
	let mut frame_dec = ruzstd::FrameDecoder::new();
	file.rewind().unwrap();
	frame_dec.reset(&mut file).unwrap();
	let mut result = Vec::with_capacity(1024);

	while !frame_dec.is_finished() {
		// decode (roughly) batch_size many bytes
		frame_dec
			.decode_blocks(&mut file, BlockDecodingStrategy::UptoBytes(1024))
			.unwrap();
		dbg!(frame_dec.blocks_decoded());

		// read from the decoder to collect bytes from the internal buffer
		let bytes_read = frame_dec.read(result.as_mut_slice()).unwrap();

		// then do something with it
		println!("{:02x?}", &result[0..bytes_read]);
	}

	// handle the last chunk of data
	while frame_dec.can_collect() > 0 {
		let chunk = frame_dec.collect().unwrap();
		println!("{:02x?}", chunk);
		dbg!(String::from_utf8(chunk));
	}
}
