//! Zstd file format parser.
//!
//! This crate has the ambition of becoming a Zstandard implementation in pure Rust. For now, it
//! only implements types for encoding and decoding the framing of the file format.

pub mod framing;
