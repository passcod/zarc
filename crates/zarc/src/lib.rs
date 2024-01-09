//! Zarc: Archive format based on Zstd.
//!
//! [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md)
//!
//! TBD

#![warn(clippy::unwrap_used, missing_docs)]
#![deny(rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod decode;
pub mod encode;
pub mod format;
#[cfg(feature = "metadata")]
pub mod metadata;
pub mod ondemand;

pub(crate) fn map_zstd_error(code: usize) -> std::io::Error {
	let msg = zstd_safe::get_error_name(code);
	std::io::Error::other(msg)
}
