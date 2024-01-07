//! Error types for [`Decoder`](super::Decoder).
use std::borrow::Cow;

use deku::DekuError;
use miette::{Diagnostic, SourceSpan};
use thiserror::Error;

/// Convenience return type.
pub type Result<T> = std::result::Result<T, Error>;

/// Combined return error type for [`Decoder`](super::Decoder) methods.
#[derive(Error, Diagnostic, Debug)]
pub enum Error {
	/// I/O error.
	#[error(transparent)]
	Io(#[from] std::io::Error),

	/// Decoder error that's just a message.
	#[error(transparent)]
	Simple(#[from] SimpleError),

	/// Decoder error that includes source.
	#[error(transparent)]
	Source(#[from] SourceError),
}

/// Decoder error.
#[derive(Error, Diagnostic, Debug)]
#[error("zarc decode: {message}")]
pub struct SimpleError {
	/// Error kind.
	pub kind: ErrorKind,

	/// Error message.
	pub message: Cow<'static, str>,
}

/// Decoder error.
#[derive(Error, Diagnostic, Debug)]
#[error("zarc decode: {message}")]
pub struct SourceError {
	/// Error kind.
	pub kind: ErrorKind,

	/// Error message.
	pub message: Cow<'static, str>,

	/// Error location in zarc file.
	#[label("here")]
	pub at: SourceSpan,

	/// Snippet of zarc file.
	#[source_code]
	pub snippet: String,
}

impl SimpleError {
	/// New error without source.
	pub fn new(kind: ErrorKind) -> Self {
		Self {
			kind,
			message: kind.default_message().into(),
		}
	}

	/// New simple error from deku.
	pub fn from_deku(orig: DekuError) -> Self {
		Self::new(ErrorKind::Parse).with_message(orig.to_string())
	}

	/// Change the error message.
	pub fn with_message(mut self, message: impl Into<Cow<'static, str>>) -> Self {
		self.message = message.into();
		self
	}
}

impl SourceError {
	/// New error with source snippet.
	pub fn new(kind: ErrorKind, snippet: &[u8], at_byte: usize) -> Self {
		Self {
			kind,
			message: kind.default_message().into(),
			snippet: format!("{snippet:02x?}"),
			at: SourceSpan::from((
				(at_byte * 2) + 1, // to account for [
				2,                 // always 2 bytes for the hex value
			)),
		}
	}

	/// New error with source snippet, extracted from a larger source.
	pub fn from_source(kind: ErrorKind, source: &[u8], at_byte: usize, context: usize) -> Self {
		let start = at_byte.saturating_sub(context);
		let end = at_byte.saturating_add(context).min(source.len());
		Self::new(kind, &source[start..end], at_byte.saturating_sub(start))
	}

	/// New error from deku.
	pub fn from_deku(orig: DekuError, source: &[u8], at_byte: usize, context: usize) -> Self {
		Self::from_source(ErrorKind::Parse, source, at_byte, context).with_message(orig.to_string())
	}

	/// Change the error message.
	pub fn with_message(mut self, message: impl Into<Cow<'static, str>>) -> Self {
		self.message = message.into();
		self
	}
}

/// Decoder error kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
	/// Zstd initialization error.
	ZstdInit,

	/// Invalid skippable frame magic nibble.
	InvalidNibble {
		/// Expected nibble value
		expected: u8,
		/// Value actually found
		actual: u8,
	},

	/// Unsupported zarc file version.
	UnsupportedFileVersion(u8),

	/// When using internal methods manually, you can read sections of a Zarc file out of order,
	/// before necessary details are available, which will cause this error. The public API
	/// guarantees this never occurs.
	ReadOrderViolation(&'static str),

	/// Unintended magic header was malformed.
	InvalidUnintendedMagic,

	/// The file version number is repeated several times in a Zarc file, and they must all match.
	MismatchedFileVersion,

	/// Parse error.
	Parse,
}

impl ErrorKind {
	/// Get the default error message for this error kind.
	pub fn default_message(self) -> Cow<'static, str> {
		match self {
			ErrorKind::ZstdInit => Cow::Borrowed("zstd initialization error"),
			ErrorKind::InvalidNibble { expected, actual } => Cow::Owned(format!(
				"invalid skippable frame magic nibble: expected 0x{expected:X}, got 0x{actual:X}"
			)),
			ErrorKind::UnsupportedFileVersion(version) => Cow::Owned(format!(
				"unsupported zarc file version {version}, this zarc supports versions {:?}",
				[crate::format::ZARC_FILE_VERSION]
			)),
			ErrorKind::ReadOrderViolation(what) => {
				Cow::Owned(format!("read order violation: {what}"))
			}
			ErrorKind::InvalidUnintendedMagic => Cow::Borrowed("malformed unintended magic header"),
			ErrorKind::MismatchedFileVersion => Cow::Borrowed("mismatched file version"),
			ErrorKind::Parse => Cow::Borrowed("parse error"),
		}
	}
}

impl From<ErrorKind> for SimpleError {
	fn from(ek: ErrorKind) -> Self {
		Self::new(ek)
	}
}

impl From<ErrorKind> for Error {
	fn from(ek: ErrorKind) -> Self {
		Self::Simple(ek.into())
	}
}
