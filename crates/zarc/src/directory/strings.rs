use std::{
	ffi::OsStr,
	path::{Component, Path, PathBuf},
};

use minicbor::{data::Type, Decode, Decoder, Encode, Encoder};

/// Pathname as components.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Encode, Decode)]
#[cbor(transparent)]
pub struct Pathname(
	/// Components of the path.
	#[n(0)] // but unused because of transparent
	pub  Vec<CborString>,
	// double space is from rustfmt: https://github.com/rust-lang/rustfmt/issues/5997
);

impl Pathname {
	/// Converts a Path, ignoring all non-normal components.
	pub fn from_normal_components(path: &Path) -> Self {
		Self(
			path.components()
				.filter_map(|c| {
					if let Component::Normal(comp) = c {
						Some(CborString::from(comp))
					} else {
						None
					}
				})
				.collect(),
		)
	}

	/// Converts to a (platform-specific) Path.
	pub fn to_path(&self) -> PathBuf {
		let mut path = PathBuf::new();
		for comp in &self.0 {
			match comp {
				CborString::Text(text) => {
					path.push(text);
				}
				CborString::Binary(bytes) => {
					#[cfg(unix)]
					{
						use std::os::unix::ffi::OsStrExt;
						path.push(OsStr::from_bytes(bytes));
					}
					#[cfg(not(unix))]
					{
						path.push(String::from_utf8_lossy(bytes));
					}
				}
			}
		}

		path
	}
}

/// CBOR Text or Byte string.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum CborString {
	/// UTF-8 text string value.
	Text(String),

	/// Non-unicode byte string value.
	Binary(Vec<u8>),
}

impl CborString {
	/// Convert from bytes that might be UTF-8.
	pub fn from_maybe_utf8(bytes: Vec<u8>) -> Self {
		match String::from_utf8(bytes) {
			Ok(string) => Self::Text(string),
			Err(err) => Self::Binary(err.into_bytes()),
		}
	}
}

impl From<&OsStr> for CborString {
	fn from(string: &OsStr) -> Self {
		if let Some(unicode) = string.to_str() {
			Self::Text(unicode.into())
		} else {
			#[cfg(unix)]
			{
				use std::os::unix::ffi::OsStrExt;
				Self::Binary(string.as_bytes().into())
			}
			#[cfg(windows)]
			{
				use std::os::windows::ffi::OsStrExt;
				Self::Text(String::from_utf16_lossy(&string.encode_wide().collect()))
			}
		}
	}
}

impl From<&str> for CborString {
	fn from(string: &str) -> Self {
		Self::Text(string.into())
	}
}

impl From<String> for CborString {
	fn from(string: String) -> Self {
		Self::Text(string)
	}
}

impl<C> Encode<C> for CborString {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		match self {
			Self::Text(s) => s.encode(e, ctx),
			Self::Binary(b) => <&minicbor::bytes::ByteSlice>::from(b.as_slice()).encode(e, ctx),
		}
	}
}

impl<'b, C> Decode<'b, C> for CborString {
	fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		match d.datatype()? {
			Type::String => d.str().map(|s| Self::Text(s.into())),
			Type::StringIndef => Ok(Self::Text(d.str_iter()?.try_fold(
				String::new(),
				|mut string, s| {
					s.map(|s| {
						string.extend(s.chars());
						string
					})
				},
			)?)),
			Type::Bytes => d.bytes().map(|b| Self::Binary(b.into())),
			Type::BytesIndef => Ok(Self::Binary(d.bytes_iter()?.try_fold(
				Vec::new(),
				|mut vec, b| {
					b.map(|b| {
						vec.extend(b);
						vec
					})
				},
			)?)),
			ty => Err(minicbor::decode::Error::type_mismatch(ty)),
		}
	}
}

/// Attributes can be booleans or text or byte strings.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum AttributeValue {
	/// A boolean.
	Boolean(bool),

	/// A string.
	String(CborString),
}

impl From<bool> for AttributeValue {
	fn from(b: bool) -> Self {
		Self::Boolean(b)
	}
}

impl<T> From<T> for AttributeValue
where
	T: Into<CborString>,
{
	fn from(string: T) -> Self {
		Self::String(string.into())
	}
}

impl<C> Encode<C> for AttributeValue {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		match self {
			Self::Boolean(b) => b.encode(e, ctx),
			Self::String(s) => s.encode(e, ctx),
		}
	}
}

impl<'b, C> Decode<'b, C> for AttributeValue {
	fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		match d.datatype()? {
			Type::String | Type::StringIndef | Type::Bytes | Type::BytesIndef => {
				d.decode().map(Self::String)
			}
			Type::Bool => d.decode().map(Self::Boolean),
			ty => Err(minicbor::decode::Error::type_mismatch(ty)),
		}
	}
}
