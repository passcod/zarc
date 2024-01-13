use std::path::{Component, Path};

use minicbor::{data::Type, Decode, Decoder, Encode, Encoder};

use super::strings::{CborString, Pathname};

/// Special File metadata.
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#30-special-file-types)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(array)]
pub struct SpecialFile {
	/// Kind of special file.
	///
	/// Will be `None` for unknown kinds.
	#[n(0)]
	pub kind: Option<SpecialFileKind>,

	/// Link target.
	#[n(1)]
	pub link_target: Option<LinkTarget>,
}

impl SpecialFile {
	/// Returns `true` if this is a directory.
	///
	/// See also [`SpecialFileKind::is_dir`].
	pub fn is_dir(&self) -> bool {
		self.kind.map_or(false, SpecialFileKind::is_dir)
	}

	/// Returns `true` if this is a link.
	///
	/// See also [`SpecialFileKind::is_link`].
	pub fn is_link(&self) -> bool {
		self.kind.map_or(false, SpecialFileKind::is_link)
	}

	/// Returns `true` if this is a symlink.
	///
	/// See also [`SpecialFileKind::is_symlink`].
	pub fn is_symlink(&self) -> bool {
		self.kind.map_or(false, SpecialFileKind::is_symlink)
	}

	/// Returns `true` if this is a hardlink.
	///
	/// See also [`SpecialFileKind::is_hardlink`].
	pub fn is_hardlink(&self) -> bool {
		self.kind.map_or(false, SpecialFileKind::is_hardlink)
	}
}

/// Special File kinds.
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#30-special-file-types)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(index_only)]
pub enum SpecialFileKind {
	/// Directory.
	///
	/// To encode metadata/attributes against a directory.
	#[n(1)]
	Directory = 1,

	/// A symlink.
	///
	/// Some kind of symlink, but without specifying what exactly it is.
	#[n(10)]
	Symlink = 10,

	/// Internal symbolic link.
	///
	/// Must point to a file that exists within this Zarc.
	#[n(11)]
	InternalSymlink = 11,

	/// External absolute symbolic link.
	#[n(12)]
	ExternalAbsoluteSymlink = 12,

	/// External relative symbolic link.
	#[n(13)]
	ExternalRelativeSymlink = 13,

	/// A hardlink.
	///
	/// Some kind of hardlink, but without specifying what exactly it is.
	#[n(20)]
	Hardlink = 20,

	/// Internal hardlink.
	///
	/// Must point to a file that exists within this Zarc.
	#[n(21)]
	InternalHardlink = 21,

	/// External hardlink.
	#[n(22)]
	ExternalHardlink = 22,
}

impl SpecialFileKind {
	/// Returns `true` if this is a directory.
	pub fn is_dir(self) -> bool {
		matches!(self, Self::Directory)
	}

	/// Returns `true` if this is a link.
	///
	/// This covers all the symlink and hardlink variants.
	pub fn is_link(self) -> bool {
		self.is_symlink() || self.is_hardlink()
	}

	/// Returns `true` if this is a symlink.
	///
	/// This covers all the symlink variants.
	pub fn is_symlink(self) -> bool {
		matches!(
			self,
			Self::Symlink
				| Self::InternalSymlink
				| Self::ExternalAbsoluteSymlink
				| Self::ExternalRelativeSymlink
		)
	}

	/// Returns `true` if this is a hardlink.
	///
	/// This covers all the hardlink variants.
	pub fn is_hardlink(self) -> bool {
		matches!(
			self,
			Self::Hardlink | Self::InternalHardlink | Self::ExternalHardlink
		)
	}
}

/// Target of link (for [`SpecialFile`])
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#30-special-file-types)
#[derive(Clone, Debug, PartialEq)]
pub enum LinkTarget {
	/// Target as full pathname.
	FullPath(CborString),

	/// Target as array of path components.
	Components(Vec<CborString>),
}

impl From<Pathname> for LinkTarget {
	fn from(pathname: Pathname) -> Self {
		Self::Components(pathname.0)
	}
}

impl From<&Path> for LinkTarget {
	fn from(path: &Path) -> Self {
		if path.is_absolute()
			|| path
				.components()
				.any(|c| !matches!(c, Component::Normal(_)))
		{
			Self::FullPath(CborString::from(path.as_os_str()))
		} else {
			Self::from(Pathname::from_normal_components(path))
		}
	}
}

impl<C> Encode<C> for LinkTarget {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		match self {
			Self::FullPath(s) => s.encode(e, ctx),
			Self::Components(v) => {
				e.array(v.len().try_into().expect("path way too long"))?;
				for s in v {
					s.encode(e, ctx)?;
				}
				Ok(())
			}
		}
	}
}

impl<'b, C> Decode<'b, C> for LinkTarget {
	fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		match d.datatype()? {
			Type::Array => todo!(),
			Type::ArrayIndef => todo!(),
			_ => CborString::decode(d, ctx).map(Self::FullPath),
		}
	}
}
