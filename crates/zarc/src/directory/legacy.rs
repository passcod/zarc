use minicbor::{Decode, Encode};

/// Zarc Directory
///
/// [Spec](https://github.com/passcod/zarc/blob/main/SPEC.md#zarc-directory)
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct LegacyDirectory {
	/// Editions.
	///
	/// Editions are the versions of the archive. There will always be one edition, and if the file
	/// is modified or appended to, a new edition will be introduced.
	#[n(1)]
	pub editions: Vec<super::Edition>,

	/// Files.
	///
	/// List of files, their pathname, their metadata, and which frame of content they point to.
	#[n(2)]
	pub filemap: Vec<super::File>,

	/// Frames.
	///
	/// List of frames, their digest, signature, and offset in the file.
	#[n(3)]
	pub framelist: Vec<super::Frame>,
}
