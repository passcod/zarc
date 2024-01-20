#[cfg(unix)]
use std::sync::Mutex;

#[cfg(unix)]
use crate::owner_cache::OwnerCache;
use minicbor::{data::Type, Decode, Decoder, Encode, Encoder};
#[cfg(unix)]
use nix::unistd::{Gid, Group, Uid, User};

#[cfg(unix)]
thread_local! {
	static OWNER_CACHE: Mutex<OwnerCache> = Mutex::new(OwnerCache::default());
}

/// POSIX owner information (user or group).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PosixOwner {
	/// Owner numeric ID.
	pub id: Option<u64>,

	/// Owner name.
	pub name: Option<String>,
}

impl PosixOwner {
	/// Create from a user ID.
	///
	/// On non-Unix, this always succeeds and returns a `PosixOwner` with the ID set only.
	///
	/// On Unix, this resolves the user from the system and returns a `PosixOwner` with both the ID
	/// ID and the username set, iff the user exists.
	pub fn from_uid(uid: u32) -> std::io::Result<Option<Self>> {
		#[cfg(unix)]
		{
			OWNER_CACHE
				.with(|oc| {
					oc.lock()
						.expect("owner cache poisoned")
						.user_from_uid(Uid::from_raw(uid))
				})
				.map(|u| u.map(Into::into))
		}

		#[cfg(not(unix))]
		{
			Ok(Some(Self {
				id: Some(uid as _),
				name: None,
			}))
		}
	}

	/// Create from a group ID.
	///
	/// On non-Unix, this always succeeds and returns a `PosixOwner` with the ID set only.
	///
	/// On Unix, this resolves the group from the system and returns a `PosixOwner` with both the ID
	/// and the group name set, iff the group exists.
	pub fn from_gid(gid: u32) -> std::io::Result<Option<Self>> {
		#[cfg(unix)]
		{
			OWNER_CACHE
				.with(|oc| {
					oc.lock()
						.expect("owner cache poisoned")
						.group_from_gid(Gid::from_raw(gid))
				})
				.map(|u| u.map(Into::into))
		}

		#[cfg(not(unix))]
		{
			Ok(Some(Self {
				id: Some(gid as _),
				name: None,
			}))
		}
	}

	/// Convert to a user ID valid on the current system.
	///
	/// - If only `id` is present, this checks and returns it.
	/// - If only `name` is present, this resolves the user from the system and returns its ID if it exists.
	/// - If both are present, and:
	///   - `id` matches the resolved ID from the name, this returns `id`.
	///   - `id` does not match the resolved ID from the name, this returns the ID of the resolved user.
	///   - `name` does not resolve to a user on the system, this returns `id`.
	///
	/// Additionally if the `id` is larger than a u32, this returns an error.
	#[cfg(unix)]
	pub fn to_real_uid(&self) -> std::io::Result<Option<Uid>> {
		match self {
			Self {
				id: None,
				name: None,
			} => Ok(None),

			Self {
				id: Some(id),
				name: None,
			} => u32::try_from(*id)
				.map_err(std::io::Error::other)
				.and_then(|uid| {
					OWNER_CACHE.with(|oc| {
						oc.lock()
							.expect("owner cache poisoned")
							.user_from_uid(Uid::from_raw(uid))
					})
				})
				.map(|u| u.map(|u| u.uid)),

			Self {
				id: None,
				name: Some(name),
			} => OWNER_CACHE
				.with(|oc| {
					oc.lock()
						.expect("owner cache poisoned")
						.user_from_name(name)
				})
				.map(|u| u.map(|u| u.uid)),

			Self {
				id: Some(id),
				name: Some(name),
			} => {
				let id = u32::try_from(*id).map_err(std::io::Error::other)?;

				if let Some(user) = OWNER_CACHE.with(|oc| {
					oc.lock()
						.expect("owner cache poisoned")
						.user_from_name(name)
				})? {
					Ok(Some(user.uid))
				} else {
					Ok(Some(Uid::from_raw(id)))
				}
			}
		}
	}

	/// Convert to a group ID valid on the current system.
	///
	/// - If only `id` is present, this checks and returns it.
	/// - If only `name` is present, this resolves the group from the system and returns its ID if it exists.
	/// - If both are present, and:
	///   - `id` matches the resolved ID from the name, this returns `id`.
	///   - `id` does not match the resolved ID from the name, this returns the ID of the resolved group.
	///   - `name` does not resolve to a group on the system, this returns `id`.
	///
	/// Additionally if the `id` is larger than a u32, this returns an error.
	#[cfg(unix)]
	pub fn to_real_gid(&self) -> std::io::Result<Option<Gid>> {
		match self {
			Self {
				id: None,
				name: None,
			} => Ok(None),

			Self {
				id: Some(id),
				name: None,
			} => u32::try_from(*id)
				.map_err(std::io::Error::other)
				.and_then(|gid| {
					OWNER_CACHE.with(|oc| {
						oc.lock()
							.expect("owner cache poisoned")
							.group_from_gid(Gid::from_raw(gid))
					})
				})
				.map(|u| u.map(|u| u.gid)),

			Self {
				id: None,
				name: Some(name),
			} => OWNER_CACHE
				.with(|oc| {
					oc.lock()
						.expect("owner cache poisoned")
						.group_from_name(name)
				})
				.map(|u| u.map(|u| u.gid)),

			Self {
				id: Some(id),
				name: Some(name),
			} => {
				let id = u32::try_from(*id).map_err(std::io::Error::other)?;

				if let Some(group) = OWNER_CACHE.with(|oc| {
					oc.lock()
						.expect("owner cache poisoned")
						.group_from_name(name)
				})? {
					Ok(Some(group.gid))
				} else {
					Ok(Some(Gid::from_raw(id)))
				}
			}
		}
	}
}

#[cfg(unix)]
impl From<User> for PosixOwner {
	fn from(user: User) -> Self {
		Self {
			id: Some(user.uid.as_raw() as _),
			name: Some(user.name),
		}
	}
}

#[cfg(unix)]
impl From<Group> for PosixOwner {
	fn from(group: Group) -> Self {
		Self {
			id: Some(group.gid.as_raw() as _),
			name: Some(group.name),
		}
	}
}

impl<C> Encode<C> for PosixOwner {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		_ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		e.array(match (self.id.is_some(), self.name.is_some()) {
			(true, true) => 2,
			(true, false) | (false, true) => 1,
			(false, false) => 0,
		})?;

		if let Some(id) = &self.id {
			e.u64(*id)?;
		}

		if let Some(name) = &self.name {
			e.encode(name)?;
		}

		Ok(())
	}
}

impl<'b, C> Decode<'b, C> for PosixOwner {
	fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		let mut id = None;
		let mut name = None;

		let max = d.array()?.unwrap_or(u64::MAX);
		for _ in 0..max {
			match d.datatype()? {
				Type::Break => break,
				Type::U8 => {
					id = Some(d.u8()? as _);
				}
				Type::U16 => {
					id = Some(d.u16()? as _);
				}
				Type::U32 => {
					id = Some(d.u32()? as _);
				}
				Type::U64 => {
					id = Some(d.u64()?);
				}
				Type::String | Type::StringIndef => {
					name = Some(d.decode()?);
				}
				ty => return Err(minicbor::decode::Error::type_mismatch(ty)),
			}
		}

		Ok(Self { id, name })
	}
}
