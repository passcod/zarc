//! Caching lookup for user and group names.
//!
//! Looking up user and group names is very slow! In testing, this could often account for over 90%
//! of the time spent in `zarc` when creating a new archive, and similarly when unpacking. To speed
//! this up, we cache the results of these lookups at runtime, with the assumption that id/name
//! mappings for users and groups won't change during an invocation of the program.

use std::collections::HashMap;

use nix::unistd::{Gid, Group, Uid, User};

/// A cache of user and group info.
#[derive(Clone, Debug, Default)]
pub struct OwnerCache {
	users: HashMap<Uid, User>,
	groups: HashMap<Gid, Group>,
	uid_by_name: HashMap<String, Uid>,
	gid_by_name: HashMap<String, Gid>,
}

impl OwnerCache {
	/// Get a user from a UID, from cache or the system.
	pub fn user_from_uid(&mut self, uid: Uid) -> std::io::Result<Option<User>> {
		if let Some(user) = self.users.get(&uid) {
			return Ok(Some(user.clone()));
		}

		let user = User::from_uid(uid)?;
		if let Some(user) = user.as_ref() {
			self.users.insert(uid, user.clone());
			self.uid_by_name.insert(user.name.to_owned(), user.uid);
		}
		Ok(user)
	}

	/// Get a group from a GID, from cache or the system.
	pub fn group_from_gid(&mut self, gid: Gid) -> std::io::Result<Option<Group>> {
		if let Some(group) = self.groups.get(&gid) {
			return Ok(Some(group.clone()));
		}

		let group = Group::from_gid(gid)?;
		if let Some(group) = group.as_ref() {
			self.groups.insert(gid, group.clone());
			self.gid_by_name.insert(group.name.to_owned(), group.gid);
		}
		Ok(group)
	}

	/// Get a user from a name, from cache or the system.
	pub fn user_from_name(&mut self, name: &str) -> std::io::Result<Option<User>> {
		if let Some(uid) = self.uid_by_name.get(name) {
			return self.user_from_uid(*uid);
		}

		let user = User::from_name(name)?;
		if let Some(user) = user.as_ref() {
			self.users.insert(user.uid, user.clone());
			self.uid_by_name.insert(name.to_owned(), user.uid);
		}
		Ok(user)
	}

	/// Get a group from a UID, from cache or the system.
	pub fn group_from_name(&mut self, name: &str) -> std::io::Result<Option<Group>> {
		if let Some(gid) = self.gid_by_name.get(name) {
			return self.group_from_gid(*gid);
		}

		let group = Group::from_name(name)?;
		if let Some(group) = group.as_ref() {
			self.groups.insert(group.gid, group.clone());
			self.gid_by_name.insert(name.to_owned(), group.gid);
		}
		Ok(group)
	}
}
