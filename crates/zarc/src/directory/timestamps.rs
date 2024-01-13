use std::{fmt, time::SystemTime};

use chrono::{DateTime, Utc};
use minicbor::{
	data::{Tag, Type},
	Decode, Decoder, Encode, Encoder,
};

/// Directory Filemap Entry Timestamps.
#[derive(Clone, Debug, Default, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct Timestamps {
	/// Creation time (birth time).
	#[n(1)]
	pub created: Option<Timestamp>,

	/// Modification time (mtime).
	#[n(2)]
	pub modified: Option<Timestamp>,

	/// Access time (atime).
	#[n(3)]
	pub accessed: Option<Timestamp>,
}

/// A timestamp.
///
/// Internally this is a [`chrono`] type, and always encodes to an RFC3339 tagged text string.
/// However for flexibility it can decode from a CBOR epoch-based timestamp as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timestamp(pub DateTime<Utc>);

impl Timestamp {
	/// The current date and time.
	pub fn now() -> Self {
		Self(Utc::now())
	}
}

impl From<SystemTime> for Timestamp {
	fn from(st: SystemTime) -> Self {
		Self(st.into())
	}
}

impl From<Timestamp> for SystemTime {
	fn from(ts: Timestamp) -> Self {
		ts.0.into()
	}
}

impl From<DateTime<Utc>> for Timestamp {
	fn from(dt: DateTime<Utc>) -> Self {
		Self(dt)
	}
}

impl From<Timestamp> for DateTime<Utc> {
	fn from(ts: Timestamp) -> Self {
		ts.0
	}
}

impl fmt::Display for Timestamp {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl<C> Encode<C> for Timestamp {
	fn encode<W: minicbor::encode::write::Write>(
		&self,
		e: &mut Encoder<W>,
		_ctx: &mut C,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		e.tag(Tag::DateTime)?.str(&self.0.to_rfc3339()).map(drop)
	}
}

impl<'b, C> Decode<'b, C> for Timestamp {
	fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
		let p = d.position();
		match d.tag()? {
			Tag::DateTime => Ok(Self(
				DateTime::parse_from_rfc3339(d.str()?)
					.map_err(|err| minicbor::decode::Error::message(err.to_string()).at(p))?
					.into(),
			)),
			Tag::Timestamp => match d.datatype()? {
				Type::U32 => DateTime::<Utc>::from_timestamp(i64::from(d.u32()?), 0),
				Type::U64 => DateTime::<Utc>::from_timestamp(
					i64::try_from(d.u64()?).map_err(|err| {
						minicbor::decode::Error::message(format!("timestamp out of range: {err}"))
							.at(p)
					})?,
					0,
				),
				Type::I32 => DateTime::<Utc>::from_timestamp(i64::from(d.i32()?), 0),
				Type::I64 => DateTime::<Utc>::from_timestamp(d.i64()?, 0),
				Type::Int => DateTime::<Utc>::from_timestamp(
					i64::try_from(d.int()?).map_err(|err| {
						minicbor::decode::Error::message(format!("timestamp out of range: {err}"))
							.at(p)
					})?,
					0,
				),
				Type::F32 => {
					let f = d.f32()?;
					DateTime::<Utc>::from_timestamp(f.trunc() as _, (f.fract() * 1.0e9) as _)
				}
				Type::F64 => {
					let f = d.f64()?;
					DateTime::<Utc>::from_timestamp(f.trunc() as _, (f.fract() * 1.0e9) as _)
				}
				ty => return Err(minicbor::decode::Error::type_mismatch(ty)),
			}
			.ok_or_else(|| minicbor::decode::Error::message("timestamp out of range").at(p))
			.map(Self),
			other => Err(minicbor::decode::Error::message(format!(
				"expected Timestamp or DateTime tag, got {other:?}"
			))
			.at(p)),
		}
	}
}
