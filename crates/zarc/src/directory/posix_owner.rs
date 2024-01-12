use minicbor::{data::Type, Decode, Decoder, Encode, Encoder};

use super::strings::CborString;

/// POSIX owner information (user or group).
#[derive(Clone, Debug, PartialEq)]
pub struct PosixOwner {
	/// Owner numeric ID.
	pub id: Option<u64>,

	/// Owner name.
	pub name: Option<CborString>,
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
				Type::Bytes | Type::BytesIndef if name.is_none() => {
					name = Some(d.decode()?);
				}
				ty => return Err(minicbor::decode::Error::type_mismatch(ty)),
			}
		}

		Ok(Self { id, name })
	}
}
