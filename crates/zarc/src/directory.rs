//! Common types defining the binary format structures.

#[doc(hidden)]
pub use self::legacy::*;
mod legacy;

#[doc(inline)]
pub use self::edition::*;
#[doc(inline)]
pub use self::elements::*;
#[doc(inline)]
pub use self::file::*;
#[doc(inline)]
pub use self::frame::*;
#[doc(inline)]
pub use self::posix_owner::*;
#[doc(inline)]
pub use self::specials::*;
#[doc(inline)]
pub use self::strings::*;
#[doc(inline)]
pub use self::timestamps::*;

mod edition;
mod elements;
mod file;
mod frame;
mod posix_owner;
mod specials;
mod strings;
mod timestamps;
