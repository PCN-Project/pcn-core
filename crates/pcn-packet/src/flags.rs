//! The 16-bit Flags header field.
//!
//! Protocol v0.1 defines **no** flag bits. The field exists so that a
//! later version can signal optional header or payload features; until
//! then any nonzero value is rejected by the parser rather than silently
//! ignored.

use core::fmt;

/// The set of flag bits defined by this protocol version.
///
/// v0.1 defines none; the constant exists so future versions can widen it
/// and parsers can compute `flags & !SUPPORTED`.
pub(crate) const SUPPORTED_MASK: u16 = 0x0000;

/// The Flags field of a packet header.
///
/// An opaque bit-mask wrapper. Construction is restricted to values the
/// current protocol version understands; parsing produces
/// [`crate::ParseError::UnsupportedFlags`] for anything else.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Flags(u16);

impl Flags {
    /// No flags set — the only legal value in v0.1.
    pub const NONE: Self = Self(0);

    /// Builds a flags value from raw bits without checking them.
    ///
    /// Used by the decoder, which performs the supported-bits check
    /// separately so it can report the offending value.
    pub(crate) const fn from_bits_unchecked(bits: u16) -> Self {
        Self(bits)
    }

    /// The raw 16-bit value.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// `true` if no flag bits are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
