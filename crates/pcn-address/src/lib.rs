//! `pcn-address` - PCN addressing types.
//!
//! PCN separates several concepts that other protocols conflate:
//!
//! * **PCN-ID** - a stable cryptographic node identity (future work, see
//!   the `pcn-identity` crate plan in the repository README). A PCN-ID does
//!   not change when the node moves.
//! * **Routing address** - the 8-byte [`Address`] carried in packet
//!   headers. It locates a node inside the PCN routing domain; it is *not*
//!   an identity.
//! * **Transport endpoint** - e.g. an IP address plus UDP port. Endpoints
//!   are owned by the transport layer and must never be treated as a PCN
//!   identity or a PCN address.
//!
//! Addresses are scoped:
//!
//! * *Local* addresses are only meaningful inside a [`DomainId`]. The same
//!   local address may be allocated independently in different domains, so
//!   any resolution of a local address must carry domain context - see
//!   [`ScopedAddress`].
//! * *Global* addresses come from the centrally administered PCN Global
//!   space. Not every node has one.
//!
//! In protocol v0.1 the on-wire address (PCN-ADDR) is a structured
//! 64-bit value: a 3-bit type field, a 60-bit address value, and one
//! reserved bit. Local and global scopes are expressed as address types
//! (see `docs/protocol/addressing.md`).

use core::fmt;
use std::error::Error;
use std::str::FromStr;

/// Length in bytes of a PCN routing address on the wire.
pub const ADDRESS_LEN: usize = 8;

/// Textual prefix of a PCN-ADDR address (`pcn~TXXX-XXXX-XXXXX`).
pub const ADDRESS_PREFIX: &str = "pcn~";

/// Base32 alphabet for the PCN-ADDR text form (Crockford-style,
/// uppercase, without I/L/O/U).
const BASE32_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Largest value the 60-bit address-value field can hold.
pub const ADDRESS_VALUE_MAX: u64 = (1 << 60) - 1;

const TYPE_SHIFT: u32 = 61;
const VALUE_SHIFT: u32 = 1;
const RESERVED_BIT: u64 = 1;

/// Returns the Base32 value of `b`, or `None` if it is not in the
/// PCN-ADDR alphabet.
fn base32_value(b: u8) -> Option<u8> {
    BASE32_ALPHABET
        .iter()
        .position(|&a| a == b)
        .map(|p| p as u8)
}

/// The address type carried in bits `[63:61]` of a PCN-ADDR address.
///
/// Only [`AddressType::Private`] and [`AddressType::Public`] are
/// routable in v0.1. [`AddressType::Reserved`] (0) names the
/// unspecified/reserved space; [`AddressType::Unsupported`] covers the
/// values 3-7 that the protocol reserves for future use.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AddressType {
    /// Type 0 - reserved; the only assigned member is the all-zero
    /// unspecified address.
    Reserved,
    /// Type 1 - private/local address, meaningful inside a domain.
    Private,
    /// Type 2 - public address from the PCN Global space.
    Public,
    /// Types 3-7 - reserved by the protocol, not yet assigned.
    Unsupported(u8),
}

impl AddressType {
    /// The 3-bit type code as it appears in bits `[63:61]`.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::Private => 1,
            Self::Public => 2,
            Self::Unsupported(v) => v,
        }
    }

    /// Maps a raw 3-bit type code to an [`AddressType`].
    const fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Self::Reserved,
            1 => Self::Private,
            2 => Self::Public,
            v => Self::Unsupported(v),
        }
    }
}

/// An 8-byte PCN routing address (PCN-ADDR).
///
/// This is the address carried in the packet header's source and
/// destination fields. Its 64 bits are laid out as:
///
/// * bits `[63:61]` - address type (3 bits),
/// * bits `[60:1]`  - address value (60 bits),
/// * bit  `[0]`     - reserved, always `0`.
///
/// The canonical textual form is `pcn~` followed by 13 Base32
/// characters grouped `4-4-5`: the first character encodes the type,
/// the remaining twelve encode the 60-bit value, e.g.
/// `pcn~1K4M-2X9R-06D3P` (private) or `pcn~2K4M-2X9R-06D3P` (public).
/// The `pcn~` prefix is optional when parsing, but [`fmt::Display`] always
/// emits the canonical prefixed form.
/// The text form never appears on the wire; the wire form is 8 raw
/// big-endian octets.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(u64);

impl Address {
    /// The all-zero address: type 0, value 0. It may be represented
    /// (e.g. "no address assigned yet" in node state) but is rejected
    /// by the packet layer in source and destination fields.
    pub const UNSPECIFIED: Self = Self(0);

    /// Builds an address from an [`AddressType`] and a 60-bit value.
    ///
    /// `value` is masked to 60 bits; the reserved bit `[0]` is always
    /// cleared, so the result is representable in the text form.
    #[must_use]
    pub const fn new(address_type: AddressType, value: u64) -> Self {
        Self(
            ((address_type.to_bits() as u64) << TYPE_SHIFT)
                | ((value & ADDRESS_VALUE_MAX) << VALUE_SHIFT),
        )
    }

    /// Builds an address from its 8 raw wire octets (big-endian).
    ///
    /// This is a raw constructor: it does not validate the type field
    /// or the reserved bit. Validation for use in packets is the packet
    /// layer's job (`Header::decode`, `PacketBuilder::build`); callers
    /// can pre-check with [`Address::is_routable`].
    #[must_use]
    pub const fn from_octets(octets: [u8; ADDRESS_LEN]) -> Self {
        Self(u64::from_be_bytes(octets))
    }

    /// Returns the 8 raw wire octets of the address (big-endian).
    #[must_use]
    pub const fn to_octets(&self) -> [u8; ADDRESS_LEN] {
        self.0.to_be_bytes()
    }

    /// Builds an address from its raw 64-bit representation.
    ///
    /// Raw constructor like [`Address::from_octets`]: no validation of
    /// the type field or the reserved bit.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw 64-bit representation.
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// The address type field (bits `[63:61]`).
    #[must_use]
    pub const fn address_type(&self) -> AddressType {
        AddressType::from_bits((self.0 >> TYPE_SHIFT) as u8)
    }

    /// The 60-bit address value field (bits `[60:1]`).
    #[must_use]
    pub const fn value(&self) -> u64 {
        (self.0 >> VALUE_SHIFT) & ADDRESS_VALUE_MAX
    }

    /// Returns `true` if reserved bit `[0]` is set.
    ///
    /// Such an address is malformed: it cannot appear in the text form
    /// (which carries only bits `[63:1]`) and must be rejected on the
    /// wire.
    #[must_use]
    pub const fn has_reserved_bit(&self) -> bool {
        self.0 & RESERVED_BIT != 0
    }

    /// Returns `true` if this is the all-zero [`Address::UNSPECIFIED`]
    /// address (type 0, value 0, reserved bit clear).
    #[must_use]
    pub const fn is_unspecified(&self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if the address is legal in a packet header in
    /// v0.1: type is [`AddressType::Private`] or [`AddressType::Public`]
    /// and the reserved bit is clear.
    #[must_use]
    pub const fn is_routable(&self) -> bool {
        matches!(
            self.address_type(),
            AddressType::Private | AddressType::Public
        ) && !self.has_reserved_bit()
    }
}

impl fmt::Display for Address {
    /// Formats `pcn~TXXX-XXXX-XXXXX`: the 3-bit type and the 60-bit
    /// value, Base32, grouped `4-4-5`. Reserved bit `[0]` is not part
    /// of the text form and is dropped.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut digits = [0u8; 13];
        digits[0] = BASE32_ALPHABET[self.address_type().to_bits() as usize];
        let value = self.value();
        for i in 0..12 {
            digits[1 + i] = BASE32_ALPHABET[((value >> (5 * (11 - i))) & 31) as usize];
        }
        f.write_str(ADDRESS_PREFIX)?;
        for (i, &d) in digits.iter().enumerate() {
            if i == 4 || i == 8 {
                f.write_str("-")?;
            }
            write!(f, "{}", d as char)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl From<[u8; ADDRESS_LEN]> for Address {
    fn from(octets: [u8; ADDRESS_LEN]) -> Self {
        Self::from_octets(octets)
    }
}

impl From<Address> for [u8; ADDRESS_LEN] {
    fn from(addr: Address) -> Self {
        addr.to_octets()
    }
}

/// Error returned when parsing the textual form of an [`Address`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressParseError {
    /// The address digits are not exactly 15 characters long
    /// (13 Base32 digits plus two hyphens).
    InvalidLength {
        /// Length of the string after stripping an optional `pcn~`
        /// prefix.
        found: usize,
    },
    /// The hyphens are not at positions 4 and 9, i.e. the grouping is
    /// not `4-4-5`.
    InvalidGrouping,
    /// A character is outside the Base32 alphabet
    /// `0123456789ABCDEFGHJKMNPQRSTVWXYZ`.
    InvalidCharacter {
        /// Byte offset inside the part after `pcn~`.
        position: usize,
    },
    /// The first Base32 character encodes an address type that v0.1
    /// does not support. Only `0`, `1`, `2` are valid; `3`-`7` are
    /// reserved by the protocol.
    UnsupportedAddressType {
        /// The Base32 value of the type character.
        found: u8,
    },
}

impl fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { found } => write!(
                f,
                "address must be 15 characters \
                 (13 Base32 digits grouped 4-4-5), found {found}"
            ),
            Self::InvalidGrouping => {
                write!(f, "address digits must be grouped 4-4-5 with hyphens")
            }
            Self::InvalidCharacter { position } => write!(
                f,
                "invalid character at position {position} \
                 (alphabet is 0-9 A-H J-K M-N P-T V-Z)"
            ),
            Self::UnsupportedAddressType { found } => write!(
                f,
                "unsupported address type {found} \
                 (v0.1 assigns 1 = private, 2 = public)"
            ),
        }
    }
}

impl Error for AddressParseError {}

impl FromStr for Address {
    type Err = AddressParseError;

    /// Parses `pcn~TXXX-XXXX-XXXXX`, or the same 15-character form
    /// without the `pcn~` prefix: 13 Base32 characters grouped `4-4-5`
    /// by hyphens. The first character encodes the type (must be
    /// `0`-`2`), the rest the 60-bit value. Both spellings produce the
    /// same [`Address`]; a wrong prefix (e.g. `PCN~`, `pcn`, `pcn~~`)
    /// is rejected by the ordinary length/grouping checks.
    ///
    /// The reserved bit `[0]` cannot be expressed in text form and is
    /// always clear in the result.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s.strip_prefix(ADDRESS_PREFIX).unwrap_or(s);
        if body.len() != 15 {
            return Err(AddressParseError::InvalidLength { found: body.len() });
        }
        let bytes = body.as_bytes();
        if bytes[4] != b'-' || bytes[9] != b'-' {
            return Err(AddressParseError::InvalidGrouping);
        }
        let mut digits = [0u8; 13];
        let mut n = 0usize;
        for (pos, &b) in bytes.iter().enumerate() {
            if b == b'-' {
                continue;
            }
            digits[n] =
                base32_value(b).ok_or(AddressParseError::InvalidCharacter { position: pos })?;
            n += 1;
        }
        if n != digits.len() {
            // More or fewer than 13 digit positions means an extra
            // hyphen slipped in outside positions 4 and 9.
            return Err(AddressParseError::InvalidGrouping);
        }
        let type_bits = digits[0];
        if type_bits >= 3 {
            return Err(AddressParseError::UnsupportedAddressType { found: type_bits });
        }
        let mut value = 0u64;
        for &d in &digits[1..] {
            value = (value << 5) | u64::from(d);
        }
        Ok(Self::from_raw(
            (u64::from(type_bits) << TYPE_SHIFT) | (value << VALUE_SHIFT),
        ))
    }
}

/// Identifier of a PCN domain.
///
/// A domain is the scope in which *local* addresses are administered.
/// Anyone may create an isolated private domain; globally routed domains
/// are registered with PCN Global operators. In v0.1 the identifier is a
/// 64-bit value chosen by the domain's administrator; a collision-safe
/// allocation scheme is future work.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainId(u64);

impl DomainId {
    /// Domain identifier meaning "no domain context" (e.g. an isolated
    /// node that has not joined any domain).
    pub const UNSPECIFIED: Self = Self(0);

    /// Builds a domain identifier from its raw value.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw 64-bit value.
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns `true` if this is [`DomainId::UNSPECIFIED`].
    #[must_use]
    pub const fn is_unspecified(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "domain-{:016x}", self.0)
    }
}

impl fmt::Debug for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// An [`Address`] qualified by the [`DomainId`] it is meaningful in.
///
/// Resolution of a local address is only well-defined inside its domain;
/// the same address octets may refer to different nodes in different
/// domains. Carrying the domain alongside the address prevents local
/// addresses from silently leaking across domain boundaries.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ScopedAddress {
    address: Address,
    domain: DomainId,
}

impl ScopedAddress {
    /// Binds an address to the domain it belongs to.
    #[must_use]
    pub const fn new(address: Address, domain: DomainId) -> Self {
        Self { address, domain }
    }

    /// The routing address.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// The domain the address is valid in.
    #[must_use]
    pub const fn domain(&self) -> DomainId {
        self.domain
    }
}

impl fmt::Display for ScopedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.address, self.domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_examples_roundtrip() {
        // Private (type 1) and public (type 2) forms from the spec.
        for (text, ty) in [
            ("pcn~1K4M-2X9R-06D3P", AddressType::Private),
            ("pcn~2K4M-2X9R-06D3P", AddressType::Public),
        ] {
            let addr: Address = text.parse().unwrap();
            assert_eq!(addr.address_type(), ty);
            assert!(!addr.has_reserved_bit());
            assert!(addr.is_routable());
            assert_eq!(addr.to_string(), text);
        }
    }

    #[test]
    fn boundary_values_roundtrip() {
        for (ty, value, text) in [
            (AddressType::Private, 0, "pcn~1000-0000-00000"),
            (
                AddressType::Public,
                ADDRESS_VALUE_MAX,
                "pcn~2ZZZ-ZZZZ-ZZZZZ",
            ),
        ] {
            let addr = Address::new(ty, value);
            assert_eq!(addr.value(), value);
            assert_eq!(addr.to_string(), text);
            assert_eq!(text.parse::<Address>().unwrap(), addr);
        }
    }

    #[test]
    fn text_wire_octets_roundtrip() {
        let addr: Address = "pcn~1K4M-2X9R-06D3P".parse().unwrap();
        assert_eq!(Address::from_octets(addr.to_octets()), addr);
        assert_eq!(Address::from_raw(addr.as_u64()), addr);

        // Private value 0 -> type 1 in bits 63:61, all else zero.
        let a = Address::new(AddressType::Private, 0);
        assert_eq!(a.as_u64(), 1 << 61);
        assert_eq!(
            a.to_octets(),
            [0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );

        // Public value 2 -> 0x4000_0000_0000_0004.
        let b = Address::new(AddressType::Public, 2);
        assert_eq!(b.as_u64(), 0x4000_0000_0000_0004);
        assert_eq!(
            b.to_octets(),
            [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04]
        );
    }

    #[test]
    fn unspecified_address() {
        let u: Address = "pcn~0000-0000-00000".parse().unwrap();
        assert_eq!(u, Address::UNSPECIFIED);
        assert!(u.is_unspecified());
        assert!(!u.is_routable());
        assert_eq!(u.address_type(), AddressType::Reserved);

        // Type 0 with a nonzero value is representable but not routable.
        let a = Address::new(AddressType::Reserved, 7);
        assert!(!a.is_unspecified());
        assert!(!a.is_routable());
        assert!(!Address::from_octets([1; 8]).is_unspecified());
    }

    #[test]
    fn reserved_bit_is_detected() {
        // Bit 0 set: cannot appear in text form, detectable on the wire.
        let a = Address::from_octets([0x20, 0, 0, 0, 0, 0, 0, 0x03]);
        assert!(a.has_reserved_bit());
        assert!(!a.is_routable());
        assert_eq!(a.address_type(), AddressType::Private);
        // Display drops bit 0: it renders the bits-63:1 form.
        assert_eq!(a.to_string(), "pcn~1000-0000-00001");

        let odd = Address::from_octets([0x20, 0, 0, 0, 0, 0, 0, 0x21]);
        assert!(odd.has_reserved_bit());
        assert!(!odd.is_routable());
    }

    #[test]
    fn unsupported_types_report_bits() {
        for bits in 3..=7u8 {
            let a = Address::from_raw((u64::from(bits) << 61) | 4);
            assert_eq!(a.address_type(), AddressType::Unsupported(bits));
            assert!(!a.is_routable());
        }
    }

    #[test]
    fn prefix_is_optional() {
        for text in ["pcn~1K4M-2X9R-06D3P", "pcn~2K4M-2X9R-06D3P"] {
            let bare = &text[ADDRESS_PREFIX.len()..];
            let with: Address = text.parse().unwrap();
            let without: Address = bare.parse().unwrap();
            // Both spellings decode to the very same address.
            assert_eq!(with, without);
            assert_eq!(with.to_octets(), without.to_octets());
            // Display always emits the canonical prefixed form.
            assert_eq!(with.to_string(), text);
            assert_eq!(without.to_string(), text);
        }
    }

    #[test]
    fn rejects_bad_prefix_and_length() {
        // Wrong or mangled prefixes: `pcn` without tilde, uppercase,
        // doubled prefix, or `pcn~` embedded inside the digits - all
        // rejected by the ordinary length/grouping checks.
        for bad in [
            "PCN~1K4M-2X9R-06D3P",
            "pcn1K4M-2X9R-06D3P",
            "pcn~~1K4M-2X9R-06D3P",
            "pcn~pcn~1K4M-2X9R-06D3P",
            "1K4Mpcn~-2X9R-06D3P",
        ] {
            assert!(bad.parse::<Address>().is_err(), "{bad} must be rejected");
        }
        assert!(matches!(
            "pcn~1K4M-2X9R-06D3".parse::<Address>(),
            Err(AddressParseError::InvalidLength { .. })
        ));
        assert!(matches!(
            "pcn~1K4M-2X9R-06D3P0".parse::<Address>(),
            Err(AddressParseError::InvalidLength { .. })
        ));
        assert!(matches!(
            "1K4M-2X9R-06D3".parse::<Address>(),
            Err(AddressParseError::InvalidLength { .. })
        ));
        assert_eq!(
            "".parse::<Address>(),
            Err(AddressParseError::InvalidLength { found: 0 })
        );
    }

    #[test]
    fn rejects_bad_grouping() {
        // No hyphens at all -> wrong length too, so length wins.
        assert!("pcn~1K4M2X9R06D3P".parse::<Address>().is_err());
        // Right length, hyphens in the wrong places.
        assert_eq!(
            "pcn~1K4-M2X9-R06D3P".parse::<Address>(),
            Err(AddressParseError::InvalidGrouping)
        );
        // Extra hyphen at a non-separator position -> wrong digit count.
        assert_eq!(
            "pcn~1K4M-2X9R-06D3-".parse::<Address>(),
            Err(AddressParseError::InvalidGrouping)
        );
    }

    #[test]
    fn rejects_invalid_characters() {
        // 'I' is not in the alphabet (position 14 after 'pcn~').
        assert_eq!(
            "pcn~1K4M-2X9R-06D3I".parse::<Address>(),
            Err(AddressParseError::InvalidCharacter { position: 14 })
        );
        // Lowercase is not accepted.
        assert!(matches!(
            "pcn~1k4m-2x9r-06d3p".parse::<Address>(),
            Err(AddressParseError::InvalidCharacter { .. })
        ));
        assert!(matches!(
            "pcn~1K4M-2X9R-06D3!".parse::<Address>(),
            Err(AddressParseError::InvalidCharacter { .. })
        ));
    }

    #[test]
    fn rejects_unsupported_type_chars() {
        for bad in ["3", "7", "8", "Z"] {
            let s = format!("pcn~{bad}K4M-2X9R-06D3P");
            assert!(
                matches!(
                    s.parse::<Address>(),
                    Err(AddressParseError::UnsupportedAddressType { .. })
                ),
                "{s} must be rejected"
            );
        }
        // Type chars 0-2 are accepted.
        assert!("pcn~0000-0000-00000".parse::<Address>().is_ok());
    }

    #[test]
    fn domain_id_basics() {
        assert!(DomainId::UNSPECIFIED.is_unspecified());
        let d = DomainId::from_raw(0xdead_beef);
        assert_eq!(d.as_u64(), 0xdead_beef);
        assert_eq!(d.to_string(), "domain-00000000deadbeef");
        assert!(!d.is_unspecified());
    }

    #[test]
    fn scoped_address_keeps_domain_context() {
        let addr: Address = "pcn~1000-0000-0000A".parse().unwrap();
        let domain = DomainId::from_raw(7);
        let scoped = ScopedAddress::new(addr, domain);
        assert_eq!(scoped.address(), addr);
        assert_eq!(scoped.domain(), domain);
        assert_eq!(
            scoped.to_string(),
            "pcn~1000-0000-0000A@domain-0000000000000007"
        );
        // Same address in a different domain is a different scoped address.
        assert_ne!(scoped, ScopedAddress::new(addr, DomainId::from_raw(8)));
    }
}
