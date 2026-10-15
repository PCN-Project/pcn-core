//! `pcn-address` — PCN addressing types.
//!
//! PCN separates several concepts that other protocols conflate:
//!
//! * **PCN-ID** — a stable cryptographic node identity (future work, see
//!   the `pcn-identity` crate plan in the repository README). A PCN-ID does
//!   not change when the node moves.
//! * **Routing address** — the 16-byte [`Address`] carried in packet
//!   headers. It locates a node inside the PCN routing domain; it is *not*
//!   an identity.
//! * **Transport endpoint** — e.g. an IP address plus UDP port. Endpoints
//!   are owned by the transport layer and must never be treated as a PCN
//!   identity or a PCN address.
//!
//! Addresses are scoped:
//!
//! * *Local* addresses are only meaningful inside a [`DomainId`]. The same
//!   local address may be allocated independently in different domains, so
//!   any resolution of a local address must carry domain context — see
//!   [`ScopedAddress`].
//! * *Global* addresses come from the centrally administered PCN Global
//!   space. Not every node has one.
//!
//! In protocol v0.1 the on-wire address is an opaque 128-bit value; the
//! bit-level split between local and global ranges is deliberately not
//! defined yet (see `docs/protocol/v0.1/addressing.md`).

use core::fmt;
use std::error::Error;
use std::str::FromStr;

/// Length in bytes of a PCN routing address on the wire.
pub const ADDRESS_LEN: usize = 16;

/// A 16-byte PCN routing address.
///
/// This is the address carried in the packet header's source and
/// destination fields. It is intentionally opaque: v0.1 does not define
/// how the 128-bit space is carved into local and global ranges.
///
/// The textual form is eight groups of four lowercase hexadecimal digits
/// separated by colons, e.g. `2001:0db8:0000:0000:0000:0000:0000:0001`.
/// This format is provisional and only used for diagnostics and configs —
/// never on the wire as text.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    /// The all-zero address. Never valid as a source or destination.
    pub const UNSPECIFIED: Self = Self([0; ADDRESS_LEN]);

    /// Builds an address from its 16 raw octets.
    #[must_use]
    pub const fn from_octets(octets: [u8; ADDRESS_LEN]) -> Self {
        Self(octets)
    }

    /// Returns the 16 raw octets of the address.
    #[must_use]
    pub const fn octets(&self) -> &[u8; ADDRESS_LEN] {
        &self.0
    }

    /// Returns `true` if this is the all-zero [`Address::UNSPECIFIED`] address.
    ///
    /// Written as an explicit loop rather than `self.0 == [0; 16]` because
    /// `PartialEq` on arrays is not callable in `const fn`.
    #[must_use]
    pub const fn is_unspecified(&self) -> bool {
        let mut i = 0;
        while i < ADDRESS_LEN {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, chunk) in self.0.chunks_exact(2).enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{:02x}{:02x}", chunk[0], chunk[1])?;
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
        *addr.octets()
    }
}

/// Error returned when parsing the textual form of an [`Address`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressParseError {
    /// Expected exactly 8 colon-separated groups.
    InvalidGroupCount { found: usize },
    /// A group was empty or longer than 4 hexadecimal digits.
    InvalidGroupLength { group: usize },
    /// A group contained a non-hexadecimal character.
    InvalidDigit { group: usize },
}

impl fmt::Display for AddressParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGroupCount { found } => {
                write!(f, "expected 8 address groups, found {found}")
            }
            Self::InvalidGroupLength { group } => {
                write!(f, "address group {group} must be 1-4 hex digits")
            }
            Self::InvalidDigit { group } => {
                write!(f, "address group {group} contains a non-hex digit")
            }
        }
    }
}

impl Error for AddressParseError {}

impl FromStr for Address {
    type Err = AddressParseError;

    /// Parses `xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx` (each group 1-4
    /// hex digits, no `::` compression — the format is provisional).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let groups: Vec<&str> = s.split(':').collect();
        if groups.len() != 8 {
            return Err(AddressParseError::InvalidGroupCount {
                found: groups.len(),
            });
        }
        let mut octets = [0u8; ADDRESS_LEN];
        for (i, group) in groups.iter().enumerate() {
            if group.is_empty() || group.len() > 4 {
                return Err(AddressParseError::InvalidGroupLength { group: i });
            }
            let value = u16::from_str_radix(group, 16)
                .map_err(|_| AddressParseError::InvalidDigit { group: i })?;
            octets[2 * i..2 * i + 2].copy_from_slice(&value.to_be_bytes());
        }
        Ok(Self::from_octets(octets))
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
    fn address_display_is_canonical() {
        let addr = Address::from_octets([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        assert_eq!(addr.to_string(), "2001:0db8:0000:0000:0000:0000:0000:0001");
    }

    #[test]
    fn address_from_str_roundtrips() {
        let text = "0001:0203:0405:0607:0809:0a0b:0c0d:0e0f";
        let addr: Address = text.parse().unwrap();
        assert_eq!(addr.to_string(), text);
        assert_eq!(
            addr.octets(),
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f
            ]
        );
    }

    #[test]
    fn address_from_str_accepts_short_groups() {
        let addr: Address = "1:2:3:4:5:6:7:8".parse().unwrap();
        assert_eq!(addr.to_string(), "0001:0002:0003:0004:0005:0006:0007:0008");
    }

    #[test]
    fn address_from_str_rejects_bad_input() {
        assert!(matches!(
            "1:2:3:4:5:6:7".parse::<Address>(),
            Err(AddressParseError::InvalidGroupCount { found: 7 })
        ));
        assert!(matches!(
            "1:2:3:4:5:6:7:8:9".parse::<Address>(),
            Err(AddressParseError::InvalidGroupCount { found: 9 })
        ));
        assert!(matches!(
            "1:2:3:4:5:6:7:".parse::<Address>(),
            Err(AddressParseError::InvalidGroupLength { .. })
        ));
        assert!(matches!(
            "1:2:3:4:5:6:7:12345".parse::<Address>(),
            Err(AddressParseError::InvalidGroupLength { .. })
        ));
        assert!(matches!(
            "1:2:3:4:5:6:7:zzzz".parse::<Address>(),
            Err(AddressParseError::InvalidDigit { .. })
        ));
        // No `::` compression in the provisional format.
        assert!("2001:db8::1".parse::<Address>().is_err());
        assert!("".parse::<Address>().is_err());
    }

    #[test]
    fn unspecified_address() {
        assert!(Address::UNSPECIFIED.is_unspecified());
        assert!(!Address::from_octets([1; 16]).is_unspecified());
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
        let addr: Address = "0000:0000:0000:0000:0000:0000:0000:000a".parse().unwrap();
        let domain = DomainId::from_raw(7);
        let scoped = ScopedAddress::new(addr, domain);
        assert_eq!(scoped.address(), addr);
        assert_eq!(scoped.domain(), domain);
        assert_eq!(
            scoped.to_string(),
            "0000:0000:0000:0000:0000:0000:0000:000a@domain-0000000000000007"
        );
        // Same address in a different domain is a different scoped address.
        assert_ne!(scoped, ScopedAddress::new(addr, DomainId::from_raw(8)));
    }
}
