//! The fixed 32-byte v0.1 base header.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    Version    |     Type      |             Flags             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Header Length         |        Payload Length         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   Hop Limit   |                  Reserved                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                      Source Address (64)                      |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                   Destination Address (64)                    |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Packet ID                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! All multi-byte fields are big-endian. Offsets are defined as constants
//! so the layout is stated once, in one place.

use crate::{
    flags, Address, AddressRole, AddressType, EncodeError, Flags, PacketType, ParseError,
    BASE_HEADER_LEN, PROTOCOL_VERSION,
};
use core::fmt;

// Field offsets inside the 32-byte base header.
const OFF_VERSION: usize = 0;
const OFF_TYPE: usize = 1;
const OFF_FLAGS: usize = 2; // ..4
const OFF_HEADER_LEN: usize = 4; // ..6
const OFF_PAYLOAD_LEN: usize = 6; // ..8
const OFF_HOP_LIMIT: usize = 8;
const OFF_RESERVED: usize = 9; // ..12
const OFF_SOURCE: usize = 12; // ..20
const OFF_DESTINATION: usize = 20; // ..28
const OFF_PACKET_ID: usize = 28; // ..32

/// The fixed v0.1 packet header.
///
/// Instances are obtained either by parsing a datagram
/// ([`Header::decode`], which validates every rule of the v0.1 format) or
/// via [`crate::Packet::builder`]. Fields are read through accessors;
/// `header_len` is always [`BASE_HEADER_LEN`] and `flags` is always
/// [`Flags::NONE`], because v0.1 defines no alternatives.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    packet_type: PacketType,
    flags: Flags,
    payload_len: u16,
    hop_limit: u8,
    source: Address,
    destination: Address,
    packet_id: u32,
}

impl Header {
    /// Creates a header for a packet to be sent.
    ///
    /// `payload_len` is the size of the payload that will follow the
    /// header; it is stored in the header's Payload Length field.
    pub(crate) fn new(
        packet_type: PacketType,
        source: Address,
        destination: Address,
        packet_id: u32,
        hop_limit: u8,
        payload_len: u16,
    ) -> Self {
        Self {
            packet_type,
            flags: Flags::NONE,
            payload_len,
            hop_limit,
            source,
            destination,
            packet_id,
        }
    }

    /// The packet's semantic type.
    #[must_use]
    pub const fn packet_type(&self) -> PacketType {
        self.packet_type
    }

    /// The header flags. Always [`Flags::NONE`] in v0.1.
    #[must_use]
    pub const fn flags(&self) -> Flags {
        self.flags
    }

    /// Total header length in bytes. Always [`BASE_HEADER_LEN`] in v0.1.
    #[must_use]
    pub const fn header_len(&self) -> u16 {
        BASE_HEADER_LEN as u16
    }

    /// Declared payload length in bytes.
    #[must_use]
    pub const fn payload_len(&self) -> u16 {
        self.payload_len
    }

    /// Total wire length of the packet (header + payload) in bytes.
    #[must_use]
    pub const fn total_len(&self) -> usize {
        BASE_HEADER_LEN + self.payload_len as usize
    }

    /// Remaining forwarding hops. Semantics are defined by the routing
    /// layer; the packet layer only transports the field.
    #[must_use]
    pub const fn hop_limit(&self) -> u8 {
        self.hop_limit
    }

    /// Source PCN routing address.
    #[must_use]
    pub const fn source(&self) -> Address {
        self.source
    }

    /// Destination PCN routing address.
    #[must_use]
    pub const fn destination(&self) -> Address {
        self.destination
    }

    /// Sender-assigned packet identifier.
    #[must_use]
    pub const fn packet_id(&self) -> u32 {
        self.packet_id
    }

    /// Serializes the header into `buf`.
    ///
    /// `buf` must be at least [`BASE_HEADER_LEN`] bytes; exactly that many
    /// are written. Serialization is deterministic: the same header always
    /// produces the same bytes.
    ///
    /// # Errors
    /// Returns [`EncodeError::BufferTooSmall`] if `buf` is shorter than
    /// [`BASE_HEADER_LEN`]; the buffer is left unmodified.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        if buf.len() < BASE_HEADER_LEN {
            return Err(EncodeError::BufferTooSmall {
                required: BASE_HEADER_LEN,
                available: buf.len(),
            });
        }
        self.write_fields(&mut buf[..BASE_HEADER_LEN]);
        Ok(BASE_HEADER_LEN)
    }

    /// Writes the 32-byte encoding into `buf`.
    ///
    /// Caller must guarantee `buf.len() >= BASE_HEADER_LEN`; used by
    /// `to_bytes`/`Packet::encode` where that is true by construction.
    fn write_fields(&self, buf: &mut [u8]) {
        buf[OFF_VERSION] = PROTOCOL_VERSION;
        buf[OFF_TYPE] = self.packet_type.to_u8();
        buf[OFF_FLAGS..OFF_FLAGS + 2].copy_from_slice(&self.flags.bits().to_be_bytes());
        buf[OFF_HEADER_LEN..OFF_HEADER_LEN + 2].copy_from_slice(&self.header_len().to_be_bytes());
        buf[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[OFF_HOP_LIMIT] = self.hop_limit;
        buf[OFF_RESERVED..OFF_RESERVED + 3].copy_from_slice(&[0, 0, 0]);
        buf[OFF_SOURCE..OFF_SOURCE + 8].copy_from_slice(&self.source.to_octets());
        buf[OFF_DESTINATION..OFF_DESTINATION + 8].copy_from_slice(&self.destination.to_octets());
        buf[OFF_PACKET_ID..OFF_PACKET_ID + 4].copy_from_slice(&self.packet_id.to_be_bytes());
    }

    /// Returns the 32-byte wire encoding of this header.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BASE_HEADER_LEN] {
        let mut buf = [0u8; BASE_HEADER_LEN];
        self.write_fields(&mut buf);
        buf
    }

    /// Validates and decodes a base header from the front of `buf`.
    ///
    /// Checks, in order:
    /// 1. `buf` is at least [`BASE_HEADER_LEN`] bytes - nothing is read
    ///    before this is established.
    /// 2. Version equals [`PROTOCOL_VERSION`].
    /// 3. Header Length equals [`BASE_HEADER_LEN`] (no extensions in v0.1).
    /// 4. Flags are all zero (none are defined yet).
    /// 5. Reserved bytes are all zero.
    /// 6. Type names a known [`PacketType`].
    /// 7. Neither address is the all-zero
    ///    [`Address::UNSPECIFIED`] - it is not routable.
    /// 8. Neither address has reserved bit `[0]` set.
    /// 9. Both address type fields are assigned in v0.1
    ///    (private = 1 or public = 2).
    ///
    /// The Payload Length is *read* here but not checked against a packet
    /// boundary - that comparison requires the caller's datagram length,
    /// so [`crate::Packet::parse`] performs it.
    ///
    /// # Errors
    /// Returns the first failed rule as a [`ParseError`].
    pub fn decode(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < BASE_HEADER_LEN {
            return Err(ParseError::Truncated {
                actual: buf.len(),
                required: BASE_HEADER_LEN,
            });
        }
        // Safe from here on: every base-header field is within `buf`.

        let version = buf[OFF_VERSION];
        if version != PROTOCOL_VERSION {
            return Err(ParseError::UnsupportedVersion { found: version });
        }

        let header_len = u16::from_be_bytes([buf[OFF_HEADER_LEN], buf[OFF_HEADER_LEN + 1]]);
        if header_len != BASE_HEADER_LEN as u16 {
            return Err(ParseError::InvalidHeaderLength { found: header_len });
        }

        let flag_bits = u16::from_be_bytes([buf[OFF_FLAGS], buf[OFF_FLAGS + 1]]);
        if flag_bits & !flags::SUPPORTED_MASK != 0 {
            return Err(ParseError::UnsupportedFlags { found: flag_bits });
        }
        let flags = Flags::from_bits_unchecked(flag_bits);

        let reserved = [
            buf[OFF_RESERVED],
            buf[OFF_RESERVED + 1],
            buf[OFF_RESERVED + 2],
        ];
        if reserved != [0, 0, 0] {
            return Err(ParseError::NonZeroReserved { bytes: reserved });
        }

        let type_byte = buf[OFF_TYPE];
        let packet_type = PacketType::from_u8(type_byte)
            .ok_or(ParseError::UnknownPacketType { found: type_byte })?;

        let payload_len = u16::from_be_bytes([buf[OFF_PAYLOAD_LEN], buf[OFF_PAYLOAD_LEN + 1]]);
        let hop_limit = buf[OFF_HOP_LIMIT];

        let mut source = [0u8; 8];
        source.copy_from_slice(&buf[OFF_SOURCE..OFF_SOURCE + 8]);
        let mut destination = [0u8; 8];
        destination.copy_from_slice(&buf[OFF_DESTINATION..OFF_DESTINATION + 8]);

        let packet_id = u32::from_be_bytes([
            buf[OFF_PACKET_ID],
            buf[OFF_PACKET_ID + 1],
            buf[OFF_PACKET_ID + 2],
            buf[OFF_PACKET_ID + 3],
        ]);

        let source = Address::from_octets(source);
        let destination = Address::from_octets(destination);
        validate_address(source, AddressRole::Source)?;
        validate_address(destination, AddressRole::Destination)?;

        Ok(Self {
            packet_type,
            flags,
            payload_len,
            hop_limit,
            source,
            destination,
            packet_id,
        })
    }
}

/// Applies the v0.1 routability rules to a header address field.
///
/// Order: the all-zero unspecified address is reported as such; any
/// other address must have a clear reserved bit and an assigned type
/// (private or public - this also rejects reserved type 0 with a
/// nonzero value).
fn validate_address(addr: Address, role: AddressRole) -> Result<(), ParseError> {
    if addr.is_unspecified() {
        return Err(ParseError::UnspecifiedAddress { role });
    }
    if addr.has_reserved_bit() {
        return Err(ParseError::AddressReservedBitSet { role });
    }
    match addr.address_type() {
        AddressType::Private | AddressType::Public => Ok(()),
        other => Err(ParseError::UnsupportedAddressType {
            role,
            found: other.to_bits(),
        }),
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("packet_type", &self.packet_type)
            .field("flags", &self.flags)
            .field("header_len", &self.header_len())
            .field("payload_len", &self.payload_len)
            .field("hop_limit", &self.hop_limit)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("packet_id", &self.packet_id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_HOP_LIMIT;

    fn sample_header() -> Header {
        Header::new(
            PacketType::Data,
            Address::new(AddressType::Private, 0x1111),
            Address::new(AddressType::Public, 0x2222),
            0xdead_beef,
            DEFAULT_HOP_LIMIT,
            7,
        )
    }

    #[test]
    fn wire_layout_byte_offsets() {
        // Pin the exact field offsets of the provisional format. If this
        // test breaks, the wire format changed - update the spec, not the
        // test.
        let buf = sample_header().to_bytes();
        assert_eq!(buf[0], 1); // version
        assert_eq!(buf[1], 0x01); // DATA
        assert_eq!(&buf[2..4], &[0, 0]); // flags
        assert_eq!(&buf[4..6], &[0, 32]); // header len
        assert_eq!(&buf[6..8], &[0, 7]); // payload len
        assert_eq!(buf[8], DEFAULT_HOP_LIMIT);
        assert_eq!(&buf[9..12], &[0, 0, 0]); // reserved
                                             // source = type 1 (private) | value 0x1111 << 1
        let src = (0x2000_0000_0000_0000u64 | (0x1111u64 << 1)).to_be_bytes();
        assert_eq!(&buf[12..20], &src);
        // destination = type 2 (public) | value 0x2222 << 1
        let dst = (0x4000_0000_0000_0000u64 | (0x2222u64 << 1)).to_be_bytes();
        assert_eq!(&buf[20..28], &dst);
        assert_eq!(&buf[28..32], &0xdead_beef_u32.to_be_bytes());
    }

    #[test]
    fn encode_rejects_small_buffer() {
        let mut buf = [0u8; BASE_HEADER_LEN - 1];
        assert_eq!(
            sample_header().encode(&mut buf),
            Err(EncodeError::BufferTooSmall {
                required: BASE_HEADER_LEN,
                available: BASE_HEADER_LEN - 1
            })
        );
        // Buffer left unmodified on failure.
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn decode_roundtrip() {
        let header = sample_header();
        let decoded = Header::decode(&header.to_bytes()).unwrap();
        assert_eq!(decoded, header);
    }

    #[test]
    fn decode_extra_trailing_bytes_ok() {
        // decode() reads only the header; the packet-level length check is
        // Packet::parse's job.
        let mut buf = sample_header().to_bytes().to_vec();
        buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7]);
        assert!(Header::decode(&buf).is_ok());
    }

    #[test]
    fn rejects_unspecified_addresses() {
        // Zero source address.
        let mut buf = sample_header().to_bytes();
        buf[OFF_SOURCE..OFF_SOURCE + 8].fill(0);
        assert_eq!(
            Header::decode(&buf),
            Err(ParseError::UnspecifiedAddress {
                role: AddressRole::Source
            })
        );

        // Zero destination address.
        let mut buf = sample_header().to_bytes();
        buf[OFF_DESTINATION..OFF_DESTINATION + 8].fill(0);
        assert_eq!(
            Header::decode(&buf),
            Err(ParseError::UnspecifiedAddress {
                role: AddressRole::Destination
            })
        );

        // Both zero: source is reported first.
        let mut buf = sample_header().to_bytes();
        buf[OFF_SOURCE..OFF_DESTINATION + 8].fill(0);
        assert_eq!(
            Header::decode(&buf),
            Err(ParseError::UnspecifiedAddress {
                role: AddressRole::Source
            })
        );
    }

    #[test]
    fn rejects_address_reserved_bit() {
        for (last, role) in [
            (OFF_SOURCE + 7, AddressRole::Source),
            (OFF_DESTINATION + 7, AddressRole::Destination),
        ] {
            let mut buf = sample_header().to_bytes();
            buf[last] |= 0x01;
            assert_eq!(
                Header::decode(&buf),
                Err(ParseError::AddressReservedBitSet { role })
            );
        }
    }

    #[test]
    fn rejects_unsupported_address_types() {
        // Type 3 on the source field (top three bits of byte 12).
        let mut buf = sample_header().to_bytes();
        buf[OFF_SOURCE] |= 0x60;
        assert_eq!(
            Header::decode(&buf),
            Err(ParseError::UnsupportedAddressType {
                role: AddressRole::Source,
                found: 3
            })
        );

        // Type 0 with a nonzero value: representable, but not routable.
        let mut buf = sample_header().to_bytes();
        buf[OFF_SOURCE..OFF_SOURCE + 8].fill(0);
        buf[OFF_SOURCE + 7] = 0x02;
        assert_eq!(
            Header::decode(&buf),
            Err(ParseError::UnsupportedAddressType {
                role: AddressRole::Source,
                found: 0
            })
        );
    }

    #[test]
    fn rejects_every_short_len() {
        let buf = sample_header().to_bytes();
        for len in 0..BASE_HEADER_LEN {
            assert_eq!(
                Header::decode(&buf[..len]),
                Err(ParseError::Truncated {
                    actual: len,
                    required: BASE_HEADER_LEN
                }),
                "len {len} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_bad_version() {
        let mut buf = sample_header().to_bytes();
        for bad in [0u8, 2, 0xff] {
            buf[0] = bad;
            assert_eq!(
                Header::decode(&buf),
                Err(ParseError::UnsupportedVersion { found: bad })
            );
        }
    }

    #[test]
    fn rejects_bad_header_len() {
        for bad in [0u16, 31, 33, 48, u16::MAX] {
            let mut buf = sample_header().to_bytes();
            buf[4..6].copy_from_slice(&bad.to_be_bytes());
            assert_eq!(
                Header::decode(&buf),
                Err(ParseError::InvalidHeaderLength { found: bad })
            );
        }
    }

    #[test]
    fn rejects_any_flag_bit() {
        for bit in 0..16 {
            let mut buf = sample_header().to_bytes();
            let bits = 1u16 << bit;
            buf[2..4].copy_from_slice(&bits.to_be_bytes());
            assert_eq!(
                Header::decode(&buf),
                Err(ParseError::UnsupportedFlags { found: bits })
            );
        }
    }

    #[test]
    fn rejects_nonzero_reserved() {
        for off in OFF_RESERVED..OFF_RESERVED + 3 {
            let mut buf = sample_header().to_bytes();
            buf[off] = 0xaa;
            let mut expected = [0u8; 3];
            expected[off - OFF_RESERVED] = 0xaa;
            assert_eq!(
                Header::decode(&buf),
                Err(ParseError::NonZeroReserved { bytes: expected })
            );
        }
    }

    #[test]
    fn rejects_unknown_type() {
        for bad in [0x00u8, 0x06, 0x80, 0xff] {
            let mut buf = sample_header().to_bytes();
            buf[1] = bad;
            assert_eq!(
                Header::decode(&buf),
                Err(ParseError::UnknownPacketType { found: bad })
            );
        }
    }

    #[test]
    fn accepts_all_defined_types() {
        for ty in [
            PacketType::Data,
            PacketType::EchoRequest,
            PacketType::EchoReply,
            PacketType::Error,
            PacketType::Control,
        ] {
            let mut buf = sample_header().to_bytes();
            buf[1] = ty.to_u8();
            assert_eq!(Header::decode(&buf).unwrap().packet_type(), ty);
        }
    }
}
