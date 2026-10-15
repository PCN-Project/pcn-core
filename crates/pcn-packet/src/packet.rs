//! A complete packet: validated header plus payload.

use crate::{
    Address, AddressRole, AddressType, BuildError, EncodeError, Header, PacketType, ParseError,
    BASE_HEADER_LEN, DEFAULT_HOP_LIMIT, MAX_PACKET_LEN, MAX_PAYLOAD_LEN,
};
use core::fmt;

/// A PCN protocol v0.1 packet.
///
/// A `Packet` is always well-formed: it can only be produced by
/// [`Packet::parse`] (which validates the whole datagram) or
/// [`Packet::builder`] (which enforces the size limits at construction).
/// There is no mutable access to header fields - a different packet is a
/// different value, built through the builder.
#[derive(Clone, PartialEq, Eq)]
pub struct Packet {
    header: Header,
    payload: Vec<u8>,
}

impl Packet {
    /// Starts building a packet of type `packet_type` from `source` to
    /// `destination`.
    ///
    /// Defaults: no flags (none exist), `hop_limit` =
    /// [`DEFAULT_HOP_LIMIT`], `packet_id` = 0, empty payload.
    #[must_use]
    pub fn builder(
        packet_type: PacketType,
        source: Address,
        destination: Address,
    ) -> PacketBuilder {
        PacketBuilder {
            packet_type,
            source,
            destination,
            packet_id: 0,
            hop_limit: DEFAULT_HOP_LIMIT,
            payload: Vec::new(),
        }
    }

    /// The validated header.
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// The packet payload as a byte slice.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Total wire length in bytes: header plus payload.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.header.total_len()
    }

    /// Serializes the packet to its wire encoding.
    ///
    /// The output is deterministic and always exactly
    /// [`wire_len`](Self::wire_len) bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_len());
        buf.extend_from_slice(&self.header.to_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Serializes into a caller-provided buffer, returning the number of
    /// bytes written (always [`wire_len`](Self::wire_len) on success).
    ///
    /// # Errors
    /// Returns [`EncodeError::BufferTooSmall`] if `buf` is shorter than
    /// [`wire_len`](Self::wire_len); the buffer is left unmodified.
    pub fn encode_into(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        if buf.len() < self.wire_len() {
            return Err(EncodeError::BufferTooSmall {
                required: self.wire_len(),
                available: buf.len(),
            });
        }
        // Cannot fail: the slice is exactly BASE_HEADER_LEN.
        let _ = self.header.encode(&mut buf[..BASE_HEADER_LEN]);
        buf[BASE_HEADER_LEN..self.wire_len()].copy_from_slice(&self.payload);
        Ok(self.wire_len())
    }

    /// Parses and validates a complete datagram.
    ///
    /// In addition to the header checks in [`Header::decode`] (including
    /// rejection of unspecified source/destination addresses), this
    /// verifies that the declared total length
    /// (`Header Length + Payload Length`, computed without overflow)
    /// equals the number of bytes actually received and does not exceed
    /// [`MAX_PACKET_LEN`].
    ///
    /// The returned packet owns a copy of the payload. Allocation size is
    /// bounded by `buf.len()`, never by an unverified length field.
    ///
    /// # Errors
    /// Returns the first failed rule as a [`ParseError`].
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        let header = Header::decode(buf)?;

        // usize arithmetic: declared cannot overflow (max 32 + 65535).
        let declared = header.total_len();
        if declared != buf.len() {
            return Err(ParseError::LengthMismatch {
                declared,
                actual: buf.len(),
            });
        }
        if declared > MAX_PACKET_LEN {
            return Err(ParseError::PacketTooLarge { declared });
        }

        let payload = buf[header.header_len() as usize..].to_vec();
        Ok(Self { header, payload })
    }

    /// Convenience constructor for an [`PacketType::EchoRequest`].
    ///
    /// # Errors
    /// Returns [`BuildError::PayloadTooLarge`] if `payload` exceeds
    /// [`MAX_PAYLOAD_LEN`], or an address error
    /// ([`BuildError::UnspecifiedAddress`],
    /// [`BuildError::AddressReservedBitSet`],
    /// [`BuildError::UnsupportedAddressType`]) if an address is not
    /// routable in v0.1.
    pub fn echo_request(
        source: Address,
        destination: Address,
        packet_id: u32,
        payload: &[u8],
    ) -> Result<Self, BuildError> {
        Self::builder(PacketType::EchoRequest, source, destination)
            .packet_id(packet_id)
            .payload(payload)
            .build()
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("header", &self.header)
            .field("payload", &format_args!("{} bytes", self.payload.len()))
            .finish()
    }
}

/// Builder for [`Packet`], created by [`Packet::builder`].
#[derive(Debug, Clone)]
pub struct PacketBuilder {
    packet_type: PacketType,
    source: Address,
    destination: Address,
    packet_id: u32,
    hop_limit: u8,
    payload: Vec<u8>,
}

impl PacketBuilder {
    /// Sets the Packet ID field.
    #[must_use]
    pub const fn packet_id(mut self, packet_id: u32) -> Self {
        self.packet_id = packet_id;
        self
    }

    /// Sets the Hop Limit field.
    #[must_use]
    pub const fn hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = hop_limit;
        self
    }

    /// Sets the payload.
    #[must_use]
    pub fn payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Builds the packet.
    ///
    /// # Errors
    /// * [`BuildError::PayloadTooLarge`] - the payload does not fit in the
    ///   16-bit Payload Length field or the packet would exceed
    ///   [`MAX_PACKET_LEN`].
    /// * [`BuildError::UnspecifiedAddress`],
    ///   [`BuildError::AddressReservedBitSet`],
    ///   [`BuildError::UnsupportedAddressType`] - source or destination
    ///   is not routable in v0.1 (only private and public addresses with
    ///   a clear reserved bit are), mirroring the parse-side rules so a
    ///   built packet always survives `parse`.
    pub fn build(self) -> Result<Packet, BuildError> {
        check_address(self.source, AddressRole::Source)?;
        check_address(self.destination, AddressRole::Destination)?;
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(BuildError::PayloadTooLarge {
                len: self.payload.len(),
                max: MAX_PAYLOAD_LEN,
            });
        }
        // len <= u16::MAX is guaranteed by the check above, since
        // MAX_PAYLOAD_LEN < u16::MAX.
        let header = Header::new(
            self.packet_type,
            self.source,
            self.destination,
            self.packet_id,
            self.hop_limit,
            self.payload.len() as u16,
        );
        Ok(Packet {
            header,
            payload: self.payload,
        })
    }
}

/// Applies the v0.1 routability rules to an address given to the
/// builder, mirroring `Header::decode`.
fn check_address(addr: Address, role: AddressRole) -> Result<(), BuildError> {
    if addr.is_unspecified() {
        return Err(BuildError::UnspecifiedAddress { role });
    }
    if addr.has_reserved_bit() {
        return Err(BuildError::AddressReservedBitSet { role });
    }
    match addr.address_type() {
        AddressType::Private | AddressType::Public => Ok(()),
        other => Err(BuildError::UnsupportedAddressType {
            role,
            found: other.to_bits(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Flags;

    fn src() -> Address {
        Address::new(AddressType::Private, 0xaaaa)
    }
    fn dst() -> Address {
        Address::new(AddressType::Public, 0xbbbb)
    }

    #[test]
    fn build_encode_parse_roundtrip() {
        let packet = Packet::builder(PacketType::Data, src(), dst())
            .packet_id(0x0102_0304)
            .hop_limit(32)
            .payload(b"hello pcn".to_vec())
            .build()
            .unwrap();

        let wire = packet.encode();
        assert_eq!(wire.len(), packet.wire_len());
        assert_eq!(wire.len(), BASE_HEADER_LEN + 9);

        let parsed = Packet::parse(&wire).unwrap();
        assert_eq!(parsed, packet);
        assert_eq!(parsed.header().packet_type(), PacketType::Data);
        assert_eq!(parsed.header().packet_id(), 0x0102_0304);
        assert_eq!(parsed.header().hop_limit(), 32);
        assert_eq!(parsed.header().flags(), Flags::NONE);
        assert_eq!(parsed.header().source(), src());
        assert_eq!(parsed.header().destination(), dst());
        assert_eq!(parsed.payload(), b"hello pcn");
    }

    #[test]
    fn empty_payload_roundtrip() {
        let packet = Packet::builder(PacketType::EchoReply, src(), dst())
            .build()
            .unwrap();
        assert_eq!(packet.wire_len(), BASE_HEADER_LEN);
        assert_eq!(Packet::parse(&packet.encode()).unwrap(), packet);
    }

    #[test]
    fn max_payload_roundtrip() {
        let payload = vec![0x5a_u8; MAX_PAYLOAD_LEN];
        let packet = Packet::builder(PacketType::Data, src(), dst())
            .payload(payload.clone())
            .build()
            .unwrap();
        assert_eq!(packet.wire_len(), MAX_PACKET_LEN);
        let parsed = Packet::parse(&packet.encode()).unwrap();
        assert_eq!(parsed.payload(), payload.as_slice());
    }

    #[test]
    fn builder_rejects_oversized_payload() {
        let too_big = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert!(matches!(
            Packet::builder(PacketType::Data, src(), dst())
                .payload(too_big)
                .build(),
            Err(BuildError::PayloadTooLarge { len, max })
                if len == MAX_PAYLOAD_LEN + 1 && max == MAX_PAYLOAD_LEN
        ));
    }

    #[test]
    fn parse_rejects_length_mismatch() {
        let wire = Packet::builder(PacketType::Data, src(), dst())
            .payload(vec![1, 2, 3])
            .build()
            .unwrap()
            .encode();

        // Trailing garbage: declared stays 35, actual is 37.
        let mut padded = wire.clone();
        padded.extend_from_slice(&[0, 0]);
        assert_eq!(
            Packet::parse(&padded),
            Err(ParseError::LengthMismatch {
                declared: wire.len(),
                actual: wire.len() + 2
            })
        );

        // Truncated payload: declared 35, actual 34.
        assert_eq!(
            Packet::parse(&wire[..wire.len() - 1]),
            Err(ParseError::LengthMismatch {
                declared: wire.len(),
                actual: wire.len() - 1
            })
        );
    }

    #[test]
    fn parse_rejects_oversized_declared() {
        // header_len 32 + payload_len 65535 = 65567 > MAX_PACKET_LEN.
        // Supply a matching-length buffer so the PacketTooLarge branch is
        // what fires, not LengthMismatch.
        let mut buf = Packet::builder(PacketType::Data, src(), dst())
            .build()
            .unwrap()
            .encode();
        buf[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        buf.resize(BASE_HEADER_LEN + u16::MAX as usize, 0);
        assert_eq!(
            Packet::parse(&buf),
            Err(ParseError::PacketTooLarge {
                declared: BASE_HEADER_LEN + u16::MAX as usize
            })
        );
    }

    #[test]
    fn parse_rejects_header_errors_before_payload() {
        // A truncated datagram must report Truncated, never attempt reads.
        assert_eq!(
            Packet::parse(&[]),
            Err(ParseError::Truncated {
                actual: 0,
                required: BASE_HEADER_LEN
            })
        );
        assert!(matches!(
            Packet::parse(&[0u8; 10]),
            Err(ParseError::Truncated { .. })
        ));
    }

    #[test]
    fn encode_into_writes_exactly() {
        let packet = Packet::builder(PacketType::Control, src(), dst())
            .payload(vec![9; 4])
            .build()
            .unwrap();
        let mut buf = vec![0xff_u8; packet.wire_len() + 8];
        assert_eq!(packet.encode_into(&mut buf), Ok(packet.wire_len()));
        assert_eq!(&buf[..packet.wire_len()], packet.encode().as_slice());
        // Bytes past wire_len are untouched.
        assert!(buf[packet.wire_len()..].iter().all(|&b| b == 0xff));
    }

    #[test]
    fn encode_into_rejects_small_buffer() {
        let packet = Packet::builder(PacketType::Control, src(), dst())
            .payload(vec![9; 4])
            .build()
            .unwrap();
        let mut buf = vec![0u8; packet.wire_len() - 1];
        assert_eq!(
            packet.encode_into(&mut buf),
            Err(EncodeError::BufferTooSmall {
                required: packet.wire_len(),
                available: packet.wire_len() - 1
            })
        );
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn builder_rejects_unspecified_addresses() {
        assert_eq!(
            Packet::builder(PacketType::Data, Address::UNSPECIFIED, dst()).build(),
            Err(BuildError::UnspecifiedAddress {
                role: AddressRole::Source
            })
        );
        assert_eq!(
            Packet::builder(PacketType::Data, src(), Address::UNSPECIFIED).build(),
            Err(BuildError::UnspecifiedAddress {
                role: AddressRole::Destination
            })
        );
    }

    #[test]
    fn builder_rejects_non_routable_addresses() {
        // Reserved type 0 with a nonzero value.
        let type0 = Address::new(AddressType::Reserved, 7);
        assert_eq!(
            Packet::builder(PacketType::Data, type0, dst()).build(),
            Err(BuildError::UnsupportedAddressType {
                role: AddressRole::Source,
                found: 0
            })
        );

        // Unsupported type 5.
        let type5 = Address::new(AddressType::Unsupported(5), 1);
        assert_eq!(
            Packet::builder(PacketType::Data, src(), type5).build(),
            Err(BuildError::UnsupportedAddressType {
                role: AddressRole::Destination,
                found: 5
            })
        );

        // Private value 1 with reserved bit 0 set.
        let reserved = Address::from_octets([0x20, 0, 0, 0, 0, 0, 0, 0x03]);
        assert_eq!(
            Packet::builder(PacketType::Data, reserved, dst()).build(),
            Err(BuildError::AddressReservedBitSet {
                role: AddressRole::Source
            })
        );

        // A parsed packet can never carry such addresses either.
        assert!(!type0.is_routable());
        assert!(!type5.is_routable());
        assert!(!reserved.is_routable());
    }

    #[test]
    fn echo_request_helper() {
        let packet = Packet::echo_request(src(), dst(), 42, b"ping").unwrap();
        assert_eq!(packet.header().packet_type(), PacketType::EchoRequest);
        assert_eq!(packet.header().packet_id(), 42);
        assert_eq!(packet.payload(), b"ping");
    }
}
