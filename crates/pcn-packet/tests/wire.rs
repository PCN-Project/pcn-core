//! Public-API integration tests for the v0.1 wire format.
//!
//! These exercise the crate exactly as an external consumer (transport,
//! daemon, foreign implementation) would: build -> encode -> bytes on the
//! wire -> parse -> fields. Unit tests inside the modules cover the
//! field-by-field validation rules.

use pcn_address::{Address, AddressType};
use pcn_packet::{
    BuildError, Packet, PacketType, ParseError, BASE_HEADER_LEN, MAX_PACKET_LEN, MAX_PAYLOAD_LEN,
    PROTOCOL_VERSION,
};

/// `pcn~1000-0000-00002` - private type, value 1.
fn src() -> Address {
    Address::new(AddressType::Private, 1)
}

/// `pcn~2000-0000-00004` - public type, value 2.
fn dst() -> Address {
    Address::new(AddressType::Public, 2)
}

/// A hand-constructed reference datagram, byte for byte, matching the
/// specification table. Independent of the implementation's encoder, so
/// a wrong offset breaks this test rather than silently agreeing.
fn reference_wire() -> Vec<u8> {
    let mut buf = Vec::with_capacity(BASE_HEADER_LEN + 4);
    buf.push(PROTOCOL_VERSION);
    buf.push(0x02); // ECHO_REQUEST
    buf.extend_from_slice(&[0x00, 0x00]); // flags
    buf.extend_from_slice(&32u16.to_be_bytes()); // header len
    buf.extend_from_slice(&4u16.to_be_bytes()); // payload len
    buf.push(0x40); // hop limit
    buf.extend_from_slice(&[0, 0, 0]); // reserved
                                       // source: type 1 (private) | value 1 << 1 = 0x2000..0002
    buf.extend_from_slice(&[0x20, 0, 0, 0, 0, 0, 0, 0x02]);
    // destination: type 2 (public) | value 2 << 1 = 0x4000..0004
    buf.extend_from_slice(&[0x40, 0, 0, 0, 0, 0, 0, 0x04]);
    buf.extend_from_slice(&0xabcd_1234u32.to_be_bytes()); // packet id
    buf.extend_from_slice(b"pong");
    buf
}

#[test]
fn parses_reference_datagram() {
    let packet = Packet::parse(&reference_wire()).unwrap();
    let h = packet.header();
    assert_eq!(h.packet_type(), PacketType::EchoRequest);
    assert_eq!(h.header_len(), 32);
    assert_eq!(h.payload_len(), 4);
    assert_eq!(h.hop_limit(), 0x40);
    assert_eq!(h.source(), src());
    assert_eq!(h.destination(), dst());
    assert_eq!(h.packet_id(), 0xabcd_1234);
    assert_eq!(packet.payload(), b"pong");
}

#[test]
fn encodes_to_reference_layout() {
    let packet = Packet::builder(PacketType::EchoRequest, src(), dst())
        .hop_limit(0x40)
        .packet_id(0xabcd_1234)
        .payload(b"pong".to_vec())
        .build()
        .unwrap();
    assert_eq!(packet.encode(), reference_wire());
}

#[test]
fn full_roundtrip_every_type() {
    for ty in [
        PacketType::Data,
        PacketType::EchoRequest,
        PacketType::EchoReply,
        PacketType::Error,
        PacketType::Control,
    ] {
        let packet = Packet::builder(ty, src(), dst())
            .payload(vec![0x77; 100])
            .build()
            .unwrap();
        assert_eq!(Packet::parse(&packet.encode()).unwrap(), packet);
    }
}

#[test]
fn rejects_mutated_datagrams() {
    let good = reference_wire();

    // Flip each reserved byte.
    for i in 9..12 {
        let mut bad = good.clone();
        bad[i] = 1;
        assert!(matches!(
            Packet::parse(&bad),
            Err(ParseError::NonZeroReserved { .. })
        ));
    }

    // Every flag bit.
    for bit in 0..16 {
        let mut bad = good.clone();
        let bits = 1u16 << bit;
        bad[2..4].copy_from_slice(&bits.to_be_bytes());
        assert!(matches!(
            Packet::parse(&bad),
            Err(ParseError::UnsupportedFlags { .. })
        ));
    }

    // Unknown type.
    let mut bad = good.clone();
    bad[1] = 0x7f;
    assert!(matches!(
        Packet::parse(&bad),
        Err(ParseError::UnknownPacketType { found: 0x7f })
    ));

    // Future version.
    let mut bad = good.clone();
    bad[0] = 2;
    assert!(matches!(
        Packet::parse(&bad),
        Err(ParseError::UnsupportedVersion { found: 2 })
    ));

    // Zeroed source address (offset 12..20 in the 32-byte header).
    let mut bad = good.clone();
    bad[12..20].fill(0);
    assert!(matches!(
        Packet::parse(&bad),
        Err(ParseError::UnspecifiedAddress { .. })
    ));

    // Reserved bit 0 of the destination address set.
    let mut bad = good.clone();
    bad[27] |= 0x01;
    assert!(matches!(
        Packet::parse(&bad),
        Err(ParseError::AddressReservedBitSet { .. })
    ));

    // Reserved address type 3 in the source field (bits 63:61).
    let mut bad = good.clone();
    bad[12] |= 0x60;
    assert!(matches!(
        Packet::parse(&bad),
        Err(ParseError::UnsupportedAddressType { found: 3, .. })
    ));
}

#[test]
fn length_boundaries() {
    // Empty payload is legal.
    let p = Packet::builder(PacketType::Control, src(), dst())
        .build()
        .unwrap();
    assert_eq!(p.wire_len(), BASE_HEADER_LEN);

    // Maximum legal packet.
    let p = Packet::builder(PacketType::Data, src(), dst())
        .payload(vec![0; MAX_PAYLOAD_LEN])
        .build()
        .unwrap();
    assert_eq!(p.wire_len(), MAX_PACKET_LEN);

    // One byte over the limit is a build error, not a silent truncation.
    assert!(matches!(
        Packet::builder(PacketType::Data, src(), dst())
            .payload(vec![0; MAX_PAYLOAD_LEN + 1])
            .build(),
        Err(BuildError::PayloadTooLarge { .. })
    ));
}
