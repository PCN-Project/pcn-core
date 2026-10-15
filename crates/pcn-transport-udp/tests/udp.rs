//! Integration tests for `UdpTransport`: real UDP loopback carries real
//! `pcn-packet` datagrams byte-exact.
//!
//! The reference datagram below is built with the public `pcn-packet`
//! builder rather than copying `reference_wire()` from
//! `crates/pcn-packet/tests/wire.rs`: that helper is private to the
//! other crate's test module, and `encodes_to_reference_layout` already
//! proves the builder emits those exact bytes - so building here is the
//! least invasive way to carry the same wire image.

use pcn_address::{Address, AddressType};
use pcn_packet::{Packet, PacketType, MAX_PACKET_LEN};
use pcn_transport::Transport;
use pcn_transport_udp::UdpTransport;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

fn loopback_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn loopback_v6() -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)
}

/// The wire image matching `reference_wire()` in `pcn-packet`'s test
/// suite: ECHO_REQUEST, private src value 1, public dst value 2,
/// hop limit 64, packet id 0xabcd_1234, payload `pong`.
fn reference_datagram() -> Vec<u8> {
    let src = Address::new(AddressType::Private, 1);
    let dst = Address::new(AddressType::Public, 2);
    Packet::builder(PacketType::EchoRequest, src, dst)
        .hop_limit(0x40)
        .packet_id(0xabcd_1234)
        .payload(b"pong".to_vec())
        .build()
        .unwrap()
        .encode()
}

#[test]
fn sends_and_receives_datagram() {
    let sender = UdpTransport::bind(loopback_v4()).unwrap();
    let receiver = UdpTransport::bind(loopback_v4()).unwrap();
    let receiver_addr = receiver.local_endpoint().unwrap();
    let sender_addr = sender.local_endpoint().unwrap();

    let sent = sender.send_to(b"hello pcn", &receiver_addr).unwrap();
    assert_eq!(sent, 9);

    let mut buf = [0u8; 256];
    let (n, from) = receiver.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello pcn");
    // The reported endpoint is the sender's real bound address.
    assert_eq!(from, sender_addr);
}

#[test]
fn carries_reference_pcn_datagram() {
    let sender = UdpTransport::bind(loopback_v4()).unwrap();
    let receiver = UdpTransport::bind(loopback_v4()).unwrap();
    let receiver_addr = receiver.local_endpoint().unwrap();

    let datagram = reference_datagram();
    assert_eq!(
        sender.send_to(&datagram, &receiver_addr).unwrap(),
        datagram.len()
    );

    let mut buf = vec![0u8; MAX_PACKET_LEN];
    let (n, from) = receiver.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], datagram.as_slice());
    assert_eq!(from, sender.local_endpoint().unwrap());

    // The bytes the transport moved parse cleanly as a PCN packet.
    let packet = Packet::parse(&buf[..n]).unwrap();
    let h = packet.header();
    assert_eq!(h.packet_type(), PacketType::EchoRequest);
    assert_eq!(h.hop_limit(), 0x40);
    assert_eq!(h.packet_id(), 0xabcd_1234);
    assert_eq!(packet.payload(), b"pong");
}

#[test]
fn recv_times_out_with_no_datagram() {
    let receiver = UdpTransport::bind(loopback_v4()).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();

    let mut buf = [0u8; 64];
    let err = receiver.recv_from(&mut buf).unwrap_err();
    // Platform-dependent kind: Linux reports WouldBlock, other
    // platforms may report TimedOut. Either signals receive expiry.
    assert!(
        matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ),
        "expected a timeout-kind error, got {err:?}"
    );
}

#[test]
fn clearing_timeout_restores_unbounded_receive() {
    let receiver = UdpTransport::bind(loopback_v4()).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert_eq!(
        receiver.read_timeout().unwrap(),
        Some(Duration::from_millis(100))
    );

    receiver.set_read_timeout(None).unwrap();
    assert_eq!(receiver.read_timeout().unwrap(), None);
    // No recv_from here: with no timeout it would block forever.
}

#[test]
fn ipv6_loopback_roundtrip() {
    // Graceful skip where IPv6 loopback is unavailable.
    let sender = match UdpTransport::bind(loopback_v6()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skipping: IPv6 loopback bind failed ({e})");
            return;
        }
    };
    let receiver = match UdpTransport::bind(loopback_v6()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skipping: IPv6 loopback bind failed ({e})");
            return;
        }
    };
    let receiver_addr = receiver.local_endpoint().unwrap();

    sender.send_to(&[1, 2, 3], &receiver_addr).unwrap();
    let mut buf = [0u8; 16];
    let (n, from) = receiver.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], &[1, 2, 3]);
    assert_eq!(from, sender.local_endpoint().unwrap());
}
