//! Process-level fault-injection tests for DATA/ACK reliability.
//!
//! A deterministic in-process UDP proxy ([`udp_proxy`]) sits on a path
//! leg and drops, duplicates or delays datagrams - no dependence on
//! real network conditions. All traffic stays on loopback; the sender
//! and receiver are the real `pcn`/`pcnd` binaries.

mod common;

use common::*;
use pcn_address::Address;
use pcn_packet::{Packet, PacketType};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

/// Encodes a DATA packet (handy for sending exact bytes with chosen ids
/// straight to a socket - bypassing `pcn send`'s random ids).
fn data_wire(src: &str, dst: &str, id: u32, payload: &[u8]) -> Vec<u8> {
    Packet::builder(
        PacketType::Data,
        src.parse::<Address>().unwrap(),
        dst.parse::<Address>().unwrap(),
    )
    .packet_id(id)
    .payload(payload)
    .build()
    .unwrap()
    .encode()
}

/// `true` when `wire` is a valid packet of `ty`.
fn is_type(wire: &[u8], ty: PacketType) -> bool {
    Packet::parse(wire).is_ok_and(|p| p.header().packet_type() == ty)
}

/// Extracts the RTT milliseconds from an `acknowledged by ... in X ms`
/// stdout line.
fn acked_rtt_ms(line: &str) -> f64 {
    let rest = line.split(" in ").nth(1).expect("no ' in ' in line");
    rest.split(" ms").next().unwrap().parse().unwrap()
}

/// DATA path: send --retries 1 to a receiver whose return leg drops the
/// FIRST ACK (proxy drops datagram seq 0 = the first ACK B->A).
/// The retry must carry the same packet_id, get delivered as a
/// duplicate, and its ACK must satisfy the send - exit 0 on attempt 2.
#[test]
fn lost_ack_triggers_retry_receiver_dedups() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port, proxy_port) = (free_port(), free_port(), free_port());

    // Return path: B's route to A goes through the fault proxy, which
    // drops the first ACK (seq 0 on this leg) and forwards the retry's.
    let _proxy = udp_proxy(ep(proxy_port), ep(a_port), |seq, _bytes| {
        if seq == 0 {
            Fault::Drop
        } else {
            Fault::Forward
        }
    });
    let b = node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
        "--next-hop".into(),
        format!("1={}", ep(proxy_port)),
        "--route".into(),
        format!("{A_ADDR}=1"),
    ]);
    b.ready(deadline);

    let out = run_pcn(
        "send",
        &[
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--via".into(),
            ep(b_port).to_string(),
            "--message".into(),
            "retry survives".into(),
            "--timeout-ms".into(),
            "400".into(),
            "--retries".into(),
            "2".into(),
        ],
        Duration::from_secs(10),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "retry must recover: {stdout}");
    assert!(stdout.contains("timeout waiting for ACK"), "{stdout}");
    assert!(stdout.contains("acknowledged by"), "{stdout}");
    assert!(stdout.contains("attempt 2/3"), "{stdout}");

    // B saw DATA twice but delivered it once; both got ACKed.
    let first = b.expect_line(deadline, |l| l.starts_with("delivered"));
    assert!(!first.contains("(duplicate)"), "first delivery: {first}");
    b.expect_line(deadline, |l| l.starts_with("acked:"));
    let dup = b.expect_line(deadline, |l| l.starts_with("delivered"));
    assert!(dup.contains("(duplicate)"), "retry must dedup: {dup}");
    b.expect_line(deadline, |l| l.starts_with("acked:"));
}

/// Forward path drops every DATA: bounded retries exhaust, send reports
/// the failure honestly.
#[test]
fn lost_data_reports_timeout_after_bounded_retries() {
    let (a_port, b_port, proxy_port) = (free_port(), free_port(), free_port());

    let _proxy = udp_proxy(ep(proxy_port), ep(b_port), |_seq, bytes| {
        if is_type(bytes, PacketType::Data) {
            Fault::Drop
        } else {
            Fault::Forward
        }
    });
    // B would ACK anything that arrived - nothing does.
    let b = node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
    ]);
    let deadline = Instant::now() + TIMEOUT;
    b.ready(deadline);

    let out = run_pcn(
        "send",
        &[
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--via".into(),
            ep(proxy_port).to_string(),
            "--message".into(),
            "into the void".into(),
            "--timeout-ms".into(),
            "300".into(),
            "--retries".into(),
            "1".into(),
        ],
        Duration::from_secs(10),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "lost DATA must fail: {stdout}");
    assert!(stdout.contains("timeout waiting for ACK"), "{stdout}");
    assert!(stderr.contains("no ACK after 2 attempts"), "{stderr}");
}

/// A forged-looking ACK (correct addresses, WRONG packet_id) injected
/// while a real send is in flight must not satisfy it: the measured RTT
/// must correspond to the real, deliberately delayed ACK - not to the
/// early impostor.
#[test]
fn unrelated_ack_in_flight_is_ignored() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port, proxy_port) = (free_port(), free_port(), free_port());

    // Return leg through a proxy that delays every ACK by 400 ms.
    let _proxy = udp_proxy(ep(proxy_port), ep(a_port), |_seq, bytes| {
        if is_type(bytes, PacketType::Ack) {
            Fault::Delay(Duration::from_millis(400))
        } else {
            Fault::Forward
        }
    });
    let b = node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
        "--next-hop".into(),
        format!("1={}", ep(proxy_port)),
        "--route".into(),
        format!("{A_ADDR}=1"),
    ]);
    b.ready(deadline);

    // Send via Proc (not run_pcn): we inject the impostor mid-flight.
    let send = Proc::spawn(
        "pcn",
        &[
            "send".into(),
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--via".into(),
            ep(b_port).to_string(),
            "--message".into(),
            "impostor".into(),
            "--timeout-ms".into(),
            "1500".into(),
            "--retries".into(),
            "0".into(),
        ],
    );

    // DATA arrived at B -> its (delayed) ACK is now in flight.
    b.expect_line(deadline, |l| l.starts_with("delivered"));
    std::thread::sleep(Duration::from_millis(80));
    // Inject an ACK B->A with a foreign packet_id straight to A's port.
    let forged = Packet::builder(
        PacketType::Ack,
        B_ADDR.parse().unwrap(),
        A_ADDR.parse().unwrap(),
    )
    .packet_id(0xDEAD_BEEF)
    .payload([])
    .build()
    .unwrap()
    .encode();
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(&forged, ep(a_port))
        .unwrap();

    // ~400ms real ACK wins; had the impostor matched, RTT <= ~120 ms.
    let line = send.expect_line(deadline, |l| l.starts_with("acknowledged by"));
    let rtt = acked_rtt_ms(&line);
    assert!(
        rtt > 250.0,
        "rtt {rtt} ms means the forged ACK matched - it must not: {line}"
    );
    assert!(line.contains("attempt 1/1"), "{line}");
}

/// Forward path duplicates each DATA: the receiver prints the message
/// once and marks the copy `(duplicate)` - no double delivery.
#[test]
fn duplicated_data_is_suppressed() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port, proxy_port) = (free_port(), free_port(), free_port());

    let _proxy = udp_proxy(ep(proxy_port), ep(b_port), |_seq, bytes| {
        if is_type(bytes, PacketType::Data) {
            Fault::Duplicate
        } else {
            Fault::Forward
        }
    });
    let recv = Proc::spawn(
        "pcn",
        &[
            "recv".into(),
            "--listen".into(),
            ep(b_port).to_string(),
            "--source".into(),
            B_ADDR.into(),
        ],
    );
    recv.ready(deadline);

    let out = run_pcn(
        "send",
        &[
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--via".into(),
            ep(proxy_port).to_string(),
            "--message".into(),
            "echo echo".into(),
            "--no-ack".into(),
        ],
        Duration::from_secs(10),
    );
    assert!(out.status.success());

    let first = recv.expect_line(deadline, |l| l.starts_with("data from "));
    assert!(first.contains("echo echo"), "{first}");
    assert!(!first.contains("(duplicate)"), "{first}");
    let dup = recv.expect_line(deadline, |l| l.starts_with("data from "));
    assert!(dup.contains("(duplicate)"), "second copy must dedup: {dup}");
    assert!(dup.contains("echo echo"), "{dup}");
}

/// Dedup state lives in memory: a restarted receiver loses it and a
/// re-sent packet (same source+id) is delivered again - this documents
/// that dedup is a same-process guarantee only.
#[test]
fn receiver_restart_loses_dedup_state() {
    let deadline = Instant::now() + TIMEOUT;
    let b_port = free_port();
    let wire = data_wire(A_ADDR, B_ADDR, 0x1234, b"restart me");

    let send = || {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(&wire, ep(b_port))
            .unwrap();
    };

    let b1 = node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
    ]);
    b1.ready(deadline);
    send();
    let l1 = b1.expect_line(deadline, |l| {
        l.starts_with("delivered") && l.contains("id=0x00001234")
    });
    assert!(!l1.contains("(duplicate)"), "{l1}");
    drop(b1); // kill the receiver - in-memory dedup is gone

    // Restart on the same port; same wire bytes.
    std::thread::sleep(Duration::from_millis(50));
    let b2 = node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
    ]);
    b2.ready(deadline);
    send();
    let l2 = b2.expect_line(deadline, |l| {
        l.starts_with("delivered") && l.contains("id=0x00001234")
    });
    // Documented behavior: the replayed packet is NOT a duplicate
    // anymore - dedup does not survive restarts.
    assert!(!l2.contains("(duplicate)"), "dedup survived restart: {l2}");
}

/// Cache is bounded at 4096 keys: once full, it resets - so an evicted
/// old packet redelivers, while the most recent entry still dedups.
/// Proves bounded memory and documents the eviction trade-off.
#[test]
fn dedup_cache_eviction_semantics() {
    const CAP: u32 = 4096;
    let deadline = Instant::now() + Duration::from_secs(30);
    let b_port = free_port();

    let b = node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
    ]);
    b.ready(deadline);

    // Fill the cache: ids 0..=CAP (CAP+1 arrivals -> one eviction past
    // full). Paced in bursts so loopback UDP buffers do not drop them.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut delivered = 0u32;
    let mut sent = 0u32;
    while sent <= CAP {
        let wire = data_wire(A_ADDR, B_ADDR, sent, b"x");
        sock.send_to(&wire, ep(b_port)).unwrap();
        sent += 1;
        if sent % 64 == 0 {
            std::thread::sleep(Duration::from_millis(8));
        }
        // Drain in step with sends so the channel never backs up.
        while delivered < sent {
            b.expect_line(deadline, |l| l.starts_with("delivered"));
            delivered += 1;
        }
    }

    // Newest entry (id=CAP) is still cached -> marked duplicate.
    sock.send_to(&data_wire(A_ADDR, B_ADDR, CAP, b"x"), ep(b_port))
        .unwrap();
    let dup = b.expect_line(deadline, |l| {
        l.starts_with("delivered") && l.contains("id=0x00001000")
    });
    assert!(dup.contains("(duplicate)"), "newest must dedup: {dup}");

    // Oldest entry (id=0) was evicted -> delivered again, no marker.
    sock.send_to(&data_wire(A_ADDR, B_ADDR, 0, b"x"), ep(b_port))
        .unwrap();
    let old = b.expect_line(deadline, |l| {
        l.starts_with("delivered") && l.contains("id=0x00000000")
    });
    assert!(
        !old.contains("(duplicate)"),
        "evicted id must redeliver: {old}"
    );
}
