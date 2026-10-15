//! End-to-end tests for `pcn send`/`pcn recv`: real `pcn` client
//! processes and `pcnd` nodes exchanging PCN DATA packets over UDP
//! loopback. The process harness lives in `tests/common/`.

mod common;

use common::*;
use std::time::{Duration, Instant};

const MSG: &str = "Zażółć gęślą jaźń - PCN działa";

/// Third address: destination with no route, or foreign destination
/// sharing B's socket.
const C_ADDR: &str = "pcn~1000-0000-00003";

/// A -> R1 -> B(recv): the message payload must arrive byte-exact,
/// and R1's log must show the transit forward with a decremented
/// hop limit.
#[test]
fn data_message_crosses_router_exactly() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, r1_port, b_port) = (free_port(), free_port(), free_port());

    // B: `pcn recv` bound to b_port; --via R1 is its first hop for ACKs.
    let recv = Proc::spawn(
        "pcn",
        &[
            "recv".into(),
            "--listen".into(),
            ep(b_port).to_string(),
            "--source".into(),
            B_ADDR.into(),
            "--via".into(),
            ep(r1_port).to_string(),
        ],
    );
    // R1: static routes in both directions - DATA to B, ACK back to A.
    let r1 = node(&[
        "--listen".into(),
        ep(r1_port).to_string(),
        "--address".into(),
        R1_ADDR.into(),
        "--next-hop".into(),
        format!("1={}", ep(b_port)),
        "--route".into(),
        format!("{B_ADDR}=1"),
        "--next-hop".into(),
        format!("2={}", ep(a_port)),
        "--route".into(),
        format!("{A_ADDR}=2"),
    ]);
    recv.ready(deadline);
    r1.ready(deadline);

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
            ep(r1_port).to_string(),
            "--message".into(),
            MSG.into(),
        ],
        Duration::from_secs(10),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "send failed: {stdout}{stderr}");
    // Exit 0 required a matching ACK from the destination endpoint.
    assert!(stdout.contains("acknowledged by"), "{stdout}");

    // Transit proof at the router in BOTH directions: DATA A->B, then
    // the ACK B->A - no shortcut back to the UDP sender.
    let fwd = r1.expect_line(deadline, |l| {
        l.starts_with("forwarded:") && l.contains(A_ADDR) && l.contains(B_ADDR)
    });
    assert!(fwd.contains("hop_limit 63"), "{fwd}");
    let fwd_back = r1.expect_line(deadline, |l| {
        l.starts_with("forwarded:") && l.contains(B_ADDR) && l.contains(A_ADDR)
    });
    assert!(fwd_back.contains("hop_limit 63"), "{fwd_back}");

    // Application-facing delivery: exact UTF-8 payload, correct sender.
    let line = recv.expect_line(deadline, |l| l.starts_with("data from "));
    assert!(line.contains(MSG), "payload mangled: {line}");
    assert!(line.contains(A_ADDR), "{line}");
}

/// A -> B(pcnd): the node logs `delivered:` with the payload - the
/// local application-facing interface for this stage.
#[test]
fn pcnd_delivers_data_payload() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port) = (free_port(), free_port());

    // B: node with a route back to A, so its ACK can be routed.
    let b = node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
        "--next-hop".into(),
        format!("1={}", ep(a_port)),
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
            "direct data".into(),
        ],
        Duration::from_secs(10),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("acknowledged by"), "{stdout}");

    let line = b.expect_line(deadline, |l| l.starts_with("delivered:"));
    assert!(line.contains("type=DATA"), "{line}");
    assert!(line.contains("\"direct data\""), "payload missing: {line}");
    // The node originated and routed an ACK back to the sender.
    let acked = b.expect_line(deadline, |l| l.starts_with("acked:"));
    assert!(acked.contains(B_ADDR), "{acked}");
    assert!(acked.contains(A_ADDR), "{acked}");
}

/// DATA for an unrouted destination dies at the router - never
/// bounced to the sender's UDP endpoint, never silently lost in a log.
#[test]
fn unrouted_data_is_dropped_at_router() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, r1_port) = (free_port(), free_port());

    let r1 = node(&[
        "--listen".into(),
        ep(r1_port).to_string(),
        "--address".into(),
        R1_ADDR.into(),
    ]);
    r1.ready(deadline);

    let out = run_pcn(
        "send",
        &[
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            C_ADDR.into(),
            "--via".into(),
            ep(r1_port).to_string(),
            "--message".into(),
            "nowhere".into(),
            "--no-ack".into(),
        ],
        Duration::from_secs(10),
    );
    // --no-ack: send() only promises the datagram left the socket.
    assert!(out.status.success());

    let drop_line = r1.expect_line(deadline, |l| {
        l.starts_with("dropped (") && l.contains("no route") && l.contains(C_ADDR)
    });
    assert!(drop_line.contains(A_ADDR), "{drop_line}");
}

/// An oversized --message is rejected before any datagram is sent.
#[test]
fn send_rejects_oversized_message() {
    let out = run_pcn(
        "send",
        &[
            "--listen".into(),
            "127.0.0.1:0".into(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--via".into(),
            "127.0.0.1:9".into(),
            "--message".into(),
            "x".repeat(70_000),
        ],
        Duration::from_secs(10),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "oversized send must fail");
    assert!(
        stderr.contains("payload") || stderr.contains("exceeds"),
        "{stderr}"
    );
}

/// `pcn recv` reports only DATA for its own address: a valid packet to
/// another destination on the same socket is consumed silently.
#[test]
fn recv_ignores_foreign_destinations() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port) = (free_port(), free_port());

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

    // A valid DATA packet for C arrives at B's socket first.
    let out = run_pcn(
        "send",
        &[
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            C_ADDR.into(),
            "--via".into(),
            ep(b_port).to_string(),
            "--message".into(),
            "not for you".into(),
            "--no-ack".into(),
        ],
        Duration::from_secs(10),
    );
    assert!(out.status.success());

    // Then the real one for B. If recv had printed the foreign packet,
    // expect_line would have consumed that line instead.
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
            "for you".into(),
            "--no-ack".into(),
        ],
        Duration::from_secs(10),
    );
    assert!(out.status.success());

    let line = recv.expect_line(deadline, |l| l.starts_with("data from "));
    assert!(line.contains("for you"), "{line}");
    assert!(
        !line.contains("not for you"),
        "foreign packet leaked: {line}"
    );
}

/// The ACK cannot be routed back to the sender (B has no route to A):
/// B still delivers the DATA once, its ACK is dropped by routing, and
/// send times out instead of claiming delivery.
#[test]
fn send_times_out_when_ack_route_missing() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port) = (free_port(), free_port());

    // B delivers but has NO route back to A - the ACK must drop.
    let b = node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
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
            "unreachable ack".into(),
            "--timeout-ms".into(),
            "500".into(),
            "--retries".into(),
            "1".into(),
        ],
        Duration::from_secs(10),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must fail without ACK: {stdout}");
    assert!(stderr.contains("no ACK after 2 attempts"), "{stderr}");

    // DATA still delivered once; the ACK was dropped by routing, not
    // bounced to A's UDP socket.
    b.expect_line(deadline, |l| l.starts_with("delivered:"));
    let drop = b.expect_line(deadline, |l| {
        l.starts_with("dropped (") && l.contains("no route") && l.contains(A_ADDR)
    });
    assert!(drop.contains(B_ADDR), "{drop}");
}

/// A passive receiver (no --via) never ACKs: send retries with the
/// SAME packet_id and the receiver must print the payload once, then
/// mark the retry as a duplicate - proof retries do not produce
/// uncontrolled double delivery.
#[test]
fn retries_produce_one_delivery_and_marks_duplicates() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port) = (free_port(), free_port());

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
            ep(b_port).to_string(),
            "--message".into(),
            "retry me".into(),
            "--timeout-ms".into(),
            "400".into(),
            "--retries".into(),
            "1".into(),
        ],
        Duration::from_secs(10),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "no ACK must fail: {stdout}{stderr}");
    assert!(stdout.contains("timeout waiting for ACK"), "{stdout}");
    assert!(stderr.contains("no ACK after 2 attempts"), "{stderr}");

    // Both attempts reached recv; dedup printed the payload once.
    let first = recv.expect_line(deadline, |l| l.starts_with("data from "));
    assert!(first.contains("retry me"), "{first}");
    assert!(!first.contains("duplicate"), "{first}");
    let dup = recv.expect_line(deadline, |l| l.starts_with("data from "));
    assert!(dup.contains("(duplicate)"), "retry not deduped: {dup}");
}
