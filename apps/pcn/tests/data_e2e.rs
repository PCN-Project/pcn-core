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

    // B: `pcn recv` bound to b_port, receiving for B's PCN address.
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
    // R1: static route to B only - DATA needs no return route.
    let r1 = node(&[
        "--listen".into(),
        ep(r1_port).to_string(),
        "--address".into(),
        R1_ADDR.into(),
        "--next-hop".into(),
        format!("1={}", ep(b_port)),
        "--route".into(),
        format!("{B_ADDR}=1"),
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
    // Honest semantics: sent, not "delivered" - no ACK exists.
    assert!(stdout.contains("unacknowledged"), "{stdout}");

    // Transit proof at the router.
    let fwd = r1.expect_line(deadline, |l| {
        l.starts_with("forwarded:") && l.contains(A_ADDR) && l.contains(B_ADDR)
    });
    assert!(fwd.contains("hop_limit 63"), "{fwd}");

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
            "direct data".into(),
        ],
        Duration::from_secs(10),
    );
    assert!(out.status.success());

    let line = b.expect_line(deadline, |l| l.starts_with("delivered:"));
    assert!(line.contains("type=DATA"), "{line}");
    assert!(line.contains("\"direct data\""), "payload missing: {line}");
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
        ],
        Duration::from_secs(10),
    );
    // send() only promises the datagram left the socket.
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
