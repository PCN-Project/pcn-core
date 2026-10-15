//! End-to-end tests for `pcn ping`: a real `pcn` client process plus
//! real `pcnd` node processes exchanging PCN ECHO packets over UDP
//! loopback. The process harness lives in `tests/common/`.

mod common;

use common::*;
use std::time::{Duration, Instant};

#[test]
fn ping_round_trip_through_router() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, r1_port, b_port) = (free_port(), free_port(), free_port());

    // B: destination node; route back to A goes via R1's endpoint.
    let b = node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
        "--next-hop".into(),
        format!("1={}", ep(r1_port)),
        "--route".into(),
        format!("{A_ADDR}=1"),
    ]);
    // R1: router with routes in both directions (to B and back to A).
    let r1 = node(&[
        "--listen".into(),
        ep(r1_port).to_string(),
        "--address".into(),
        R1_ADDR.into(),
        "--next-hop".into(),
        format!("1={}", ep(b_port)),
        "--next-hop".into(),
        format!("2={}", ep(a_port)),
        "--route".into(),
        format!("{B_ADDR}=1"),
        "--route".into(),
        format!("{A_ADDR}=2"),
    ]);
    b.ready(deadline);
    r1.ready(deadline);

    // A: the ping client, bound to a_port so R1's return route resolves.
    let out = run_pcn(
        "ping",
        &[
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--via".into(),
            ep(r1_port).to_string(),
            "--count".into(),
            "3".into(),
            "--timeout-ms".into(),
            "2000".into(),
            "--interval-ms".into(),
            "100".into(),
        ],
        Duration::from_secs(15),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(out.status.success(), "ping failed: {stdout}{stderr}");
    assert!(stdout.contains("reply from"), "no reply lines: {stdout}");
    assert!(
        stdout.contains("3 sent, 3 received, 0 lost (0% loss)"),
        "{stdout}"
    );
    assert!(stdout.contains("rtt min/avg/max"), "{stdout}");

    // Proof the round trip crossed the router in both directions:
    // R1 forwards A->B, then B->A.
    let to_b = r1.expect_line(deadline, |l| {
        l.starts_with("forwarded:") && l.contains(A_ADDR) && l.contains(B_ADDR)
    });
    assert!(to_b.contains("hop_limit 63"), "{to_b}");
    let back_to_a = r1.expect_line(deadline, |l| {
        l.starts_with("forwarded:") && l.contains(B_ADDR) && l.contains(A_ADDR)
    });
    assert!(back_to_a.contains("hop_limit 63"), "{back_to_a}");

    // B actually answered, not some shortcut.
    let replied = b.expect_line(deadline, |l| l.starts_with("replied:"));
    assert!(replied.contains(B_ADDR), "{replied}");
    assert!(replied.contains(A_ADDR), "{replied}");
}

#[test]
fn ping_times_out_when_return_route_missing() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, r1_port, b_port) = (free_port(), free_port(), free_port());

    // B replies toward A via R1, exactly as before.
    let b = node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
        "--next-hop".into(),
        format!("1={}", ep(r1_port)),
        "--route".into(),
        format!("{A_ADDR}=1"),
    ]);
    // R1 knows only the route to B - NO route back to A. The reply
    // reaching R1 must be dropped there; it must not bounce straight to
    // A's socket just because A sent the original datagram.
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
    b.ready(deadline);
    r1.ready(deadline);

    let out = run_pcn(
        "ping",
        &[
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--via".into(),
            ep(r1_port).to_string(),
            "--count".into(),
            "2".into(),
            "--timeout-ms".into(),
            "1500".into(),
            "--interval-ms".into(),
            "100".into(),
        ],
        Duration::from_secs(15),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        !out.status.success(),
        "ping must fail on total loss: {stdout}"
    );
    assert!(stdout.contains("2 sent, 0 received"), "{stdout}");
    assert!(stdout.contains("100% loss"), "{stdout}");

    // The reply died at R1's routing table - evidence it was not
    // silently bounced to the UDP sender.
    let drop_line = r1.expect_line(deadline, |l| {
        l.starts_with("dropped (") && l.contains("no route") && l.contains(B_ADDR)
    });
    assert!(drop_line.contains(A_ADDR), "{drop_line}");
}
