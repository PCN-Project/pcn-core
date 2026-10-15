//! End-to-end tests for `pcn ping`: a real `pcn` client process plus
//! real `pcnd` node processes exchanging PCN ECHO packets over UDP
//! loopback.
//!
//! The Node/expect harness mirrors `apps/pcnd/tests/node_e2e.rs` - test
//! helpers cannot be shared across crates without a dedicated
//! test-support crate, so the ~70 lines are deliberately duplicated as
//! the least invasive option.
//!
//! Ports are pre-allocated with the bind-0-then-release trick (standard
//! TOCTOU caveat, far better than fixed ports). All addresses are
//! private PCN type 1.

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(15);

/// A's, R1's and B's PCN addresses (private type, values 1/9/2).
const A_ADDR: &str = "pcn~1000-0000-00001";
const R1_ADDR: &str = "pcn~1000-0000-00009";
const B_ADDR: &str = "pcn~1000-0000-00002";

/// Grabs a currently-free UDP port. Small inherent race vs. another
/// process grabbing it first; acceptable and standard for tests.
fn free_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn ep(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Path to a sibling workspace binary (`pcnd`) next to this package's
/// `pcn` binary. `CARGO_BIN_EXE_<name>` is only defined for binaries of
/// the package under test, so cross-binary e2e resolves by directory.
fn sibling_bin(name: &str) -> std::path::PathBuf {
    let own = std::path::PathBuf::from(env!("CARGO_BIN_EXE_pcn"));
    let path = own.parent().expect("target dir").join(name);
    assert!(
        path.exists(),
        "{name} binary not found at {} - build the workspace first (cargo build --workspace)",
        path.display()
    );
    path
}

/// A running `pcnd` child with stdout piped into a channel.
struct Node {
    child: Child,
    rx: Receiver<String>,
}

impl Node {
    fn spawn(args: &[String]) -> Self {
        let mut child = Command::new(sibling_bin("pcnd"))
            .arg("run")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pcnd");
        let stdout: ChildStdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.expect("node stdout line")).is_err() {
                    break;
                }
            }
        });
        Self { child, rx }
    }

    /// Waits for `listening on ...` - proves the node bound its socket.
    fn ready(&self, deadline: Instant) {
        expect(self, deadline, |line| {
            line.starts_with("listening on ").then_some(())
        });
    }

    /// Waits for a stdout line matching `pred` before `deadline`.
    fn expect_line(&self, deadline: Instant, pred: impl Fn(&str) -> bool) -> String {
        expect(self, deadline, |line| {
            if pred(line) {
                Some(line.to_string())
            } else {
                None
            }
        })
    }
}

fn expect<T>(node: &Node, deadline: Instant, mut pred: impl FnMut(&str) -> Option<T>) -> T {
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .expect("deadline exceeded waiting for pcnd output");
        match node.rx.recv_timeout(left) {
            Ok(line) => {
                if let Some(v) = pred(&line) {
                    return v;
                }
            }
            Err(_) => panic!("timeout waiting for pcnd output"),
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs `pcn ping` to completion with a hard upper bound; a wedged
/// client is killed so the test can report instead of hanging forever.
fn run_ping(args: &[String], limit: Duration) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcn"))
        .arg("ping")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pcn");

    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child.wait_with_output().expect("collect output");
            }
            Ok(None) => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait_with_output();
                    panic!("pcn ping exceeded {limit:?}");
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("pcn wait failed: {e}"),
        }
    }
}

#[test]
fn ping_round_trip_through_router() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, r1_port, b_port) = (free_port(), free_port(), free_port());

    // B: destination node; route back to A goes via R1's endpoint.
    let b = Node::spawn(&[
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
    let r1 = Node::spawn(&[
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
    let out = run_ping(
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
    let b = Node::spawn(&[
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
    let r1 = Node::spawn(&[
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

    let out = run_ping(
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
