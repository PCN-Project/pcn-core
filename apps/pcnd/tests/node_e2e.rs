//! End-to-end tests for `pcnd run`: real `pcnd` child processes
//! exchanging PCN packets over real UDP loopback.
//!
//! Nodes bind `127.0.0.1:0` (OS-assigned ports), so runs never collide.
//! The test reads each node's stdout for the `listening on ...` line to
//! learn its endpoint, then drives traffic with a raw `UdpSocket`.

use pcn_address::{Address, AddressType};
use pcn_packet::{Packet, PacketType};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::{Duration, Instant};

/// Overall budget per expect() wait; generous to stay flake-free on a
/// loaded machine while still catching a dead node quickly.
const TIMEOUT: Duration = Duration::from_secs(10);

fn addr(value: u64) -> Address {
    Address::new(AddressType::Private, value)
}

/// A running `pcnd run` child process with its stdout lines piped into
/// a channel for assertions.
struct Node {
    child: Child,
    rx: Receiver<String>,
}

impl Node {
    /// Spawns `pcnd run` with the given arguments.
    fn spawn(args: &[String]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pcnd"))
            .arg("run")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pcnd");

        let stdout: ChildStdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = channel();
        // Reader thread: pushes each stdout line; exits at child EOF.
        // println! in pcnd is line-buffered even when piped.
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.expect("node stdout line")).is_err() {
                    break;
                }
            }
        });
        Self { child, rx }
    }

    /// Waits for the `listening on ...` line and returns the endpoint.
    fn listen_addr(&self, deadline: Instant) -> SocketAddr {
        expect(self, deadline, |line| {
            line.strip_prefix("listening on ").map(str::to_string)
        })
        .parse()
        .expect("listen endpoint parses")
    }

    /// Asserts a stdout line satisfying `pred` arrives before `deadline`,
    /// returning the line (or the mapped capture).
    fn expect_until(&self, deadline: Instant, pred: impl Fn(&str) -> bool) -> String {
        expect(self, deadline, |line| pred(line).then(|| line.to_string()))
    }
}

/// Polls node stdout until a line yields `Some(capture)` or time runs
/// out. Unrelated lines are consumed and skipped.
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

fn packet_wire(src: Address, dst: Address, packet_id: u32, hop_limit: u8) -> Vec<u8> {
    Packet::builder(PacketType::Data, src, dst)
        .packet_id(packet_id)
        .hop_limit(hop_limit)
        .payload(b"e2e".to_vec())
        .build()
        .unwrap()
        .encode()
}

#[test]
fn node_delivers_packet_for_local_address() {
    let deadline = Instant::now() + TIMEOUT;
    let node = Node::spawn(&[
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--address".into(),
        "pcn~1000-0000-00002".into(),
    ]);
    let node_addr = node.listen_addr(deadline);

    // A raw UDP socket acts as node A: real packet, real wire.
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let wire = packet_wire(addr(1), addr(2), 0xbeef, 64);
    sender.send_to(&wire, node_addr).unwrap();

    let line = node.expect_until(deadline, |l| l.starts_with("delivered:"));
    assert!(
        line.contains("pcn~1000-0000-00002"),
        "delivery line should name the local destination: {line}"
    );
    assert!(line.contains("id=0x0000beef"), "{line}");
}

#[test]
fn router_forwards_packet_to_destination() {
    let deadline = Instant::now() + TIMEOUT;

    // B first, so R1 can be configured with B's real endpoint.
    let b = Node::spawn(&[
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--address".into(),
        "pcn~1000-0000-00002".into(),
    ]);
    let b_addr = b.listen_addr(deadline);

    // R1: static route B -> next-hop 1 (= B's UDP endpoint).
    let r1 = Node::spawn(&[
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--address".into(),
        "pcn~1000-0000-00009".into(),
        "--next-hop".into(),
        format!("1={b_addr}"),
        "--route".into(),
        "pcn~1000-0000-00002=1".into(),
    ]);
    let r1_addr = r1.listen_addr(deadline);

    // A -> R1: a DATA packet for B.
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(&packet_wire(addr(1), addr(2), 0xabcd, 64), r1_addr)
        .unwrap();

    // R1 forwards with hop_limit 64 -> 63 to B's endpoint.
    let fwd = r1.expect_until(deadline, |l| l.starts_with("forwarded:"));
    assert!(fwd.contains(&b_addr.to_string()), "{fwd}");
    assert!(fwd.contains("hop_limit 63"), "{fwd}");

    // B receives it as local traffic.
    let delivered = b.expect_until(deadline, |l| l.starts_with("delivered:"));
    assert!(delivered.contains("pcn~1000-0000-00002"), "{delivered}");
}

#[test]
fn router_drops_unrouted_packet_without_bounce() {
    let deadline = Instant::now() + TIMEOUT;

    // Router with a route only for B; nothing for the packet's actual
    // destination.
    let r1 = Node::spawn(&[
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--address".into(),
        "pcn~1000-0000-00009".into(),
        "--next-hop".into(),
        "1=127.0.0.1:9".into(), // defined but unrelated
        "--route".into(),
        "pcn~1000-0000-00002=1".into(),
    ]);
    let r1_addr = r1.listen_addr(deadline);

    // Destination pcn~1000-0000-00003 has no route: drop, never bounce.
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(&packet_wire(addr(1), addr(3), 1, 64), r1_addr)
        .unwrap();

    let drop = r1.expect_until(deadline, |l| l.starts_with("dropped ("));
    assert!(drop.contains("no route"), "{drop}");

    // And the sender receives nothing back (bounded wait, on purpose).
    sender
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut buf = [0u8; 64];
    assert!(sender.recv_from(&mut buf).is_err());
}
