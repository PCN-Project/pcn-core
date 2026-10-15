//! Shared process-level harness for `pcn`/`pcnd` end-to-end tests:
//! real binaries over real UDP loopback.
//!
//! `CARGO_BIN_EXE_<name>` exists only for the package under test, so
//! cross-binary tests locate siblings of `CARGO_BIN_EXE_pcn` in
//! `target/debug` via [`sibling_bin`]. Ports are pre-allocated with
//! bind-0-then-release (small TOCTOU caveat, far better than fixed
//! ports).

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::{Duration, Instant};

pub const TIMEOUT: Duration = Duration::from_secs(15);

/// Common private-type PCN test addresses (values 1/9/2).
pub const A_ADDR: &str = "pcn~1000-0000-00001";
pub const R1_ADDR: &str = "pcn~1000-0000-00009";
pub const B_ADDR: &str = "pcn~1000-0000-00002";

/// Grabs a currently-free UDP port.
pub fn free_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub fn ep(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// Path to a workspace binary next to this package's `pcn` binary.
pub fn sibling_bin(name: &str) -> PathBuf {
    let own = PathBuf::from(env!("CARGO_BIN_EXE_pcn"));
    let path = own.parent().expect("target dir").join(name);
    assert!(
        path.exists(),
        "{name} binary not found at {} - build the workspace first (cargo build --workspace)",
        path.display()
    );
    path
}

/// A running child process with stdout piped into a channel.
pub struct Proc {
    child: Child,
    rx: Receiver<String>,
}

impl Proc {
    /// Spawns `bin` (a workspace binary name) with `args`.
    pub fn spawn(bin: &str, args: &[String]) -> Self {
        let mut child = Command::new(sibling_bin(bin))
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {bin}: {e}"));
        let stdout: ChildStdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.expect("child stdout line")).is_err() {
                    break;
                }
            }
        });
        Self { child, rx }
    }

    /// Waits for `listening on ` or `receiving DATA ` startup line.
    pub fn ready(&self, deadline: Instant) {
        self.expect_line(deadline, |line| {
            line.starts_with("listening on ") || line.starts_with("receiving DATA ")
        });
    }

    /// Waits for a stdout line matching `pred` before `deadline`.
    /// Unrelated lines are consumed and skipped.
    pub fn expect_line(&self, deadline: Instant, pred: impl Fn(&str) -> bool) -> String {
        loop {
            let left = deadline
                .checked_duration_since(Instant::now())
                .expect("deadline exceeded waiting for process output");
            match self.rx.recv_timeout(left) {
                Ok(line) => {
                    if pred(&line) {
                        return line;
                    }
                }
                Err(_) => panic!("timeout waiting for process output"),
            }
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawns `pcnd run` with the given flags.
pub fn node(args: &[String]) -> Proc {
    let mut full = vec!["run".to_string()];
    full.extend(args.iter().cloned());
    Proc::spawn("pcnd", &full)
}

/// Runs a `pcn` subcommand to completion with a hard upper bound; a
/// wedged client is killed so tests report instead of hanging.
pub fn run_pcn(subcmd: &str, args: &[String], limit: Duration) -> Output {
    let mut full = vec![subcmd.to_string()];
    full.extend(args.iter().cloned());
    let mut child = Command::new(sibling_bin("pcn"))
        .args(&full)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pcn");

    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().expect("collect output"),
            Ok(None) => {
                if Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait_with_output();
                    panic!("pcn {subcmd} exceeded {limit:?}");
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("pcn wait failed: {e}"),
        }
    }
}
