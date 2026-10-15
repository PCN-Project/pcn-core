//! Process-level tests for the `pcn-registry` daemon and the
//! `pcn address` client over real loopback TCP.
//!
//! Each test spawns a real `pcn-registry` process with a throwaway
//! state file and drives it with the real `pcn` binary (and one raw
//! `TcpStream` for malformed-traffic coverage). HOME is redirected so
//! `~/.pcn` files never touch the developer's config.

mod common;

use common::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn temp_state(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "pcnreg-e2e-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

fn temp_home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pcnreg-home-{}-{tag}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(dir.join(".pcn")).unwrap();
    dir
}

/// Spawns the registry daemon; caller waits for `registry listening`.
fn registry(listen_port: u16, state: &Path, extra: &[String]) -> Proc {
    let mut args = vec![
        "--listen".into(),
        ep(listen_port).to_string(),
        "--state".into(),
        state.display().to_string(),
    ];
    args.extend(extra.iter().cloned());
    Proc::spawn("pcn-registry", &args)
}

/// `pcn address <sub>` with the registry given explicitly and HOME
/// redirected; returns full output.
fn address(sub_args: &[String], reg_port: u16, home: &Path) -> std::process::Output {
    let home_s = home.display().to_string();
    let reg_s = ep(reg_port).to_string();
    // `pcn address <subcommand> [flags...]` - --registry is a flag of
    // the subcommand, so it must follow `request`/`lookup`/etc.
    let mut args = sub_args.to_vec();
    args.extend(["--registry".into(), reg_s]);
    run_pcn_env(
        "address",
        &args,
        &[("HOME", home_s.as_str())],
        Duration::from_secs(10),
    )
}

fn ok(out: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout} | stderr: {stderr}");
    stdout.to_string()
}

fn fails(out: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success(), "expected failure: {stderr}");
    stderr
}

/// request allocates the lowest free private address, is idempotent,
/// and `address show` reports the locally stored record.
#[test]
fn request_allocates_and_remembers() {
    let reg_port = free_port();
    let state = temp_state("alloc");
    let home = temp_home("alloc");
    let reg = registry(reg_port, &state, &[]);
    let deadline = Instant::now() + TIMEOUT;
    reg.ready(deadline);

    let first = ok(&address(
        &["request".into(), "--name".into(), "fedora".into()],
        reg_port,
        &home,
    ));
    assert_eq!(first.trim(), "fedora -> pcn~1000-0000-00001", "{first}");

    // Idempotent: same name -> same address, no new allocation.
    let again = ok(&address(
        &["request".into(), "--name".into(), "fedora".into()],
        reg_port,
        &home,
    ));
    assert_eq!(again.trim(), "fedora -> pcn~1000-0000-00001", "{again}");

    // Second node gets the next free value - never the same address.
    let other = ok(&address(
        &["request".into(), "--name".into(), "cebula".into()],
        reg_port,
        &home,
    ));
    assert_eq!(other.trim(), "cebula -> pcn~1000-0000-00002", "{other}");

    // Local record written by request.
    let show = address(&["show".into()], reg_port, &home);
    let out = String::from_utf8_lossy(&show.stdout);
    assert!(out.contains("cebula pcn~1000-0000-00002"), "{out}");
}

/// Preferred addresses are honoured when free; conflicts are errors.
#[test]
fn preferred_address_and_conflicts() {
    let reg_port = free_port();
    let state = temp_state("pref");
    let home = temp_home("pref");
    let reg = registry(reg_port, &state, &[]);
    let deadline = Instant::now() + TIMEOUT;
    reg.ready(deadline);

    let got = ok(&address(
        &[
            "request".into(),
            "--name".into(),
            "server".into(),
            "--address".into(),
            "pcn~1000-0000-00007".into(),
        ],
        reg_port,
        &home,
    ));
    assert_eq!(got.trim(), "server -> pcn~1000-0000-00007", "{got}");

    // Same name, different preferred -> name_taken.
    let err = fails(&address(
        &[
            "request".into(),
            "--name".into(),
            "server".into(),
            "--address".into(),
            "pcn~1000-0000-00009".into(),
        ],
        reg_port,
        &home,
    ));
    assert!(err.contains("name_taken"), "{err}");

    // Different name, taken address -> addr_taken.
    let err = fails(&address(
        &[
            "request".into(),
            "--name".into(),
            "intruder".into(),
            "--address".into(),
            "pcn~1000-0000-00007".into(),
        ],
        reg_port,
        &home,
    ));
    assert!(err.contains("addr_taken"), "{err}");

    // Public-type preferred address rejected (v0.1 allocates type 1).
    let err = fails(&address(
        &[
            "request".into(),
            "--name".into(),
            "public".into(),
            "--address".into(),
            "pcn~2000-0000-00005".into(),
        ],
        reg_port,
        &home,
    ));
    assert!(err.contains("bad_address"), "{err}");
}

/// lookups go both ways; list prints every record.
#[test]
fn lookup_and_list() {
    let reg_port = free_port();
    let state = temp_state("look");
    let home = temp_home("look");
    let reg = registry(reg_port, &state, &[]);
    let deadline = Instant::now() + TIMEOUT;
    reg.ready(deadline);

    ok(&address(
        &["request".into(), "--name".into(), "fedora".into()],
        reg_port,
        &home,
    ));

    let by_name = ok(&address(
        &["lookup".into(), "--name".into(), "fedora".into()],
        reg_port,
        &home,
    ));
    assert_eq!(by_name.trim(), "pcn~1000-0000-00001", "{by_name}");

    let by_addr = ok(&address(
        &[
            "lookup".into(),
            "--address".into(),
            "pcn~1000-0000-00001".into(),
        ],
        reg_port,
        &home,
    ));
    assert_eq!(by_addr.trim(), "fedora", "{by_addr}");

    // Unknowns are clean errors.
    let err = fails(&address(
        &["lookup".into(), "--name".into(), "ghost".into()],
        reg_port,
        &home,
    ));
    assert!(err.contains("not_found"), "{err}");
    let err = fails(&address(
        &[
            "lookup".into(),
            "--address".into(),
            "pcn~1000-0000-00009".into(),
        ],
        reg_port,
        &home,
    ));
    assert!(err.contains("addr_not_found"), "{err}");

    let list = ok(&address(&["list".into()], reg_port, &home));
    assert!(list.contains("fedora pcn~1000-0000-00001"), "{list}");
}

/// reserve strictly claims an exact address for a NEW name.
#[test]
fn reserve_is_strict() {
    let reg_port = free_port();
    let state = temp_state("resv");
    let home = temp_home("resv");
    let reg = registry(reg_port, &state, &[]);
    let deadline = Instant::now() + TIMEOUT;
    reg.ready(deadline);

    ok(&address(
        &[
            "reserve".into(),
            "--name".into(),
            "svc".into(),
            "--address".into(),
            "pcn~1000-0000-00009".into(),
        ],
        reg_port,
        &home,
    ));

    // Same name -> name_taken even with the same address.
    let err = fails(&address(
        &[
            "reserve".into(),
            "--name".into(),
            "svc".into(),
            "--address".into(),
            "pcn~1000-0000-00009".into(),
        ],
        reg_port,
        &home,
    ));
    assert!(err.contains("name_taken"), "{err}");

    // Auto-alloc skips reserved addresses: svc@9, next gets 1.
    let n = ok(&address(
        &["request".into(), "--name".into(), "n".into()],
        reg_port,
        &home,
    ));
    assert_eq!(n.trim(), "n -> pcn~1000-0000-00001", "{n}");
}

/// Range exhaustion is a clean error, not a hang or wraparound.
#[test]
fn exhaustion_reports_cleanly() {
    let reg_port = free_port();
    let state = temp_state("exh");
    let home = temp_home("exh");
    let reg = registry(
        reg_port,
        &state,
        &[
            "--range-min".into(),
            "1".into(),
            "--range-max".into(),
            "2".into(),
        ],
    );
    let deadline = Instant::now() + TIMEOUT;
    reg.ready(deadline);

    ok(&address(
        &["request".into(), "--name".into(), "a".into()],
        reg_port,
        &home,
    ));
    ok(&address(
        &["request".into(), "--name".into(), "b".into()],
        reg_port,
        &home,
    ));
    let err = fails(&address(
        &["request".into(), "--name".into(), "c".into()],
        reg_port,
        &home,
    ));
    assert!(err.contains("exhausted"), "{err}");
}

/// State survives a process restart: same file -> same allocations.
#[test]
fn restart_keeps_allocations() {
    let reg_port = free_port();
    let state = temp_state("persist");
    let home = temp_home("persist");

    {
        let reg = registry(reg_port, &state, &[]);
        let deadline = Instant::now() + TIMEOUT;
        reg.ready(deadline);
        ok(&address(
            &["request".into(), "--name".into(), "fedora".into()],
            reg_port,
            &home,
        ));
    } // registry process killed here

    std::thread::sleep(Duration::from_millis(50));
    let reg = registry(reg_port, &state, &[]);
    let deadline = Instant::now() + TIMEOUT;
    reg.ready(deadline);

    // Same allocation returned after restart.
    let lookup = ok(&address(
        &["lookup".into(), "--name".into(), "fedora".into()],
        reg_port,
        &home,
    ));
    assert_eq!(lookup.trim(), "pcn~1000-0000-00001", "{lookup}");
    // Next auto-alloc continues past the persisted record.
    let next = ok(&address(
        &["request".into(), "--name".into(), "cebula".into()],
        reg_port,
        &home,
    ));
    assert_eq!(next.trim(), "cebula -> pcn~1000-0000-00002", "{next}");
}

/// Garbage and oversized frames are rejected without harming the
/// daemon: the connection dies, the registry keeps serving.
#[test]
fn malformed_tcp_is_rejected() {
    let reg_port = free_port();
    let state = temp_state("badtcp");
    let home = temp_home("badtcp");
    let reg = registry(reg_port, &state, &[]);
    let deadline = Instant::now() + TIMEOUT;
    reg.ready(deadline);

    // Not a frame at all: huge advertised length then close.
    let mut raw = TcpStream::connect(ep(reg_port)).unwrap();
    raw.write_all(&0x00FF_FFFFu32.to_be_bytes()).unwrap();
    raw.write_all(b"junk").unwrap();
    raw.flush().unwrap();
    let mut sink = [0u8; 8];
    let res = raw.read(&mut sink);
    assert!(
        matches!(res, Ok(0)) || res.is_err(),
        "connection must be closed after a bad frame"
    );
    drop(raw);

    // A valid framed but unknown verb -> `err bad_request`, daemon OK.
    let mut s = TcpStream::connect(ep(reg_port)).unwrap();
    let frame = b"frobnicate";
    s.write_all(&(frame.len() as u32).to_be_bytes()).unwrap();
    s.write_all(frame).unwrap();
    s.flush().unwrap();
    // Read len prefix + body.
    let mut len_buf = [0u8; 4];
    std::io::Read::read_exact(&mut s, &mut len_buf).unwrap();
    let n = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; n];
    std::io::Read::read_exact(&mut s, &mut body).unwrap();
    let text = String::from_utf8(body).unwrap();
    assert!(text.starts_with("err bad_request"), "{text}");

    // Registry still healthy.
    let ok_out = ok(&address(&["list".into()], reg_port, &home));
    assert!(
        ok_out.contains("empty") || ok_out.contains("pcn~"),
        "{ok_out}"
    );
}

/// PCN_REGISTRY env supplies the endpoint when no --registry is given.
#[test]
fn registry_via_env() {
    let reg_port = free_port();
    let state = temp_state("env");
    let home = temp_home("env");
    let reg = registry(reg_port, &state, &[]);
    let deadline = Instant::now() + TIMEOUT;
    reg.ready(deadline);

    let home_s = home.display().to_string();
    let reg_s = ep(reg_port).to_string();
    let out = run_pcn_env(
        "address",
        &["request".into(), "--name".into(), "envtest".into()],
        &[("PCN_REGISTRY", reg_s.as_str()), ("HOME", home_s.as_str())],
        Duration::from_secs(10),
    );
    let stdout = ok(&out);
    assert!(stdout.contains("envtest -> pcn~"), "{stdout}");
}

/// No registry configured anywhere -> clear error, not a TCP attempt.
#[test]
fn missing_registry_reports_how_to_fix() {
    let home = temp_home("noreg");
    let home_s = home.display().to_string();
    let out = run_pcn_env(
        "address",
        &["list".into()],
        &[("HOME", home_s.as_str())],
        Duration::from_secs(5),
    );
    let stderr = fails(&out);
    assert!(stderr.contains("no registry configured"), "{stderr}");
    assert!(stderr.contains("PCN_REGISTRY"), "{stderr}");
}
