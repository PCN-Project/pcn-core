//! Process-level tests for default-gateway resolution:
//! `--via` > `PCN_VIA` > `~/.pcn/gateway`.
//!
//! Every child gets a redirected HOME (empty temp dir or one holding a
//! prepared `.pcn/gateway` file) plus optional `PCN_VIA`, so precedence
//! is proven end-to-end through the real `pcn` binary - the rest of the
//! environment is inherited untouched.

mod common;

use common::*;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// A throwaway HOME dir: exists, empty, unique per call.
fn temp_home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pcn-gw-test-{}-{tag}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(dir.join(".pcn")).unwrap();
    dir
}

/// HOME prepared with `.pcn/gateway` containing `endpoint`.
fn home_with_gateway(tag: &str, endpoint: &str) -> PathBuf {
    let dir = temp_home(tag);
    std::fs::write(dir.join(".pcn").join("gateway"), format!("{endpoint}\n")).unwrap();
    dir
}

/// A pcnd "receiver" for B with a return route to A's endpoint.
fn receiver_node(a_port: u16, b_port: u16) -> Proc {
    node(&[
        "--listen".into(),
        ep(b_port).to_string(),
        "--address".into(),
        B_ADDR.into(),
        "--next-hop".into(),
        format!("1={}", ep(a_port)),
        "--route".into(),
        format!("{A_ADDR}=1"),
    ])
}

/// PCN_VIA alone supplies the gateway: send reaches B and its ACK comes
/// back through B's own static route.
#[test]
fn env_gateway_is_used() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port) = (free_port(), free_port());
    let b = receiver_node(a_port, b_port);
    b.ready(deadline);
    let home = temp_home("env");
    let home_s = home.display().to_string();
    let via_s = ep(b_port).to_string();

    let out = run_pcn_env(
        "send",
        &[
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--message".into(),
            "via env".into(),
        ],
        &[("PCN_VIA", via_s.as_str()), ("HOME", home_s.as_str())],
        Duration::from_secs(10),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("acknowledged by"), "{stdout}");
    b.expect_line(deadline, |l| l.starts_with("delivered"));
}

/// ~/.pcn/gateway alone (no flag, no env) supplies the gateway.
#[test]
fn file_gateway_is_used() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port) = (free_port(), free_port());
    let b = receiver_node(a_port, b_port);
    b.ready(deadline);
    let home = home_with_gateway("file", &ep(b_port).to_string());
    let home_s = home.display().to_string();

    let out = run_pcn_env(
        "send",
        &[
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--message".into(),
            "via file".into(),
        ],
        &[("HOME", home_s.as_str())],
        Duration::from_secs(10),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("acknowledged by"), "{stdout}");
}

/// Explicit --via beats PCN_VIA (and would beat the file): env points
/// at a dead port, the flag at the real receiver.
#[test]
fn explicit_via_beats_env() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port, dead_port) = (free_port(), free_port(), free_port());
    let b = receiver_node(a_port, b_port);
    b.ready(deadline);
    let home = home_with_gateway("cli", &ep(dead_port).to_string());
    let home_s = home.display().to_string();
    let dead = ep(dead_port).to_string();

    let out = run_pcn_env(
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
            "via flag".into(),
            "--timeout-ms".into(),
            "400".into(),
            "--retries".into(),
            "0".into(),
        ],
        &[("PCN_VIA", dead.as_str()), ("HOME", home_s.as_str())],
        Duration::from_secs(10),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("acknowledged by"), "{stdout}");
}

/// PCN_VIA beats the file: file points at a dead port, env at the real
/// receiver.
#[test]
fn env_beats_file() {
    let deadline = Instant::now() + TIMEOUT;
    let (a_port, b_port, dead_port) = (free_port(), free_port(), free_port());
    let b = receiver_node(a_port, b_port);
    b.ready(deadline);
    let home = home_with_gateway("envfile", &ep(dead_port).to_string());
    let home_s = home.display().to_string();
    let via_s = ep(b_port).to_string();

    let out = run_pcn_env(
        "send",
        &[
            "--listen".into(),
            ep(a_port).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--message".into(),
            "env wins".into(),
            "--timeout-ms".into(),
            "400".into(),
            "--retries".into(),
            "0".into(),
        ],
        &[("PCN_VIA", via_s.as_str()), ("HOME", home_s.as_str())],
        Duration::from_secs(10),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("acknowledged by"), "{stdout}");
}

/// Nothing configured anywhere: ping fails fast with a how-to error,
/// not a hang or a bogus endpoint.
#[test]
fn missing_gateway_reports_how_to_fix() {
    let home = temp_home("none");
    let home_s = home.display().to_string();
    let out = run_pcn_env(
        "ping",
        &[
            "--listen".into(),
            ep(free_port()).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--count".into(),
            "1".into(),
        ],
        &[("HOME", home_s.as_str())],
        Duration::from_secs(5),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must fail without any gateway");
    assert!(stderr.contains("no gateway configured"), "{stderr}");
    // The hint names every supported mechanism.
    assert!(stderr.contains("--via"), "{stderr}");
    assert!(stderr.contains("PCN_VIA"), "{stderr}");
    assert!(stderr.contains("gateway set"), "{stderr}");
}

/// A configured-but-invalid endpoint is an error, not a silent skip to
/// a lower-priority source.
#[test]
fn invalid_env_gateway_is_rejected() {
    let home = temp_home("badenv");
    let home_s = home.display().to_string();
    let out = run_pcn_env(
        "send",
        &[
            "--listen".into(),
            ep(free_port()).to_string(),
            "--source".into(),
            A_ADDR.into(),
            "--target".into(),
            B_ADDR.into(),
            "--message".into(),
            "x".into(),
        ],
        &[("PCN_VIA", "not-an-endpoint"), ("HOME", home_s.as_str())],
        Duration::from_secs(5),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("PCN_VIA"), "{stderr}");
}

/// `pcn gateway set` writes ~/.pcn/gateway; a bare `pcn gateway` then
/// reports it as the effective gateway sourced from the file.
#[test]
fn gateway_set_then_show() {
    let home = temp_home("setshow");
    let home_s = home.display().to_string();
    let gw = ep(free_port()).to_string();

    let set = run_pcn_env(
        "gateway",
        &["set".into(), gw.clone()],
        &[("HOME", home_s.as_str())],
        Duration::from_secs(5),
    );
    let stdout = String::from_utf8_lossy(&set.stdout);
    assert!(set.status.success(), "{stdout}");
    assert!(stdout.contains(&gw), "{stdout}");
    // File actually written with the endpoint.
    let stored = std::fs::read_to_string(home.join(".pcn").join("gateway")).unwrap();
    assert_eq!(stored.trim(), gw);

    let show = run_pcn_env(
        "gateway",
        &[],
        &[("HOME", home_s.as_str())],
        Duration::from_secs(5),
    );
    let stdout = String::from_utf8_lossy(&show.stdout);
    assert!(stdout.contains(&gw), "{stdout}");
    assert!(stdout.contains("~/.pcn/gateway"), "{stdout}");
}

/// `pcn gateway set` rejects a malformed endpoint and writes nothing.
#[test]
fn gateway_set_rejects_bad_endpoint() {
    let home = temp_home("badset");
    let home_s = home.display().to_string();
    let out = run_pcn_env(
        "gateway",
        &["set".into(), "banana".into()],
        &[("HOME", home_s.as_str())],
        Duration::from_secs(5),
    );
    assert!(!out.status.success());
    assert!(!home.join(".pcn").join("gateway").exists());
}
