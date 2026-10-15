//! Node mode for `pcnd`: a real UDP receive loop driven by static
//! routing decisions.
//!
//! `pcnd run` binds a [`UdpTransport`], parses incoming datagrams with
//! `pcn-packet`, asks `pcn-routing::decide` what to do with each valid
//! packet, and executes the decision:
//!
//! * [`Decision::Deliver`] - the packet is for a local address; it is
//!   logged only (no echo responder or upper layer exists yet).
//! * [`Decision::Forward`] - the packet is rebuilt with a decremented
//!   Hop Limit via `pcn-routing::forward` and sent to the next hop's
//!   endpoint.
//! * [`Decision::Drop`] - logged and forgotten; never bounced back to
//!   the sender, never auto-routed.
//!
//! Layering: this module maps [`NextHopId`] to `SocketAddr` - exactly
//! the resolution the routing crate deliberately does not perform.

use pcn_address::Address;
use pcn_packet::{Packet, PacketType, ParseError, MAX_PACKET_LEN};
use pcn_routing::{decide, forward, Decision, DropReason, ForwardError, NextHopId, RouteTable};
use pcn_transport::Transport;
use pcn_transport_udp::UdpTransport;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Everything a node needs at startup, produced by CLI parsing.
#[derive(Debug)]
pub struct NodeConfig {
    /// Local UDP endpoint the node binds.
    pub listen: SocketAddr,
    /// PCN addresses that belong to this node - packets addressed to
    /// any of them are delivered locally.
    pub local_addrs: Vec<Address>,
    /// Resolves a route's [`NextHopId`] to a concrete UDP endpoint.
    /// Kept here, not in the routing layer, so `pcn-routing` stays
    /// transport-agnostic.
    pub next_hops: HashMap<NextHopId, SocketAddr>,
    /// Static exact-match routes.
    pub routes: RouteTable,
}

/// Usage text for `pcnd run --help`.
pub const RUN_USAGE: &str = "\
pcnd run - start a PCN node: UDP receive loop + static forwarding

USAGE:
    pcnd run --listen HOST:PORT --address ADDR [options]

OPTIONS:
    --listen HOST:PORT       local UDP endpoint to bind (required)
    --address ADDR           local PCN address, pcn~ form or bare body
                             (repeatable, at least one required)
    --next-hop ID=HOST:PORT  map next-hop ID (u32) to a UDP endpoint
                             (repeatable)
    --route ADDR=ID          static route: destination PCN address to
                             next-hop ID (repeatable); every route's ID
                             must appear in a --next-hop entry

EXAMPLE (A -> R1 -> B, all on 127.0.0.1):
    # node B, address pcn~1000-0000-00002, port 41003
    pcnd run --listen 127.0.0.1:41003 \\
        --address pcn~1000-0000-00002 \\
        --next-hop 1=127.0.0.1:41002 \\
        --route pcn~1000-0000-00001=1

Every option also accepts --flag=value form.
Node exits on Ctrl-C/SIGTERM; local delivery is only logged.";

/// Result of pushing one received datagram through the node pipeline
/// (parse -> decide -> forward plan). Contains everything the caller
/// needs to act or log; performs no I/O itself, so it is fully testable
/// without sockets.
#[derive(Debug, PartialEq)]
pub enum Action {
    /// The datagram was not a valid PCN packet.
    Malformed(ParseError),
    /// Destination is a local address; the packet is delivered to the
    /// (future) local stack - currently logging only.
    Deliver(Packet),
    /// Routing rejected the packet; the original is kept for logging.
    Drop { reason: DropReason, packet: Packet },
    /// Send this packet to this transport endpoint. For transit
    /// packets (`originated: false`) it was rebuilt by `forward()` with
    /// Hop Limit - 1; locally originated replies/ACKs keep their fresh
    /// Hop Limit.
    Send {
        packet: Packet,
        endpoint: SocketAddr,
        /// `true` when this node originated the packet (ECHO_REPLY,
        /// ACK), `false` for transit - used only for log wording.
        originated: bool,
    },
    /// Defensive arm for the unreachable rebuild failure: a parsed
    /// packet always survives `PacketBuilder`, so this exists only so
    /// `handle` never panics if `pcn-packet` invariants ever weaken.
    Internal(ForwardError),
    /// Deliver `packet` locally, then dispatch `then` - used for DATA,
    /// whose local delivery is followed by routing an ACK back to the
    /// sender through the normal routing table (Send), dropped when no
    /// return route exists, or delivered locally for self-addressed
    /// DATA.
    DeliverThen {
        /// The packet delivered to the local application interface.
        packet: Packet,
        /// The follow-up action (the ACK's routing outcome).
        then: Box<Action>,
    },
}

/// Pure packet pipeline: bytes in, [`Action`] out. No sockets, no
/// logging - the receive loop owns both.
pub fn handle(config: &NodeConfig, bytes: &[u8]) -> Action {
    let packet = match Packet::parse(bytes) {
        Ok(p) => p,
        Err(e) => return Action::Malformed(e),
    };
    match decide(&config.local_addrs, &config.routes, &packet) {
        // Locally addressed ECHO_REQUEST is answered; DATA is delivered
        // and then acknowledged - the ACK is routed by its PCN
        // destination like any locally originated packet; everything
        // else delivered (ECHO_REPLY, ACK, CONTROL, ERROR) is just
        // delivered - replies never trigger replies.
        Decision::Deliver => match packet.header().packet_type() {
            PacketType::EchoRequest => respond(config, packet),
            PacketType::Data => {
                // Unreachable for a parsed packet; kept so handle()
                // never panics if invariants weaken.
                match packet.ack() {
                    Ok(ack) => Action::DeliverThen {
                        packet,
                        then: Box::new(route_out(config, ack)),
                    },
                    Err(e) => Action::Internal(ForwardError::Rebuild(e)),
                }
            }
            _ => Action::Deliver(packet),
        },
        Decision::Drop(reason) => Action::Drop { reason, packet },
        Decision::Forward(next_hop) => match config.next_hops.get(&next_hop) {
            Some(&endpoint) => match forward(&packet) {
                Ok(fwd) => Action::Send {
                    packet: fwd,
                    endpoint,
                    originated: false,
                },
                // decide() already filtered hop_limit <= 1; both arms are
                // kept explicit so no forward() error becomes a panic.
                Err(ForwardError::HopLimitExhausted) => Action::Drop {
                    reason: DropReason::HopLimitExhausted,
                    packet,
                },
                Err(e @ ForwardError::Rebuild(_)) => Action::Internal(e),
            },
            // Config validation guarantees every route's NextHopId is
            // defined; this arm defends configs built programmatically.
            None => Action::Drop {
                reason: DropReason::NoRoute,
                packet,
            },
        },
    }
}

/// Answers a locally delivered ECHO_REQUEST through the normal routing
/// path.
///
/// The reply is a newly originated packet (`Packet::echo_reply` gives it
/// a fresh Hop Limit), so it does not pass through
/// `pcn_routing::forward`; decrementing applies to transit only. Its
/// destination is the request's source address. With no return route the
/// reply is dropped as [`DropReason::NoRoute`]; it is never bounced
/// directly to the UDP sender endpoint and never auto-routed.
fn respond(config: &NodeConfig, request: Packet) -> Action {
    let reply = match request.echo_reply() {
        Ok(r) => r,
        // Unreachable: handle() already verified EchoRequest. Kept
        // explicit so no error path ever panics.
        Err(e) => return Action::Internal(ForwardError::Rebuild(e)),
    };
    route_out(config, reply)
}

/// Routes a locally originated packet (ECHO_REPLY, ACK) through the
/// normal decision path. Identical semantics for both: fresh packets
/// skip `forward()`'s decrement; the destination is resolved by the
/// route table; no route = drop, never a bounce to the UDP sender.
fn route_out(config: &NodeConfig, packet: Packet) -> Action {
    match decide(&config.local_addrs, &config.routes, &packet) {
        // Destination is ourselves (self-addressed): deliver locally -
        // and being a reply-type packet it triggers nothing further.
        Decision::Deliver => Action::Deliver(packet),
        Decision::Drop(reason) => Action::Drop { reason, packet },
        Decision::Forward(next_hop) => match config.next_hops.get(&next_hop) {
            Some(&endpoint) => Action::Send {
                packet,
                endpoint,
                originated: true,
            },
            None => Action::Drop {
                reason: DropReason::NoRoute,
                packet,
            },
        },
    }
}

/// Executes one [`Action`]: logs it and performs the socket I/O.
/// `DeliverThen` recurses so a DATA delivery is followed by its routed
/// ACK; `seen_data` dedups retransmitted DATA (deliver once, but still
/// route every ACK - the sender may retry on a lost one).
fn act(
    transport: &UdpTransport,
    action: Action,
    malformed_count: &mut u64,
    seen_data: &mut HashSet<(Address, u32)>,
) {
    match action {
        Action::Deliver(p) => log_delivered(&p, false),
        Action::DeliverThen { packet, then } => {
            let h = packet.header();
            // Dedup fires only for DATA; other DeliverThen payloads are
            // already protected by their sender-side semantics.
            if h.packet_type() == PacketType::Data && !seen_data.insert((h.source(), h.packet_id()))
            {
                log_delivered(&packet, true);
            } else {
                if seen_data.len() > 4096 {
                    seen_data.clear();
                }
                log_delivered(&packet, false);
            }
            act(transport, *then, malformed_count, seen_data);
        }
        Action::Send {
            packet,
            endpoint,
            originated,
        } => {
            let h = packet.header();
            // 'replied'/'acked' only for locally originated answers;
            // transit packets - including transit ACKs - are forwarded.
            let verb = match (originated, h.packet_type()) {
                (true, PacketType::EchoReply) => "replied",
                (true, PacketType::Ack) => "acked",
                _ => "forwarded",
            };
            match transport.send_to(&packet.encode(), &endpoint) {
                Ok(_) => println!(
                    "{verb}: {} -> {} via {} (hop_limit {})",
                    h.source(),
                    h.destination(),
                    endpoint,
                    h.hop_limit()
                ),
                Err(e) => eprintln!("send to {endpoint} failed: {e}"),
            }
        }
        Action::Drop { reason, packet } => {
            let h = packet.header();
            println!("dropped ({reason}): {} -> {}", h.source(), h.destination());
        }
        // Throttled: first few malformed datagrams logged individually,
        // then only each 1000th - a hostile or broken peer must not
        // drown the log.
        Action::Malformed(e) => {
            *malformed_count += 1;
            if *malformed_count <= 3 || *malformed_count % 1000 == 0 {
                eprintln!("malformed datagram #{malformed_count}: {e}");
            }
        }
        Action::Internal(e) => eprintln!("internal forward error: {e}"),
    }
}

/// The application-facing delivery interface for this stage: one
/// stdout line per delivered packet, payload included. Duplicates are
/// marked, not silently re-delivered.
fn log_delivered(p: &Packet, duplicate: bool) {
    let h = p.header();
    println!(
        "delivered{}: {} -> {} type={} id=0x{:08x} {} B payload {}",
        if duplicate { " (duplicate)" } else { "" },
        h.source(),
        h.destination(),
        h.packet_type().name(),
        h.packet_id(),
        p.payload().len(),
        fmt_payload(p.payload())
    );
}

/// Renders payload bytes for logs: UTF-8 text in quotes, anything else
/// as hex (capped at 64 bytes displayed).
fn fmt_payload(payload: &[u8]) -> String {
    use std::fmt::Write as _;
    match std::str::from_utf8(payload) {
        Ok(text) => format!("\"{text}\""),
        Err(_) => {
            let mut s = String::from("0x");
            for &b in payload.iter().take(64) {
                let _ = write!(s, "{b:02x}");
            }
            if payload.len() > 64 {
                let _ = write!(s, "..(+{} B)", payload.len() - 64);
            }
            s
        }
    }
}

/// `pcnd run ...` entry point: parses arguments, binds the socket, and
/// serves until the process is signalled. Returns the exit code.
pub fn run_command(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{RUN_USAGE}");
        return ExitCode::SUCCESS;
    }
    let config = match parse_run_args(args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!("{RUN_USAGE}");
            return ExitCode::from(2);
        }
    };
    // The flag exists so in-process callers (tests, embedding) can stop
    // the loop cleanly; on the CLI the process simply dies by signal.
    let running = AtomicBool::new(true);
    match run(&config, &running) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Serves the node on `config.listen` until `running` goes false.
///
/// Errors only on socket setup (bind, timeout). Per-datagram failures -
/// malformed bytes, send errors, recv timeouts - are logged and the loop
/// continues; one bad packet can never kill the node.
pub fn run(config: &NodeConfig, running: &AtomicBool) -> io::Result<()> {
    let transport = UdpTransport::bind(config.listen)?;
    // Polling timeout: bounds recv latency so `running` is honoured
    // without signal handling dependencies.
    transport.set_read_timeout(Some(Duration::from_millis(200)))?;
    println!("listening on {}", transport.local_endpoint()?);

    // Sized to the packet layer's absolute wire bound; anything larger
    // is truncated by the OS and then rejected by Packet::parse.
    let mut buf = vec![0u8; MAX_PACKET_LEN];
    let mut malformed_count = 0u64;
    // Bounded dedup: retransmitted DATA (the sender retries when its
    // ACK is lost) must not be delivered to the application twice.
    // 4096 recent (source, packet_id) keys; on overflow the cache
    // resets - a stale duplicate may reappear then, acceptable here.
    let mut seen_data: HashSet<(Address, u32)> = HashSet::new();

    while running.load(Ordering::Relaxed) {
        match transport.recv_from(&mut buf) {
            Ok((n, _from)) => {
                act(
                    &transport,
                    handle(config, &buf[..n]),
                    &mut malformed_count,
                    &mut seen_data,
                );
            }
            Err(e) => match e.kind() {
                // Read-timeout expiry and EINTR: loop around and
                // re-check `running`.
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted => continue,
                // Unexpected socket error: report and keep serving -
                // the socket stays valid for the process lifetime.
                _ => eprintln!("recv error: {e}"),
            },
        }
    }
    Ok(())
}

/// Grabs the value for a flag: either the `--flag=value` inline form or
/// the following argument.
fn take<'a>(
    args: &'a [String],
    i: &mut usize,
    inline: Option<&'a str>,
    flag: &str,
) -> Result<&'a str, String> {
    match inline {
        Some(v) => Ok(v),
        None => {
            *i += 1;
            args.get(*i)
                .map(String::as_str)
                .ok_or_else(|| format!("'{flag}' requires a value"))
        }
    }
}

/// Parses `host:port` for `--listen` and `--next-hop` values.
fn parse_endpoint(s: &str, flag: &str) -> Result<SocketAddr, String> {
    s.parse::<SocketAddr>()
        .map_err(|_| format!("{flag}: '{s}' is not a valid socket address (expected HOST:PORT)"))
}

/// Parses a PCN address (canonical `pcn~` form or bare body) and checks
/// it is routable in v0.1.
fn parse_address(s: &str, flag: &str) -> Result<Address, String> {
    let addr = s
        .parse::<Address>()
        .map_err(|e| format!("{flag}: invalid address '{s}': {e}"))?;
    if !addr.is_routable() {
        return Err(format!(
            "{flag}: '{s}' is not routable (only private and public addresses are)"
        ));
    }
    Ok(addr)
}

/// Parses `ID` as a next-hop identifier.
fn parse_next_hop_id(s: &str) -> Result<NextHopId, String> {
    s.parse::<u32>()
        .map(NextHopId)
        .map_err(|_| format!("invalid next-hop id '{s}' (expected u32)"))
}

/// Parses the `pcnd run` arguments into a [`NodeConfig`].
///
/// Every failure is a `Err(String)` describing exactly one problem;
/// the caller prints it plus usage. Order of flags is irrelevant -
/// routes are validated against the complete next-hop table.
pub fn parse_run_args(args: &[String]) -> Result<NodeConfig, String> {
    let mut listen = None;
    let mut local_addrs: Vec<Address> = Vec::new();
    let mut next_hops: HashMap<NextHopId, SocketAddr> = HashMap::new();
    let mut route_specs: Vec<(Address, NextHopId)> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let (flag, inline) = match args[i].split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v)),
            _ => (args[i].as_str(), None),
        };
        match flag {
            "--listen" => {
                let v = take(args, &mut i, inline, flag)?;
                if listen.is_some() {
                    return Err("duplicate --listen".to_string());
                }
                listen = Some(parse_endpoint(v, flag)?);
            }
            "--address" => {
                let v = take(args, &mut i, inline, flag)?;
                let addr = parse_address(v, flag)?;
                if local_addrs.contains(&addr) {
                    return Err(format!("--address: duplicate local address '{v}'"));
                }
                local_addrs.push(addr);
            }
            "--next-hop" => {
                let v = take(args, &mut i, inline, flag)?;
                let (id_s, ep_s) = v
                    .split_once('=')
                    .ok_or_else(|| format!("--next-hop: expected ID=HOST:PORT, got '{v}'"))?;
                let id = parse_next_hop_id(id_s)?;
                let endpoint = parse_endpoint(ep_s, flag)?;
                if next_hops.insert(id, endpoint).is_some() {
                    return Err(format!("--next-hop: duplicate id {id_s}"));
                }
            }
            "--route" => {
                let v = take(args, &mut i, inline, flag)?;
                let (dest_s, id_s) = v
                    .split_once('=')
                    .ok_or_else(|| format!("--route: expected ADDR=ID, got '{v}'"))?;
                let dest = parse_address(dest_s, flag)?;
                let id = parse_next_hop_id(id_s)?;
                route_specs.push((dest, id));
            }
            other => return Err(format!("unknown option '{other}'")),
        }
        i += 1;
    }

    let listen = listen.ok_or("run requires --listen HOST:PORT")?;
    if local_addrs.is_empty() {
        return Err("run requires at least one --address".to_string());
    }

    let mut routes = RouteTable::new();
    for (dest, id) in route_specs {
        if !next_hops.contains_key(&id) {
            return Err(format!(
                "--route: destination {dest} points at undefined next-hop id {}",
                id.0
            ));
        }
        if routes.insert(dest, id).is_some() {
            return Err(format!("--route: duplicate route to {dest}"));
        }
    }

    Ok(NodeConfig {
        listen,
        local_addrs,
        next_hops,
        routes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcn_address::AddressType;
    use pcn_packet::PacketType;

    fn addr(value: u64) -> Address {
        Address::new(AddressType::Private, value)
    }

    fn ep(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn packet(src: Address, dst: Address, hop_limit: u8) -> Packet {
        Packet::builder(PacketType::Data, src, dst)
            .packet_id(7)
            .hop_limit(hop_limit)
            .payload(b"x".to_vec())
            .build()
            .unwrap()
    }

    /// A minimal hand-built config: locals [1], one hop, one route.
    fn config() -> NodeConfig {
        let mut next_hops = HashMap::new();
        next_hops.insert(NextHopId(2), ep(44002));
        let mut routes = RouteTable::new();
        routes.insert(addr(9), NextHopId(2));
        NodeConfig {
            listen: ep(44001),
            local_addrs: vec![addr(1)],
            next_hops,
            routes,
        }
    }

    // --- CLI parsing -------------------------------------------------

    #[test]
    fn parses_full_run_args() {
        let cfg = parse_run_args(&[
            "--listen".into(),
            "127.0.0.1:41001".into(),
            "--address".into(),
            "pcn~1000-0000-00001".into(),
            "--address".into(),
            "pcn~2000-0000-00002".into(),
            "--next-hop".into(),
            "1=127.0.0.1:41002".into(),
            "--next-hop=2=127.0.0.1:41003".into(), // inline form
            "--route".into(),
            "pcn~1000-0000-00009=1".into(),
            "--route".into(),
            "pcn~1000-0000-0000A=2".into(),
        ])
        .unwrap();
        assert_eq!(cfg.listen, ep(41001));
        assert_eq!(cfg.local_addrs.len(), 2);
        assert_eq!(cfg.next_hops[&NextHopId(2)], ep(41003));
        assert_eq!(cfg.routes.lookup(addr(9)), Some(NextHopId(1)));
        assert_eq!(cfg.routes.len(), 2);
    }

    #[test]
    fn parse_rejects_missing_or_bad_listen() {
        assert!(parse_run_args(&["--address".into(), "pcn~1000-0000-00001".into()]).is_err());
        for bad in [
            "127.0.0.1",
            "127.0.0.1:99999",
            "nope:41001",
            "127.0.0.1:abc",
        ] {
            let err = parse_run_args(&[
                "--listen".into(),
                bad.into(),
                "--address".into(),
                "pcn~1000-0000-00001".into(),
            ]);
            assert!(err.is_err(), "listen '{bad}' must be rejected");
        }
    }

    #[test]
    fn parse_rejects_bad_or_non_routable_address() {
        for bad in [
            "garbage",
            "pcn~1K4M-2X9R-06D3I",
            "pcn~3K4M-2X9R-06D3P", // type 3 unsupported
            "pcn~0000-0000-00000", // unspecified
        ] {
            let err = parse_run_args(&[
                "--listen".into(),
                "127.0.0.1:41001".into(),
                "--address".into(),
                bad.into(),
            ]);
            assert!(err.is_err(), "address '{bad}' must be rejected");
        }
    }

    #[test]
    fn parse_rejects_missing_address() {
        assert!(parse_run_args(&["--listen".into(), "127.0.0.1:41001".into()]).is_err());
    }

    #[test]
    fn parse_rejects_route_to_undefined_next_hop() {
        let err = parse_run_args(&[
            "--listen".into(),
            "127.0.0.1:41001".into(),
            "--address".into(),
            "pcn~1000-0000-00001".into(),
            "--route".into(),
            "pcn~1000-0000-00009=7".into(), // no --next-hop 7
        ])
        .unwrap_err();
        assert!(err.contains("undefined next-hop"), "{err}");
    }

    #[test]
    fn parse_rejects_duplicate_route_and_hop() {
        let base = [
            "--listen".into(),
            "127.0.0.1:41001".into(),
            "--address".into(),
            "pcn~1000-0000-00001".into(),
        ];
        let mut dup_hop = base.to_vec();
        dup_hop.extend([
            "--next-hop".into(),
            "1=127.0.0.1:41002".into(),
            "--next-hop".into(),
            "1=127.0.0.1:41003".into(),
        ]);
        assert!(parse_run_args(&dup_hop).is_err());

        let mut dup_route = base.to_vec();
        dup_route.extend([
            "--next-hop".into(),
            "1=127.0.0.1:41002".into(),
            "--route".into(),
            "pcn~1000-0000-00009=1".into(),
            "--route".into(),
            "pcn~1000-0000-00009=1".into(),
        ]);
        assert!(parse_run_args(&dup_route).is_err());
    }

    // --- packet pipeline ----------------------------------------------

    #[test]
    fn handle_delivers_to_local_address() {
        let cfg = config();
        let wire = packet(addr(2), addr(1), 64).encode();
        // DATA to a local address: deliver, then the ACK's routing
        // outcome (no route to the sender -> dropped ACK).
        match handle(&cfg, &wire) {
            Action::DeliverThen { packet: p, then } => {
                assert_eq!(p.header().destination(), addr(1));
                assert_eq!(p.payload(), b"x");
                assert!(matches!(
                    *then,
                    Action::Drop {
                        reason: DropReason::NoRoute,
                        ..
                    }
                ));
            }
            other => panic!("expected DeliverThen, got {other:?}"),
        }
    }

    #[test]
    fn handle_local_delivery_wins_over_hop_limit_edge() {
        let cfg = config();
        for hl in [1, 0] {
            let wire = packet(addr(2), addr(1), hl).encode();
            assert!(
                matches!(handle(&cfg, &wire), Action::DeliverThen { .. }),
                "local packet with hop_limit {hl} must be delivered"
            );
        }
    }

    #[test]
    fn handle_forwards_with_decrement_and_endpoint() {
        let cfg = config();
        let wire = packet(addr(2), addr(9), 64).encode();
        match handle(&cfg, &wire) {
            Action::Send {
                packet, endpoint, ..
            } => {
                assert_eq!(endpoint, ep(44002));
                let h = packet.header();
                assert_eq!(h.hop_limit(), 63);
                assert_eq!(h.source(), addr(2));
                assert_eq!(h.destination(), addr(9));
                assert_eq!(h.packet_type(), PacketType::Data);
                assert_eq!(h.packet_id(), 7);
                assert_eq!(packet.payload(), b"x");
            }
            other => panic!("expected Send, got {other:?}"),
        }
    }

    #[test]
    fn handle_drops_without_route_never_bounces_back() {
        let cfg = config();
        // No route to addr(10): the packet must be dropped, and nothing
        // is ever sent - in particular not to the sender's address.
        let wire = packet(addr(2), addr(10), 64).encode();
        match handle(&cfg, &wire) {
            Action::Drop { reason, .. } => assert_eq!(reason, DropReason::NoRoute),
            other => panic!("expected Drop(NoRoute), got {other:?}"),
        }
    }

    #[test]
    fn handle_drops_transit_at_hop_limit_edge() {
        let cfg = config();
        for hl in [1, 0] {
            let wire = packet(addr(2), addr(9), hl).encode();
            match handle(&cfg, &wire) {
                Action::Drop { reason, .. } => {
                    assert_eq!(reason, DropReason::HopLimitExhausted)
                }
                other => panic!("expected Drop(HopLimitExhausted) for hl {hl}, got {other:?}"),
            }
        }
    }

    /// Config whose node can route replies back to requester addr(2).
    fn config_with_return_route() -> NodeConfig {
        let mut cfg = config();
        cfg.next_hops.insert(NextHopId(3), ep(44003));
        cfg.routes.insert(addr(2), NextHopId(3));
        cfg
    }

    #[test]
    fn handle_answers_local_echo_request_via_routing() {
        let cfg = config_with_return_route();
        let wire = Packet::echo_request(addr(2), addr(1), 77, b"ping")
            .unwrap()
            .encode();
        match handle(&cfg, &wire) {
            Action::Send {
                packet, endpoint, ..
            } => {
                let h = packet.header();
                assert_eq!(h.packet_type(), PacketType::EchoReply);
                // Mirrored addresses, preserved correlation fields.
                assert_eq!(h.source(), addr(1));
                assert_eq!(h.destination(), addr(2));
                assert_eq!(h.packet_id(), 77);
                assert_eq!(packet.payload(), b"ping");
                // Originated packet: full hop budget, normal send path.
                assert_eq!(h.hop_limit(), 64);
                assert_eq!(endpoint, ep(44003));
            }
            other => panic!("expected Send(ECHO_REPLY), got {other:?}"),
        }
    }

    #[test]
    fn handle_drops_reply_when_no_return_route() {
        // config() has no route to requester addr(2): the reply must be
        // dropped by routing - never bounced to the UDP sender.
        let cfg = config();
        let wire = Packet::echo_request(addr(2), addr(1), 77, b"ping")
            .unwrap()
            .encode();
        match handle(&cfg, &wire) {
            Action::Drop { reason, packet } => {
                assert_eq!(reason, DropReason::NoRoute);
                assert_eq!(packet.header().packet_type(), PacketType::EchoReply);
            }
            other => panic!("expected Drop(NoRoute) for reply, got {other:?}"),
        }
    }

    #[test]
    fn handle_never_answers_an_echo_reply() {
        let cfg = config_with_return_route();
        let req = Packet::echo_request(addr(1), addr(2), 5, b"x").unwrap();
        let reply_wire = req.echo_reply().unwrap().encode();
        // A reply addressed to our local addr(1) is just Deliver - not
        // Send; answering a reply would loop forever.
        match handle(&cfg, &reply_wire) {
            Action::Deliver(p) => {
                assert_eq!(p.header().packet_type(), PacketType::EchoReply)
            }
            other => panic!("expected Deliver for ECHO_REPLY, got {other:?}"),
        }
    }

    #[test]
    fn handle_data_delivers_then_routes_ack() {
        let cfg = config_with_return_route();
        let data = Packet::builder(PacketType::Data, addr(2), addr(1))
            .packet_id(0xBEEF)
            .payload(b"hello".to_vec())
            .build()
            .unwrap();
        match handle(&cfg, &data.encode()) {
            Action::DeliverThen { packet, then } => {
                assert_eq!(packet, data);
                // The ACK goes through routing like any originated
                // packet - here: forwarded to the sender's next hop.
                match *then {
                    Action::Send {
                        packet: ack,
                        endpoint,
                        ..
                    } => {
                        let h = ack.header();
                        assert_eq!(h.packet_type(), PacketType::Ack);
                        assert_eq!(h.source(), addr(1));
                        assert_eq!(h.destination(), addr(2));
                        assert_eq!(h.packet_id(), 0xBEEF);
                        assert_eq!(endpoint, ep(44003));
                    }
                    other => panic!("expected Send(ACK), got {other:?}"),
                }
            }
            other => panic!("expected DeliverThen, got {other:?}"),
        }
    }

    #[test]
    fn handle_data_without_return_route_drops_ack_but_delivers() {
        let cfg = config(); // no route back to addr(2)
        let wire = Packet::builder(PacketType::Data, addr(2), addr(1))
            .packet_id(7)
            .payload(b"hi".to_vec())
            .build()
            .unwrap()
            .encode();
        match handle(&cfg, &wire) {
            Action::DeliverThen { then, .. } => match *then {
                Action::Drop { reason, packet } => {
                    assert_eq!(reason, DropReason::NoRoute);
                    assert_eq!(packet.header().packet_type(), PacketType::Ack);
                }
                other => panic!("expected Drop(NoRoute) for ACK, got {other:?}"),
            },
            other => panic!("expected DeliverThen, got {other:?}"),
        }
    }

    #[test]
    fn handle_never_acks_an_ack() {
        // An ACK addressed to us is just Deliver - never DeliverThen.
        let cfg = config();
        let data = Packet::builder(PacketType::Data, addr(1), addr(2))
            .packet_id(1)
            .build()
            .unwrap();
        let wire = data.ack().unwrap().encode();
        assert!(matches!(handle(&cfg, &wire), Action::Deliver(_)));
    }

    #[test]
    fn handle_never_panics_on_malformed() {
        let cfg = config();
        for bytes in [
            &[][..],
            &[0u8; 10][..],
            &[0xff; 32][..],
            &packet(addr(2), addr(9), 64).encode()[..31], // truncated
        ] {
            assert!(
                matches!(handle(&cfg, bytes), Action::Malformed(_)),
                "input of len {} must parse-fail cleanly",
                bytes.len()
            );
        }
    }
}
