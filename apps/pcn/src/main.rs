//! `pcn` - PCN command-line client.
//!
//! * `pcn ping` - probes a PCN address with ECHO_REQUEST packets carried
//!   as real PCN-over-UDP datagrams. The client IS a PCN endpoint: it
//!   owns the `--source` address and binds `--listen`; routers on the
//!   path must have a route back to that source address for the
//!   ECHO_REPLY to arrive. Probes are sequential - at most one request
//!   is outstanding at a time.
//! * `pcn send` / `pcn recv` - DATA packets carrying UTF-8 payloads.
//!   `send` waits for the destination's ACK (bounded retries); exit 0
//!   requires a matching ACK, `--no-ack` restores fire-and-forget.

use pcn_address::Address;
use pcn_packet::{Packet, PacketType, MAX_PACKET_LEN, PROTOCOL_VERSION};
use pcn_registry_proto::{read_frame, write_frame, Request, Response};
use pcn_transport::Transport;
use pcn_transport_udp::UdpTransport;
use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const USAGE: &str = "\
pcn - PCN command-line client

USAGE:
    pcn <command>

COMMANDS:
    ping            Probe a PCN address with ECHO_REQUEST/ECHO_REPLY
    send            Send a DATA packet (UTF-8 message) to a PCN address
    recv            Receive DATA packets addressed to a local PCN address
    gateway         Show or set the default gateway
    address         Request/inspect a registered PCN address
    version         Print version information";

const PING_USAGE: &str = "\
pcn ping - probe a PCN address with ECHO_REQUEST/ECHO_REPLY over UDP

USAGE:
    pcn ping --listen HOST:PORT --source ADDR --target ADDR --via HOST:PORT [options]

OPTIONS:
    --listen HOST:PORT    local UDP endpoint to bind (required); this is
                          the return endpoint - the network must route
                          your --source address back to it
    --source ADDR         local PCN address, pcn~ form or bare body
    --target ADDR         destination PCN address to probe
    --via HOST:PORT       UDP endpoint of the first hop (default:
                          $PCN_VIA, then ~/.pcn/gateway - see
                          'pcn gateway')
    --count N             number of probes (default 4)
    --interval-ms MS      delay between probes (default 1000)
    --timeout-ms MS       per-probe reply timeout (default 1000)
    --payload-size BYTES  ECHO payload size (default 32)

Probes are sequential: one outstanding request at a time.
Exit code: 0 = at least one reply, 1 = total loss or I/O error, 2 = bad
arguments.";

const SEND_USAGE: &str = "\
pcn send - send a DATA packet to a PCN address (ACKed by default)

USAGE:
    pcn send --listen HOST:PORT --source ADDR --target ADDR
             --via HOST:PORT --message TEXT

OPTIONS:
    --listen HOST:PORT    local UDP endpoint to bind (required)
    --source ADDR         local PCN address, pcn~ form or bare body
    --target ADDR         destination PCN address
    --via HOST:PORT       UDP endpoint of the first hop (default:
                          $PCN_VIA, then ~/.pcn/gateway)
    --message TEXT        UTF-8 message payload (required)
    --timeout-ms MS       per-attempt ACK timeout (default 1000)
    --retries N           retransmissions after a timeout (default 2)
    --no-ack              fire-and-forget: do not wait for an ACK

By default send waits for an ACK packet from the destination; exit 0
means the destination endpoint acknowledged the exact message (type,
both addresses, and packet_id must match - a bare id is not proof).
Each retry resends the SAME packet_id: if the ACK was lost, the
receiver sees a duplicate and must dedup it - it still ACKs again.
Exit code: 0 = acknowledged (or sent with --no-ack), 1 = timeout or
I/O error, 2 = bad arguments.";

const RECV_USAGE: &str = "\
pcn recv - receive DATA packets addressed to a local PCN address

USAGE:
    pcn recv --listen HOST:PORT --source ADDR

OPTIONS:
    --listen HOST:PORT    local UDP endpoint to bind (required)
    --source ADDR         local PCN address to receive on
    --via HOST:PORT       UDP endpoint for ACKs back to senders
                          (default: $PCN_VIA, then ~/.pcn/gateway;
                          none configured = passive sink, acked
                          'pcn send' will time out)

Prints one line per matching DATA packet:
    data from pcn~...: <utf8 text or 0x hex>
With --via, every matching DATA packet is acknowledged - including
retransmissions, which print as 'data from ... (duplicate): ...'.
All other datagrams (ECHO, foreign destinations, malformed bytes) are
ignored. Runs until interrupted. Nodes sending to --source must route
it to this --listen endpoint - there is no implicit return routing.";

const GATEWAY_USAGE: &str = "\
pcn gateway - show or set the default PCN gateway

USAGE:
    pcn gateway              show the effective gateway and its source
    pcn gateway set H:P      store H:P in ~/.pcn/gateway

A gateway is a physical UDP endpoint (HOST:PORT), not a PCN address.
Precedence for every command that needs one:
    --via flag > $PCN_VIA > ~/.pcn/gateway file";

const ADDRESS_USAGE: &str = "\
pcn address - registered PCN address management

USAGE:
    pcn address request --name NAME [--address ADDR]
    pcn address lookup (--name NAME | --address ADDR)
    pcn address list
    pcn address reserve --name NAME --address ADDR
    pcn address show

OPTIONS:
    --registry HOST:PORT   registry endpoint (default: $PCN_REGISTRY,
                           then ~/.pcn/registry)

'request' allocates (or returns the existing) private address for
NAME and stores it in ~/.pcn/address; 'show' prints that local record
without contacting the registry. 'reserve' strictly claims an exact
address for a new name. Repeating 'request' is idempotent; a name
holding a different address than requested is a conflict, not a
reallocation.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("ping") => ping_command(&args[1..]),
        Some("send") => send_command(&args[1..]),
        Some("recv") => recv_command(&args[1..]),
        Some("gateway") => gateway_command(&args[1..]),
        Some("address") => address_command(&args[1..]),
        Some("version") | Some("--version") | Some("-V") => {
            println!("pcn (wire version {PROTOCOL_VERSION})");
            ExitCode::SUCCESS
        }
        Some("help") | Some("--help") | Some("-h") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unknown command '{other}'");
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// `pcn ping` configuration, produced by [`parse_ping_args`].
#[derive(Debug)]
struct PingConfig {
    /// Local UDP endpoint the client binds - the reply destination
    /// on the wire, resolved by routing the `source` PCN address.
    listen: SocketAddr,
    /// Our PCN address; the request's source and the reply's
    /// destination.
    source: Address,
    /// The probed PCN address; the request's destination.
    target: Address,
    /// UDP endpoint of the first hop; resolved from --via, $PCN_VIA or
    /// ~/.pcn/gateway by the command layer.
    via: Option<SocketAddr>,
    /// Number of probes.
    count: u32,
    /// Delay between probes.
    interval: Duration,
    /// Per-probe reply timeout.
    timeout: Duration,
    /// ECHO payload size in bytes.
    payload_size: usize,
}

fn ping_command(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{PING_USAGE}");
        return ExitCode::SUCCESS;
    }
    let mut config = match parse_ping_args(args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };
    config.via = match require_gateway(config.via) {
        Ok(v) => Some(v),
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    match ping(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// `true` when `packet` answers our pending probe: an ECHO_REPLY from
/// the probe target, addressed to our source, carrying our packet_id.
/// Type, both addresses, and id must all match - a bare id is not proof.
fn match_reply(packet: &Packet, target: Address, source: Address, packet_id: u32) -> bool {
    let h = packet.header();
    h.packet_type() == PacketType::EchoReply
        && h.source() == target
        && h.destination() == source
        && h.packet_id() == packet_id
}

/// `true` when `packet` acknowledges our pending DATA message: an ACK
/// from the target endpoint, addressed to our source, carrying the
/// DATA `packet_id`. Same triple check as ping's reply matching.
fn match_ack(packet: &Packet, target: Address, source: Address, packet_id: u32) -> bool {
    let h = packet.header();
    h.packet_type() == PacketType::Ack
        && h.source() == target
        && h.destination() == source
        && h.packet_id() == packet_id
}

/// Waits until `deadline` for a packet satisfying `matches`; unrelated
/// or malformed datagrams are consumed and ignored. Returns the
/// elapsed time from `sent_at` on a monotonic clock.
///
/// # Errors
/// Propagates unexpected socket errors; timeout expiry is not an error -
/// it returns `Ok(None)`.
fn await_matching(
    transport: &UdpTransport,
    sent_at: Instant,
    deadline: Instant,
    matches: impl Fn(&Packet) -> bool,
) -> io::Result<Option<Duration>> {
    let mut buf = vec![0u8; MAX_PACKET_LEN];
    loop {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(None);
        };
        transport.set_read_timeout(Some(left))?;
        match transport.recv_from(&mut buf) {
            Ok((n, _from)) => {
                if let Ok(p) = Packet::parse(&buf[..n]) {
                    if matches(&p) {
                        return Ok(Some(sent_at.elapsed()));
                    }
                }
                // Anything else - malformed bytes, foreign packets,
                // mismatched replies - is ignored, never fatal.
            }
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => return Ok(None),
                io::ErrorKind::Interrupted => continue,
                _ => return Err(e),
            },
        }
    }
}

/// Waits for the matching ECHO_REPLY until `deadline`.
fn await_reply(
    transport: &UdpTransport,
    deadline: Instant,
    sent_at: Instant,
    config: &PingConfig,
    packet_id: u32,
) -> io::Result<Option<Duration>> {
    await_matching(transport, sent_at, deadline, |p| {
        match_reply(p, config.target, config.source, packet_id)
    })
}

/// min/avg/max over RTT samples. `None` when empty.
fn rtt_stats(rtts: &[Duration]) -> Option<(Duration, Duration, Duration)> {
    if rtts.is_empty() {
        return None;
    }
    let mut min = rtts[0];
    let mut max = rtts[0];
    let mut total_micros: u128 = 0;
    for &r in rtts {
        min = min.min(r);
        max = max.max(r);
        total_micros += r.as_micros();
    }
    let avg = Duration::from_micros((total_micros / rtts.len() as u128) as u64);
    Some((min, avg, max))
}

/// Per-process packet-id seed: wall-clock nanos plus pid. Not
/// crypto-unique; unique enough that a single sequential client cannot
/// collide with itself and two clients started the same second differ.
fn packet_id_seed() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos ^ std::process::id()
}

/// Runs the probe loop: `count` sequential ECHO_REQUESTs through `via`,
/// per-probe reply lines, and a closing loss/RTT summary.
///
/// # Errors
/// Returns an `Err` message on bind/send failures or a complete loss of
/// replies - so the CLI exits nonzero on total failure.
fn ping(config: &PingConfig) -> Result<(), String> {
    let via = config.via.expect("via resolved by ping_command");
    let transport = UdpTransport::bind(config.listen)
        .map_err(|e| format!("cannot bind {}: {e}", config.listen))?;
    println!(
        "ping {} from {} via {} (listening on {})",
        config.target,
        config.source,
        via,
        transport
            .local_endpoint()
            .map_err(|e| format!("local addr: {e}"))?
    );

    let seed = packet_id_seed();
    let payload = vec![0xabu8; config.payload_size];
    let mut received = 0u32;
    let mut rtts: Vec<Duration> = Vec::new();

    for seq in 0..config.count {
        let packet_id = seed.wrapping_add(seq);
        let request = Packet::echo_request(config.source, config.target, packet_id, &payload)
            .map_err(|e| format!("cannot build ECHO_REQUEST: {e}"))?;
        let wire = request.encode();

        let sent_at = Instant::now();
        transport
            .send_to(&wire, &via)
            .map_err(|e| format!("send to {via}: {e}"))?;
        let deadline = sent_at + config.timeout;

        match await_reply(&transport, deadline, sent_at, config, packet_id) {
            Ok(Some(rtt)) => {
                received += 1;
                rtts.push(rtt);
                println!(
                    "reply from {}: id=0x{packet_id:08x} rtt={:.3} ms",
                    config.target,
                    rtt.as_secs_f64() * 1000.0
                );
            }
            Ok(None) => println!("request id=0x{packet_id:08x}: timeout"),
            Err(e) => return Err(format!("receive error: {e}")),
        }

        if seq + 1 < config.count {
            std::thread::sleep(config.interval);
        }
    }

    let lost = config.count - received;
    let loss_pct = (lost as f64 / config.count as f64) * 100.0;
    println!("--- ping statistics ---");
    println!(
        "{} sent, {} received, {} lost ({loss_pct:.0}% loss)",
        config.count, received, lost
    );
    if let Some((min, avg, max)) = rtt_stats(&rtts) {
        println!(
            "rtt min/avg/max = {:.3}/{:.3}/{:.3} ms",
            min.as_secs_f64() * 1000.0,
            avg.as_secs_f64() * 1000.0,
            max.as_secs_f64() * 1000.0
        );
    }

    if received == 0 {
        return Err(format!("no replies from {}", config.target));
    }
    Ok(())
}

/// Grabs the value for a flag: `--flag=value` or the next argument.
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

fn parse_endpoint(s: &str, flag: &str) -> Result<SocketAddr, String> {
    s.parse::<SocketAddr>()
        .map_err(|_| format!("{flag}: '{s}' is not a valid socket address (expected HOST:PORT)"))
}

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

fn parse_u32(s: &str, flag: &str) -> Result<u32, String> {
    s.parse::<u32>()
        .map_err(|_| format!("{flag}: '{s}' is not a positive integer"))
}

fn parse_duration_ms(s: &str, flag: &str) -> Result<Duration, String> {
    let ms = parse_u32(s, flag)?;
    if ms == 0 {
        return Err(format!("{flag}: must be at least 1 ms"));
    }
    Ok(Duration::from_millis(u64::from(ms)))
}

/// Parses `pcn ping` arguments into a [`PingConfig`].
fn parse_ping_args(args: &[String]) -> Result<PingConfig, String> {
    let mut listen = None;
    let mut source = None;
    let mut target = None;
    let mut via = None;
    let mut count = 4u32;
    let mut interval = Duration::from_secs(1);
    let mut timeout = Duration::from_secs(1);
    let mut payload_size = 32usize;

    let mut i = 0;
    while i < args.len() {
        let (flag, inline) = match args[i].split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v)),
            _ => (args[i].as_str(), None),
        };
        match flag {
            "--listen" => listen = Some(parse_endpoint(take(args, &mut i, inline, flag)?, flag)?),
            "--source" => source = Some(parse_address(take(args, &mut i, inline, flag)?, flag)?),
            "--target" => target = Some(parse_address(take(args, &mut i, inline, flag)?, flag)?),
            "--via" => via = Some(parse_endpoint(take(args, &mut i, inline, flag)?, flag)?),
            "--count" => {
                count = parse_u32(take(args, &mut i, inline, flag)?, flag)?;
                if count == 0 {
                    return Err("--count: must be at least 1".to_string());
                }
            }
            "--interval-ms" => {
                interval = parse_duration_ms(take(args, &mut i, inline, flag)?, flag)?
            }
            "--timeout-ms" => timeout = parse_duration_ms(take(args, &mut i, inline, flag)?, flag)?,
            "--payload-size" => {
                payload_size = usize::try_from(parse_u32(take(args, &mut i, inline, flag)?, flag)?)
                    .map_err(|_| format!("{flag}: value too large"))?;
                if payload_size > pcn_packet::MAX_PAYLOAD_LEN {
                    return Err(format!(
                        "--payload-size: exceeds max payload {}",
                        pcn_packet::MAX_PAYLOAD_LEN
                    ));
                }
            }
            other => return Err(format!("unknown option '{other}'")),
        }
        i += 1;
    }

    Ok(PingConfig {
        listen: listen.ok_or("ping requires --listen HOST:PORT")?,
        source: source.ok_or("ping requires --source ADDR")?,
        target: target.ok_or("ping requires --target ADDR")?,
        via,
        count,
        interval,
        timeout,
        payload_size,
    })
}

/// `pcn send` configuration.
#[derive(Debug)]
struct SendConfig {
    /// Local UDP endpoint the client binds.
    listen: SocketAddr,
    /// Our PCN address; the packet's source.
    source: Address,
    /// Destination PCN address.
    target: Address,
    /// UDP endpoint of the first hop; resolved from --via, $PCN_VIA or
    /// ~/.pcn/gateway by the command layer.
    via: Option<SocketAddr>,
    /// UTF-8 message; becomes the DATA payload byte-for-byte.
    message: String,
    /// Per-attempt ACK timeout.
    timeout: Duration,
    /// Retransmissions after each timeout.
    retries: u32,
    /// Skip waiting for an ACK entirely (fire-and-forget).
    no_ack: bool,
}

fn send_command(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{SEND_USAGE}");
        return ExitCode::SUCCESS;
    }
    let mut config = match parse_send_args(args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };
    config.via = match require_gateway(config.via) {
        Ok(v) => Some(v),
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    match send(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Sends the DATA packet to `via`, then (unless `--no-ack`) waits for
/// the destination's ACK with bounded retries. All retransmissions
/// carry the SAME `packet_id` - a retried packet is a duplicate by
/// design and the receiver dedups it by (source, id).
fn send(config: &SendConfig) -> Result<(), String> {
    let transport = UdpTransport::bind(config.listen)
        .map_err(|e| format!("cannot bind {}: {e}", config.listen))?;
    let packet_id = packet_id_seed();
    let packet = Packet::builder(PacketType::Data, config.source, config.target)
        .packet_id(packet_id)
        .payload(config.message.as_bytes())
        .build()
        .map_err(|e| format!("cannot build DATA packet: {e}"))?;
    let wire = packet.encode();
    let via = config.via.expect("via resolved by send_command");

    if config.no_ack {
        transport
            .send_to(&wire, &via)
            .map_err(|e| format!("send to {via}: {e}"))?;
        println!(
            "sent {} B DATA {} -> {} via {via} (id=0x{packet_id:08x}); unacknowledged",
            packet.payload().len(),
            config.source,
            config.target
        );
        return Ok(());
    }

    let attempts = 1 + config.retries;
    for attempt in 1..=attempts {
        let sent_at = Instant::now();
        transport
            .send_to(&wire, &via)
            .map_err(|e| format!("send to {via}: {e}"))?;
        match await_matching(&transport, sent_at, sent_at + config.timeout, |p| {
            match_ack(p, config.target, config.source, packet_id)
        })
        .map_err(|e| format!("receive error: {e}"))?
        {
            Some(rtt) => {
                println!(
                    "acknowledged by {} in {:.3} ms (id=0x{packet_id:08x}, attempt {attempt}/{attempts})",
                    config.target,
                    rtt.as_secs_f64() * 1000.0
                );
                return Ok(());
            }
            None => println!("timeout waiting for ACK (attempt {attempt}/{attempts})"),
        }
    }
    Err(format!(
        "no ACK after {attempts} attempts - message not confirmed delivered"
    ))
}

/// `pcn recv` configuration.
#[derive(Debug)]
struct RecvConfig {
    /// Local UDP endpoint the client binds.
    listen: SocketAddr,
    /// Our PCN address; only DATA addressed to it is reported.
    source: Address,
    /// UDP endpoint ACKs are sent to (first hop back to the sender);
    /// `None` = passive sink, never acknowledges.
    via: Option<SocketAddr>,
}

/// `true` for a DATA packet addressed to `local`. ECHO and packets for
/// other destinations are not application data and are ignored.
fn is_data_for(packet: &Packet, local: Address) -> bool {
    let h = packet.header();
    h.packet_type() == PacketType::Data && h.destination() == local
}

/// Renders payload bytes for output: UTF-8 text verbatim, anything
/// else as hex (capped at 64 bytes displayed).
fn fmt_payload(payload: &[u8]) -> String {
    use std::fmt::Write as _;
    match std::str::from_utf8(payload) {
        Ok(text) => text.to_string(),
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

fn recv_command(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{RECV_USAGE}");
        return ExitCode::SUCCESS;
    }
    let mut config = match parse_recv_args(args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };
    // recv may legitimately run without a gateway (passive sink), so
    // an unconfigured gateway is not an error here - an invalid one is.
    config.via = match resolve_gateway(config.via) {
        Ok(v) => v.map(|(ep, _)| ep),
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };
    match recv(&config) {
        // recv() only returns on error; normal exit is via signal.
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Blocking receive loop: prints every DATA packet for `config.source`.
///
/// # Errors
/// Socket bind/receive failures. Malformed datagrams and non-DATA or
/// foreign-destination packets are consumed and ignored.
fn recv(config: &RecvConfig) -> Result<(), String> {
    let transport = UdpTransport::bind(config.listen)
        .map_err(|e| format!("cannot bind {}: {e}", config.listen))?;
    println!(
        "receiving DATA for {} on {}{}",
        config.source,
        transport
            .local_endpoint()
            .map_err(|e| format!("local addr: {e}"))?,
        match config.via {
            Some(v) => format!(", ACKs via {v}"),
            None => String::from(", passive (no ACKs - set --via to acknowledge)"),
        }
    );
    // Bounded dedup: retried DATA (same source+packet_id) is printed
    // once, but still re-ACKed - the sender may have lost the first ACK.
    let mut seen: HashSet<(Address, u32)> = HashSet::new();
    let mut buf = vec![0u8; MAX_PACKET_LEN];
    loop {
        match transport.recv_from(&mut buf) {
            Ok((n, _from)) => {
                let Ok(p) = Packet::parse(&buf[..n]) else {
                    continue;
                };
                if !is_data_for(&p, config.source) {
                    continue;
                }
                let h = p.header();
                // Check first, evict a full cache, then insert: clearing
                // after insert would evict the just-seen key itself.
                let key = (h.source(), h.packet_id());
                let duplicate = if seen.contains(&key) {
                    true
                } else {
                    if seen.len() >= 4096 {
                        seen.clear();
                    }
                    seen.insert(key);
                    false
                };
                // ACK first, then report - even a duplicate gets its ACK
                // (it may be a retry after a lost one).
                if let Some(via) = config.via {
                    match p.ack() {
                        Ok(ack) => {
                            if let Err(e) = transport.send_to(&ack.encode(), &via) {
                                eprintln!("ACK send to {via} failed: {e}");
                            }
                        }
                        // Unreachable: p is DATA, ack() only rejects
                        // non-DATA. Log defensively, never panic.
                        Err(e) => eprintln!("cannot build ACK: {e}"),
                    }
                }
                println!(
                    "data from {}{}: {}",
                    h.source(),
                    if duplicate { " (duplicate)" } else { "" },
                    fmt_payload(p.payload())
                );
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("receive error: {e}")),
        }
    }
}

/// Parses `pcn send` arguments.
fn parse_send_args(args: &[String]) -> Result<SendConfig, String> {
    let mut listen = None;
    let mut source = None;
    let mut target = None;
    let mut via = None;
    let mut message = None;
    let mut timeout = Duration::from_millis(1000);
    let mut retries = 2u32;
    let mut no_ack = false;

    let mut i = 0;
    while i < args.len() {
        let (flag, inline) = match args[i].split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v)),
            _ => (args[i].as_str(), None),
        };
        match flag {
            "--listen" => listen = Some(parse_endpoint(take(args, &mut i, inline, flag)?, flag)?),
            "--source" => source = Some(parse_address(take(args, &mut i, inline, flag)?, flag)?),
            "--target" => target = Some(parse_address(take(args, &mut i, inline, flag)?, flag)?),
            "--via" => via = Some(parse_endpoint(take(args, &mut i, inline, flag)?, flag)?),
            "--timeout-ms" => timeout = parse_duration_ms(take(args, &mut i, inline, flag)?, flag)?,
            "--retries" => retries = parse_u32(take(args, &mut i, inline, flag)?, flag)?,
            "--no-ack" => {
                if inline.is_some() {
                    return Err("--no-ack takes no value".into());
                }
                no_ack = true;
            }
            "--message" => {
                let m = take(args, &mut i, inline, flag)?;
                if m.len() > pcn_packet::MAX_PAYLOAD_LEN {
                    return Err(format!(
                        "--message: exceeds max payload {} bytes",
                        pcn_packet::MAX_PAYLOAD_LEN
                    ));
                }
                message = Some(m.to_string());
            }
            other => return Err(format!("unknown option '{other}'")),
        }
        i += 1;
    }

    Ok(SendConfig {
        listen: listen.ok_or("send requires --listen HOST:PORT")?,
        source: source.ok_or("send requires --source ADDR")?,
        target: target.ok_or("send requires --target ADDR")?,
        via,
        message: message.ok_or("send requires --message TEXT")?,
        timeout,
        retries,
        no_ack,
    })
}

const NO_GATEWAY_HINT: &str = "configure one with: --via HOST:PORT, \
    PCN_VIA=HOST:PORT, or 'pcn gateway set HOST:PORT'";

const NO_REGISTRY_HINT: &str = "no registry configured: pass \
    --registry HOST:PORT, set PCN_REGISTRY=HOST:PORT, or write \
    HOST:PORT to ~/.pcn/registry";

/// Where the effective gateway came from (for `pcn gateway` output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GwSource {
    /// Explicit `--via`.
    Cli,
    /// `PCN_VIA` environment variable.
    Env,
    /// `~/.pcn/gateway` file.
    File,
}

impl GwSource {
    fn describe(self) -> &'static str {
        match self {
            Self::Cli => "from --via",
            Self::Env => "from PCN_VIA",
            Self::File => "from ~/.pcn/gateway",
        }
    }
}

/// The generic precedence chain: explicit flag > env > file. Injected
/// env/file contents keep this testable without touching the real
/// environment or HOME.
///
/// `Ok(Some)` = resolved, `Ok(None)` = nothing configured (callers
/// decide whether that is an error), `Err` = a configured value was
/// invalid. A present-but-bad env or file value is an error, never a
/// silent fallthrough to a lower-priority source.
fn resolve_endpoint_with(
    explicit: Option<SocketAddr>,
    env_label: &'static str,
    env_val: Option<String>,
    file_label: &'static str,
    file_val: Option<String>,
) -> Result<Option<(SocketAddr, GwSource)>, String> {
    if let Some(ep) = explicit {
        return Ok(Some((ep, GwSource::Cli)));
    }
    if let Some(raw) = env_val {
        let raw = raw.trim();
        if !raw.is_empty() {
            return parse_endpoint(raw, env_label).map(|ep| Some((ep, GwSource::Env)));
        }
    }
    if let Some(raw) = file_val {
        let raw = raw.trim();
        if !raw.is_empty() {
            return parse_endpoint(raw, file_label).map(|ep| Some((ep, GwSource::File)));
        }
    }
    Ok(None)
}

/// Gateway variant of [`resolve_endpoint_with`] - exercised by unit
/// tests; the binary itself goes through [`resolve_gateway`].
#[cfg(test)]
fn resolve_gateway_with(
    explicit: Option<SocketAddr>,
    env_val: Option<String>,
    file_val: Option<String>,
) -> Result<Option<(SocketAddr, GwSource)>, String> {
    resolve_endpoint_with(explicit, "PCN_VIA", env_val, "~/.pcn/gateway", file_val)
}

/// Reads the real environment and config file, then applies
/// [`resolve_endpoint_with`] for the gateway.
fn resolve_gateway(explicit: Option<SocketAddr>) -> Result<Option<(SocketAddr, GwSource)>, String> {
    let env_val = std::env::var("PCN_VIA").ok();
    let file_val = read_pcn_file("gateway")?;
    resolve_endpoint_with(explicit, "PCN_VIA", env_val, "~/.pcn/gateway", file_val)
}

/// Registry endpoint resolution: `--registry` > `PCN_REGISTRY` >
/// `~/.pcn/registry`.
fn resolve_registry(
    explicit: Option<SocketAddr>,
) -> Result<Option<(SocketAddr, GwSource)>, String> {
    let env_val = std::env::var("PCN_REGISTRY").ok();
    let file_val = read_pcn_file("registry")?;
    resolve_endpoint_with(
        explicit,
        "PCN_REGISTRY",
        env_val,
        "~/.pcn/registry",
        file_val,
    )
}

/// Reads `~/.pcn/<name>`; `Ok(None)` = missing or no HOME, `Err` =
/// present but unreadable (reported, not silently ignored).
fn read_pcn_file(name: &str) -> Result<Option<String>, String> {
    let Some(path) = pcn_file_path(name) else {
        return Ok(None);
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// `~/.pcn/<name>`; `None` when no home directory can be determined.
fn pcn_file_path(name: &str) -> Option<PathBuf> {
    std::env::home_dir().map(|h| h.join(".pcn").join(name))
}

/// For ping/send a gateway is mandatory: resolution must produce one,
/// with a clear how-to error otherwise.
fn require_gateway(explicit: Option<SocketAddr>) -> Result<SocketAddr, String> {
    match resolve_gateway(explicit)? {
        Some((ep, _)) => Ok(ep),
        None => Err(format!("no gateway configured: {NO_GATEWAY_HINT}")),
    }
}

/// `pcn gateway set H:P` - writes the endpoint to ~/.pcn/gateway,
/// creating the directory if needed.
fn write_gateway_file(ep: SocketAddr) -> Result<PathBuf, String> {
    write_pcn_file("gateway", &format!("{ep}\n"))
}

/// Writes `content` to `~/.pcn/<name>`, creating the directory if
/// needed. Returns the path written.
fn write_pcn_file(name: &str, content: &str) -> Result<PathBuf, String> {
    let path = pcn_file_path(name)
        .ok_or_else(|| format!("cannot determine home directory for ~/.pcn/{name}"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    std::fs::write(&path, content).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}

fn gateway_command(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{GATEWAY_USAGE}");
        return ExitCode::SUCCESS;
    }
    match args.first().map(String::as_str) {
        None => match resolve_gateway(None) {
            Ok(Some((ep, src))) => {
                println!("{ep} ({})", src.describe());
                ExitCode::SUCCESS
            }
            Ok(None) => {
                println!("no default gateway configured");
                println!("{NO_GATEWAY_HINT}");
                ExitCode::SUCCESS
            }
            Err(msg) => {
                eprintln!("error: {msg}");
                ExitCode::FAILURE
            }
        },
        Some("set") => match args.get(1) {
            Some(raw) => match parse_endpoint(raw, "gateway set") {
                Ok(ep) => match write_gateway_file(ep) {
                    Ok(path) => {
                        println!("default gateway: {ep} ({})", path.display());
                        ExitCode::SUCCESS
                    }
                    Err(msg) => {
                        eprintln!("error: {msg}");
                        ExitCode::FAILURE
                    }
                },
                Err(msg) => {
                    eprintln!("error: {msg}");
                    ExitCode::from(2)
                }
            },
            None => {
                eprintln!("error: 'gateway set' requires HOST:PORT");
                ExitCode::from(2)
            }
        },
        Some(other) => {
            eprintln!("error: unknown gateway argument '{other}'");
            eprintln!("{GATEWAY_USAGE}");
            ExitCode::from(2)
        }
    }
}

// ------------------------------------------------------------------
// `pcn address` - registry client
// ------------------------------------------------------------------

/// One TCP round-trip: send `req`, read one response frame. Both ends
/// bounded by a socket timeout; a closed or malformed stream errors.
fn registry_call(registry: SocketAddr, req: &Request) -> Result<Response, String> {
    let mut stream = TcpStream::connect_timeout(&registry, Duration::from_secs(5))
        .map_err(|e| format!("cannot reach registry {registry}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    write_frame(&mut stream, &req.encode()).map_err(|e| format!("send to registry: {e}"))?;
    let text = read_frame(&mut stream)
        .map_err(|e| format!("read from registry: {e}"))?
        .ok_or("registry closed the connection without a reply")?;
    Response::parse(&text).map_err(|(code, msg)| format!("{code}: {msg}"))
}

/// Prints a response or converts an `err` into the exit-1 message.
fn report(response: Result<Response, String>) -> Result<String, String> {
    match response {
        Ok(Response::Registered { name, addr }) => Ok(format!("{name} -> {addr}")),
        Ok(Response::Address(addr)) => Ok(format!("{addr}")),
        Ok(Response::Name(name)) => Ok(name),
        Ok(Response::List(entries)) => {
            if entries.is_empty() {
                Ok("(empty registry)".into())
            } else {
                Ok(entries
                    .iter()
                    .map(|(n, a)| format!("{n} {a}"))
                    .collect::<Vec<_>>()
                    .join("\n"))
            }
        }
        Ok(Response::Error { code, message }) => Err(format!("{code}: {message}")),
        Err(msg) => Err(msg),
    }
}

fn address_command(args: &[String]) -> ExitCode {
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{ADDRESS_USAGE}");
        return ExitCode::SUCCESS;
    }
    let (sub, rest) = (args[0].as_str(), &args[1..]);

    // Flags shared by the registry-talking subcommands.
    let mut registry = None;
    let mut name = None;
    let mut addr = None;
    let mut i = 0;
    let bad_args = |msg: String| -> ExitCode {
        eprintln!("error: {msg}");
        ExitCode::from(2)
    };
    while i < rest.len() {
        let (flag, inline) = match rest[i].split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v)),
            _ => (rest[i].as_str(), None),
        };
        let take = |i: &mut usize| -> Result<String, String> {
            if let Some(v) = inline {
                return Ok(v.to_string());
            }
            *i += 1;
            rest.get(*i)
                .cloned()
                .ok_or_else(|| format!("option '{flag}' requires a value"))
        };
        match flag {
            "--registry" => {
                let v = match take(&mut i) {
                    Ok(v) => v,
                    Err(m) => return bad_args(m),
                };
                match parse_endpoint(&v, "--registry") {
                    Ok(ep) => registry = Some(ep),
                    Err(m) => return bad_args(m),
                }
            }
            "--name" => {
                let v = match take(&mut i) {
                    Ok(v) => v,
                    Err(m) => return bad_args(m),
                };
                name = Some(v);
            }
            "--address" => {
                let v = match take(&mut i) {
                    Ok(v) => v,
                    Err(m) => return bad_args(m),
                };
                match v.parse::<Address>() {
                    Ok(a) => addr = Some(a),
                    Err(e) => return bad_args(format!("--address: '{v}': {e}")),
                }
            }
            other => return bad_args(format!("unknown option '{other}'")),
        }
        i += 1;
    }

    match sub {
        "show" => {
            // Local only - the last address `request` wrote.
            match read_pcn_file("address") {
                Ok(Some(text)) => {
                    println!("{}", text.trim());
                    ExitCode::SUCCESS
                }
                Ok(None) => {
                    println!("no local address (run 'pcn address request' first)");
                    ExitCode::SUCCESS
                }
                Err(m) => {
                    eprintln!("error: {m}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            // Registry endpoint is required for everything else.
            let reg = match resolve_registry(registry) {
                Ok(Some((ep, _))) => ep,
                Ok(None) => {
                    eprintln!("error: {NO_REGISTRY_HINT}");
                    return ExitCode::FAILURE;
                }
                Err(m) => {
                    eprintln!("error: {m}");
                    return ExitCode::FAILURE;
                }
            };
            let req = match sub {
                "request" => Request::Alloc {
                    name: match name {
                        Some(n) => n,
                        None => return bad_args("request requires --name NAME".into()),
                    },
                    preferred: addr,
                },
                "reserve" => match (name, addr) {
                    (Some(n), Some(a)) => Request::Reserve { name: n, addr: a },
                    _ => return bad_args("reserve requires --name NAME and --address ADDR".into()),
                },
                "lookup" => match (name, addr) {
                    (Some(n), None) => Request::Lookup { name: n },
                    (None, Some(a)) => Request::WhoIs { addr: a },
                    _ => return bad_args("lookup requires exactly one of --name/--address".into()),
                },
                "list" => Request::List,
                other => return bad_args(format!("unknown address subcommand '{other}'")),
            };
            // One round-trip; a successful request also persists the
            // local `~/.pcn/address` record for `pcn address show`.
            match registry_call(reg, &req) {
                Ok(resp) => {
                    if let Response::Registered { name, addr } = &resp {
                        let _ = write_pcn_file("address", &format!("{name} {addr}\n"));
                    }
                    match report(Ok(resp)) {
                        Ok(text) => {
                            println!("{text}");
                            ExitCode::SUCCESS
                        }
                        Err(m) => {
                            eprintln!("error: {m}");
                            ExitCode::FAILURE
                        }
                    }
                }
                Err(m) => {
                    eprintln!("error: {m}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// Parses `pcn recv` arguments.
fn parse_recv_args(args: &[String]) -> Result<RecvConfig, String> {
    let mut listen = None;
    let mut source = None;
    let mut via = None;

    let mut i = 0;
    while i < args.len() {
        let (flag, inline) = match args[i].split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v)),
            _ => (args[i].as_str(), None),
        };
        match flag {
            "--listen" => listen = Some(parse_endpoint(take(args, &mut i, inline, flag)?, flag)?),
            "--source" => source = Some(parse_address(take(args, &mut i, inline, flag)?, flag)?),
            "--via" => via = Some(parse_endpoint(take(args, &mut i, inline, flag)?, flag)?),
            other => return Err(format!("unknown option '{other}'")),
        }
        i += 1;
    }

    Ok(RecvConfig {
        listen: listen.ok_or("recv requires --listen HOST:PORT")?,
        source: source.ok_or("recv requires --source ADDR")?,
        via,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcn_address::AddressType;

    fn addr(value: u64) -> Address {
        Address::new(AddressType::Private, value)
    }

    fn request(src: Address, dst: Address, id: u32) -> Packet {
        Packet::echo_request(src, dst, id, b"probe").unwrap()
    }

    #[test]
    fn reply_matching_requires_everything() {
        let req = request(addr(1), addr(2), 77);
        let reply = req.echo_reply().unwrap();
        assert!(match_reply(&reply, addr(2), addr(1), 77));

        // Wrong id, wrong source, wrong destination, wrong type - each
        // alone must fail the match.
        assert!(!match_reply(&reply, addr(2), addr(1), 78));
        assert!(!match_reply(&reply, addr(9), addr(1), 77));
        assert!(!match_reply(&reply, addr(2), addr(9), 77));
        assert!(!match_reply(&req, addr(2), addr(1), 77)); // request, not reply
    }

    #[test]
    fn parse_minimal_and_defaults() {
        let cfg = parse_ping_args(&[
            "--listen".into(),
            "127.0.0.1:41001".into(),
            "--source".into(),
            "pcn~1000-0000-00001".into(),
            "--target".into(),
            "pcn~1000-0000-00002".into(),
            "--via".into(),
            "127.0.0.1:41002".into(),
        ])
        .unwrap();
        assert_eq!(cfg.count, 4);
        assert_eq!(cfg.interval, Duration::from_secs(1));
        assert_eq!(cfg.timeout, Duration::from_secs(1));
        assert_eq!(cfg.payload_size, 32);
    }

    #[test]
    fn parse_rejects_missing_and_bad() {
        // Missing each required flag.
        assert!(parse_ping_args(&[]).is_err());
        assert!(parse_ping_args(&[
            "--listen".into(),
            "127.0.0.1:41001".into(),
            "--source".into(),
            "pcn~1000-0000-00001".into(),
            "--via".into(),
            "127.0.0.1:41002".into(),
        ])
        .is_err()); // no --target

        // Bad endpoint, bad address, bad number, zero count.
        for bad_args in [
            vec!["--listen".into(), "nope".into()],
            vec!["--source".into(), "garbage".into()],
            vec!["--count".into(), "abc".into()],
            vec!["--count".into(), "0".into()],
            vec!["--timeout-ms".into(), "0".into()],
        ] {
            let mut full = vec![
                "--listen".into(),
                "127.0.0.1:41001".into(),
                "--source".into(),
                "pcn~1000-0000-00001".into(),
                "--target".into(),
                "pcn~1000-0000-00002".into(),
                "--via".into(),
                "127.0.0.1:41002".into(),
            ];
            full.extend(bad_args);
            assert!(parse_ping_args(&full).is_err(), "{full:?} must fail");
        }
    }

    #[test]
    fn ack_matching_requires_everything() {
        let data = Packet::builder(PacketType::Data, addr(1), addr(2))
            .packet_id(77)
            .payload(b"m".to_vec())
            .build()
            .unwrap();
        let ack = data.ack().unwrap();
        assert!(match_ack(&ack, addr(2), addr(1), 77));
        // Wrong id, wrong source, wrong destination, wrong type, late
        // ACK for a different message - each alone must fail.
        assert!(!match_ack(&ack, addr(2), addr(1), 78));
        assert!(!match_ack(&ack, addr(9), addr(1), 77));
        assert!(!match_ack(&ack, addr(2), addr(9), 77));
        assert!(!match_ack(&data, addr(2), addr(1), 77)); // DATA, not ACK
        let other = Packet::builder(PacketType::Data, addr(1), addr(2))
            .packet_id(78)
            .build()
            .unwrap()
            .ack()
            .unwrap();
        assert!(!match_ack(&other, addr(2), addr(1), 77));
    }

    #[test]
    fn send_parses_ack_controls() {
        let cfg = parse_send_args(&[
            "--listen".into(),
            "127.0.0.1:41001".into(),
            "--source".into(),
            "pcn~1000-0000-00001".into(),
            "--target".into(),
            "pcn~1000-0000-00002".into(),
            "--via".into(),
            "127.0.0.1:41002".into(),
            "--message".into(),
            "hi".into(),
            "--timeout-ms".into(),
            "250".into(),
            "--retries".into(),
            "5".into(),
            "--no-ack".into(),
        ])
        .unwrap();
        assert_eq!(cfg.timeout, Duration::from_millis(250));
        assert_eq!(cfg.retries, 5);
        assert!(cfg.no_ack);
        // --no-ack takes no value.
        assert!(parse_send_args(&[
            "--listen".into(),
            "127.0.0.1:41001".into(),
            "--source".into(),
            "pcn~1000-0000-00001".into(),
            "--target".into(),
            "pcn~1000-0000-00002".into(),
            "--via".into(),
            "127.0.0.1:41002".into(),
            "--message".into(),
            "hi".into(),
            "--no-ack=yes".into(),
        ])
        .is_err());
    }

    #[test]
    fn gateway_resolution_precedence() {
        let cli: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let env: SocketAddr = "127.0.0.1:2222".parse().unwrap();
        let file: SocketAddr = "127.0.0.1:3333".parse().unwrap();
        let env_s = || Some(env.to_string());
        let file_s = || Some(file.to_string());

        // Explicit flag wins over everything.
        assert_eq!(
            resolve_gateway_with(Some(cli), env_s(), file_s()).unwrap(),
            Some((cli, GwSource::Cli))
        );
        // Env wins over file.
        assert_eq!(
            resolve_gateway_with(None, env_s(), file_s()).unwrap(),
            Some((env, GwSource::Env))
        );
        // File used when nothing higher exists.
        assert_eq!(
            resolve_gateway_with(None, None, file_s()).unwrap(),
            Some((file, GwSource::File))
        );
        // Nothing anywhere.
        assert_eq!(resolve_gateway_with(None, None, None).unwrap(), None);
        // Empty values are treated as unset (not errors).
        assert_eq!(
            resolve_gateway_with(None, Some(String::new()), Some("  ".into())).unwrap(),
            None
        );
        // Invalid configured values error out - no silent fallthrough
        // to a lower-priority source.
        assert!(resolve_gateway_with(None, Some("junk".into()), file_s()).is_err());
        assert!(resolve_gateway_with(None, None, Some("junk".into())).is_err());
        assert!(resolve_gateway_with(None, env_s(), Some("junk".into())).is_ok());
    }

    #[test]
    fn data_matching_needs_type_and_destination() {
        let data = Packet::builder(PacketType::Data, addr(2), addr(1))
            .payload(b"hello".to_vec())
            .build()
            .unwrap();
        assert!(is_data_for(&data, addr(1)));
        assert!(!is_data_for(&data, addr(9))); // other destination
        let echo = Packet::echo_request(addr(2), addr(1), 1, b"hi").unwrap();
        assert!(!is_data_for(&echo, addr(1))); // ECHO, not DATA
    }

    #[test]
    fn send_requires_message_and_valid_flags() {
        assert!(parse_send_args(&[]).is_err());
        let ok = parse_send_args(&[
            "--listen".into(),
            "127.0.0.1:41001".into(),
            "--source".into(),
            "pcn~1000-0000-00001".into(),
            "--target".into(),
            "pcn~1000-0000-00002".into(),
            "--via".into(),
            "127.0.0.1:41002".into(),
            "--message".into(),
            "Zażółć gęślą jaźń".into(),
        ]);
        let cfg = ok.unwrap();
        assert_eq!(cfg.message, "Zażółć gęślą jaźń");
        // Missing --message must fail.
        assert!(parse_send_args(&[
            "--listen".into(),
            "127.0.0.1:41001".into(),
            "--source".into(),
            "pcn~1000-0000-00001".into(),
            "--target".into(),
            "pcn~1000-0000-00002".into(),
            "--via".into(),
            "127.0.0.1:41002".into(),
        ])
        .is_err());
    }

    #[test]
    fn recv_args_minimal() {
        let cfg = parse_recv_args(&[
            "--listen".into(),
            "127.0.0.1:41001".into(),
            "--source".into(),
            "pcn~1000-0000-00001".into(),
        ])
        .unwrap();
        assert_eq!(cfg.listen.port(), 41001);
        assert!(parse_recv_args(&["--listen".into(), "127.0.0.1:41001".into()]).is_err());
    }

    #[test]
    fn payload_rendering_utf8_or_hex() {
        assert_eq!(fmt_payload(b"plain"), "plain");
        assert_eq!(fmt_payload("Zażółć".as_bytes()), "Zażółć");
        assert_eq!(fmt_payload(&[0xff, 0x00]), "0xff00");
    }

    #[test]
    fn rtt_stats_min_avg_max() {
        let rtts = [
            Duration::from_micros(1000),
            Duration::from_micros(2000),
            Duration::from_micros(3000),
        ];
        let (min, avg, max) = rtt_stats(&rtts).unwrap();
        assert_eq!(min, Duration::from_micros(1000));
        assert_eq!(avg, Duration::from_micros(2000));
        assert_eq!(max, Duration::from_micros(3000));
        assert_eq!(rtt_stats(&[]), None);
    }
}
