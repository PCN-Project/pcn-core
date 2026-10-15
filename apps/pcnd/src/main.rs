//! `pcnd` - the PCN node daemon.
//!
//! * `pcnd run` - starts a real node: binds a UDP socket, parses PCN
//!   packets, delivers locally-destined packets (log only) and forwards
//!   transit packets per the static route table.
//! * `pcnd selftest` - exercises the `pcn-packet` codec (encode, parse,
//!   and each validation rejection path) and reports pass/fail.
//! * `pcnd check <hex>` - decodes a datagram supplied as hexadecimal and
//!   prints the header fields, or the precise reason it is invalid.
//!
//! No echo responder or ping yet - delivered packets are only logged.

mod node;

use pcn_address::{Address, AddressType};
use pcn_packet::{Packet, PacketType, ParseError, BASE_HEADER_LEN, PROTOCOL_VERSION};
use std::process::ExitCode;

const USAGE: &str = "\
pcnd - PCN node daemon

USAGE:
    pcnd <command>

COMMANDS:
    run             Start a PCN node (UDP + static routes; 'run --help' for flags)
    selftest        Run packet codec encode/parse/validation checks
    check <hex>     Decode a wire datagram given as hex and print its header
    version         Print version information";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => node::run_command(&args[1..]),
        Some("selftest") => selftest(),
        Some("check") => match args.get(1) {
            Some(hex) => check(hex),
            None => {
                eprintln!("error: 'check' requires a hex-encoded datagram");
                eprintln!("{USAGE}");
                ExitCode::from(2)
            }
        },
        Some("version") | Some("--version") | Some("-V") => {
            println!("pcnd (wire version {PROTOCOL_VERSION})");
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

/// Decodes a hex datagram and prints either the header or the rejection.
fn check(hex: &str) -> ExitCode {
    let bytes = match decode_hex(hex) {
        Ok(b) => b,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };
    match Packet::parse(&bytes) {
        Ok(packet) => {
            let h = packet.header();
            println!(
                "valid {} packet, {} bytes total",
                h.packet_type().name(),
                bytes.len()
            );
            println!("  version      = {PROTOCOL_VERSION}");
            println!(
                "  type         = {} (0x{:02x})",
                h.packet_type().name(),
                h.packet_type().to_u8()
            );
            println!("  header_len   = {}", h.header_len());
            println!("  payload_len  = {}", h.payload_len());
            println!("  hop_limit    = {}", h.hop_limit());
            println!("  source       = {}", h.source());
            println!("  destination  = {}", h.destination());
            println!("  packet_id    = 0x{:08x}", h.packet_id());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("invalid datagram: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Minimal hex decoder.
///
/// Accepts an optional `0x` prefix and ignores ASCII whitespace, so
/// `"01 02 03"` and `"010203"` are equivalent. Offsets in error messages
/// refer to the whitespace-stripped string.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let s = compact.strip_prefix("0x").unwrap_or(&compact);
    if s.len() % 2 != 0 {
        return Err("hex input has odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("invalid hex at offset {i}"))
        })
        .collect()
}

/// A selftest rejection case: corrupt `wire[offset] = value`, then check
/// that `Packet::parse` fails with an error matching `expect`.
type RejectCase = (&'static str, usize, u8, fn(&ParseError) -> bool);

/// Encode/parse/validate exercise. Returns process exit code.
fn selftest() -> ExitCode {
    let mut failures = 0u32;
    let mut run = |name: &str, ok: bool| {
        println!("  {name:<48} {}", if ok { "ok" } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };

    println!("pcnd selftest - packet codec (wire version {PROTOCOL_VERSION})");

    // 1. Roundtrip.
    let src = Address::new(AddressType::Private, 0x10);
    let dst = Address::new(AddressType::Public, 0x20);
    let packet = Packet::builder(PacketType::Data, src, dst)
        .packet_id(1)
        .payload(b"pcnd selftest".to_vec())
        .build();
    let roundtrip_ok = match &packet {
        Ok(p) => Packet::parse(&p.encode()).as_ref() == Ok(p),
        Err(_) => false,
    };
    run("encode/parse roundtrip", roundtrip_ok);

    // 2. Each validation path rejects a corrupted datagram.
    let wire = packet.as_ref().map(Packet::encode).unwrap_or_default();
    let cases: &[RejectCase] = &[
        ("rejects bad version", 0, 0x02, |e| {
            matches!(e, ParseError::UnsupportedVersion { .. })
        }),
        ("rejects unknown type", 1, 0x7f, |e| {
            matches!(e, ParseError::UnknownPacketType { .. })
        }),
        ("rejects flag bit", 2, 0x01, |e| {
            matches!(e, ParseError::UnsupportedFlags { .. })
        }),
        ("rejects reserved byte", 9, 0xff, |e| {
            matches!(e, ParseError::NonZeroReserved { .. })
        }),
        // Set reserved bit 0 of the source address (last byte, offset 19).
        ("rejects address reserved bit", 19, 0x21, |e| {
            matches!(e, ParseError::AddressReservedBitSet { .. })
        }),
        // Force reserved address type 3 in bits 63:61 of the source.
        ("rejects reserved address type", 12, 0x60, |e| {
            matches!(e, ParseError::UnsupportedAddressType { .. })
        }),
    ];
    for (name, offset, value, matches) in cases {
        let mut bad = wire.clone();
        bad[*offset] = *value;
        let ok = matches!(Packet::parse(&bad), Err(e) if matches(&e));
        run(name, ok);
    }
    // Zeroing the source address (offset 12..20) must be rejected too.
    let mut no_src = wire.clone();
    no_src[12..20].fill(0);
    run(
        "rejects unspecified source",
        matches!(
            Packet::parse(&no_src),
            Err(ParseError::UnspecifiedAddress { .. })
        ),
    );
    run(
        "rejects short datagram",
        matches!(
            Packet::parse(&wire[..BASE_HEADER_LEN - 1]),
            Err(ParseError::Truncated { .. })
        ),
    );
    run(
        "rejects length mismatch",
        matches!(
            Packet::parse(&wire[..wire.len().saturating_sub(1)]),
            Err(ParseError::LengthMismatch { .. })
        ),
    );

    if failures == 0 {
        println!("selftest passed");
        ExitCode::SUCCESS
    } else {
        eprintln!("selftest FAILED ({failures} case(s))");
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::decode_hex;

    #[test]
    fn hex_compact() {
        assert_eq!(
            decode_hex("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn hex_with_spaces_and_prefix() {
        assert_eq!(
            decode_hex("0xde ad\tbe\nef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn hex_empty() {
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_hex("  \t\n").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hex_odd_and_invalid() {
        assert!(decode_hex("abc").is_err());
        // Whitespace does not count toward length.
        assert!(decode_hex("a b c").is_err());
        assert!(decode_hex("zz").is_err());
        assert!(decode_hex("de zz").is_err());
    }
}
