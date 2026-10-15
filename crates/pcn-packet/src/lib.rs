//! `pcn-packet` - PCN protocol wire format: representation, serialization,
//! parsing, and validation.
//!
//! This crate implements the provisional protocol v0.1 packet format
//! described in `docs/protocol/v0.1/packet-format.md`:
//!
//! * a fixed 32-byte base header,
//! * five packet types ([`PacketType`]),
//! * a payload whose length is declared in the header.
//!
//! Design rules enforced here:
//!
//! * All multi-byte integer fields are big-endian; the wire format never
//!   depends on host endianness or native struct layout.
//! * Parsing validates the datagram *before* materializing a [`Packet`];
//!   malformed input produces a typed [`ParseError`], never a panic.
//! * No `unsafe` (forbidden workspace-wide), no heap allocation driven by
//!   unverified length fields.
//! * This crate is transport-agnostic. UDP is the first transport but is
//!   not special here; nothing in this crate assumes delivery, ordering,
//!   authentication, or confidentiality.
//!
//! Header extensions are intentionally undefined in v0.1. The
//! `Header Length` field exists so that a later version can grow the
//! header without changing this layout; today's parsers must reject
//! anything that is not exactly [`BASE_HEADER_LEN`].

mod error;
mod flags;
mod header;
mod packet;
mod packet_type;

pub use error::{AddressRole, BuildError, EncodeError, ParseError};
pub use flags::Flags;
pub use header::Header;
pub use packet::{Packet, PacketBuilder};
pub use packet_type::PacketType;

pub use pcn_address::{Address, AddressType};

/// On-wire protocol version number for the "0.1" specification.
///
/// The Version field encodes the wire-format generation, not the
/// marketing name: protocol release 0.1 is `Version = 1`.
pub const PROTOCOL_VERSION: u8 = 1;

/// Length in bytes of the fixed v0.1 base header.
pub const BASE_HEADER_LEN: usize = 32;

/// Maximum total wire size of a PCN packet in v0.1, in bytes.
///
/// This bound is chosen so that a complete packet always fits in a single
/// UDP datagram (the maximum UDP payload over IPv4/IPv6 is 65 535 bytes).
/// Transports with a smaller MTU must impose their own tighter bound; the
/// packet layer only guarantees this absolute ceiling.
pub const MAX_PACKET_LEN: usize = 65_535;

/// Maximum payload size of a v0.1 packet in bytes.
pub const MAX_PAYLOAD_LEN: usize = MAX_PACKET_LEN - BASE_HEADER_LEN;

/// Default hop limit assigned to locally originated packets.
///
/// Forwarding semantics (decrement-and-drop) are defined by the future
/// routing layer; the packet layer only carries the field.
pub const DEFAULT_HOP_LIMIT: u8 = 64;
