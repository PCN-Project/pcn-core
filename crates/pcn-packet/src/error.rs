//! Typed errors produced while parsing or building packets.

use crate::{BASE_HEADER_LEN, MAX_PACKET_LEN};
use core::fmt;
use std::error::Error;

/// Errors produced when decoding a datagram into a [`crate::Packet`].
///
/// Every variant corresponds to a validation rule in
/// `docs/protocol/v0.1/packet-format.md`. Parsing never panics on
/// malformed input; it reports one of these instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The datagram is shorter than the 48-byte base header, so no header
    /// field may be read at all.
    Truncated {
        /// Bytes actually received.
        actual: usize,
        /// Bytes required before any field can be inspected.
        required: usize,
    },
    /// The Version field is not [`crate::PROTOCOL_VERSION`].
    UnsupportedVersion {
        /// Version value found on the wire.
        found: u8,
    },
    /// The Header Length field does not equal [`BASE_HEADER_LEN`].
    ///
    /// v0.1 defines no header extensions, so any other value is invalid.
    /// This also covers a header length that would exceed the datagram.
    InvalidHeaderLength {
        /// Header Length value found on the wire.
        found: u16,
    },
    /// The declared total length (`Header Length + Payload Length`) does
    /// not match the number of bytes actually received.
    LengthMismatch {
        /// `Header Length + Payload Length` as declared on the wire.
        declared: usize,
        /// Bytes actually received.
        actual: usize,
    },
    /// The declared total length exceeds [`MAX_PACKET_LEN`].
    PacketTooLarge {
        /// `Header Length + Payload Length` as declared on the wire.
        declared: usize,
    },
    /// One or more of the three reserved bytes (offset 9..12) is nonzero.
    /// v0.1 requires them to be zero.
    NonZeroReserved {
        /// The three bytes as found on the wire.
        bytes: [u8; 3],
    },
    /// The Type field does not name a known [`crate::PacketType`].
    UnknownPacketType {
        /// Type value found on the wire.
        found: u8,
    },
    /// The Flags field sets bits that v0.1 does not define. Unknown flags
    /// are always rejected, never silently ignored.
    UnsupportedFlags {
        /// Flags value found on the wire.
        found: u16,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { actual, required } => write!(
                f,
                "datagram too short: {actual} bytes received, \
                 at least {required} required for the base header"
            ),
            Self::UnsupportedVersion { found } => write!(
                f,
                "unsupported protocol version {found} \
                 (this implementation supports version 1)"
            ),
            Self::InvalidHeaderLength { found } => write!(
                f,
                "invalid header length {found} \
                 (v0.1 requires exactly {BASE_HEADER_LEN})"
            ),
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "declared packet length {declared} does not match \
                 {actual} received bytes"
            ),
            Self::PacketTooLarge { declared } => write!(
                f,
                "declared packet length {declared} exceeds \
                 maximum of {MAX_PACKET_LEN} bytes"
            ),
            Self::NonZeroReserved { bytes } => write!(
                f,
                "reserved header bytes must be zero in v0.1, \
                 found {:02x} {:02x} {:02x}",
                bytes[0], bytes[1], bytes[2]
            ),
            Self::UnknownPacketType { found } => {
                write!(f, "unknown packet type 0x{found:02x}")
            }
            Self::UnsupportedFlags { found } => write!(
                f,
                "unsupported flags 0x{found:04x} \
                 (v0.1 defines no flag bits)"
            ),
        }
    }
}

impl Error for ParseError {}

/// Errors produced when constructing a [`crate::Packet`] for sending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The payload does not fit in the 16-bit Payload Length field or in
    /// [`MAX_PACKET_LEN`].
    PayloadTooLarge {
        /// Requested payload size in bytes.
        len: usize,
        /// Largest permitted payload size in bytes.
        max: usize,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { len, max } => write!(
                f,
                "payload of {len} bytes exceeds the maximum \
                 of {max} bytes"
            ),
        }
    }
}

impl Error for BuildError {}
