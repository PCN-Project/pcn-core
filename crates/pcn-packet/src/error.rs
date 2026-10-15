//! Typed errors produced while parsing or building packets.

use crate::{BASE_HEADER_LEN, MAX_PACKET_LEN};
use core::fmt;
use std::error::Error;

/// Which header address field an error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressRole {
    /// The Source Address field.
    Source,
    /// The Destination Address field.
    Destination,
}

impl fmt::Display for AddressRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source => f.write_str("source"),
            Self::Destination => f.write_str("destination"),
        }
    }
}

/// Errors produced when decoding a datagram into a [`crate::Packet`].
///
/// Every variant corresponds to a validation rule in
/// `docs/protocol/packet-format.md`. Parsing never panics on
/// malformed input; it reports one of these instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The datagram is shorter than the 32-byte base header, so no header
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
    /// An address field contains the all-zero
    /// [`Address::UNSPECIFIED`](crate::Address::UNSPECIFIED) address, which
    /// is not routable and therefore not legal on the wire in v0.1.
    UnspecifiedAddress {
        /// Which header field carried the zero address.
        role: AddressRole,
    },
    /// An address field has reserved bit `[0]` set. Bit 0 must be zero
    /// in every PCN-ADDR address; the text form cannot even express it,
    /// so a set bit means a malformed or future-format peer.
    AddressReservedBitSet {
        /// Which header field carried the malformed address.
        role: AddressRole,
    },
    /// An address field carries a type that v0.1 does not assign as a
    /// routable address type. Only private (1) and public (2) are
    /// legal; this also covers reserved type 0 values other than the
    /// all-zero unspecified address.
    UnsupportedAddressType {
        /// Which header field carried the address.
        role: AddressRole,
        /// The 3-bit type field as found on the wire.
        found: u8,
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
            Self::UnspecifiedAddress { role } => {
                write!(f, "{role} address is the unspecified (all-zero) address")
            }
            Self::AddressReservedBitSet { role } => write!(
                f,
                "{role} address has the reserved bit 0 set \
                 (must be zero in v0.1)"
            ),
            Self::UnsupportedAddressType { role, found } => write!(
                f,
                "{role} address has unsupported type {found} \
                 (v0.1 assigns 1 = private, 2 = public)"
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
    /// An address field is the all-zero
    /// [`Address::UNSPECIFIED`](crate::Address::UNSPECIFIED) address, which
    /// is not routable and therefore not legal on the wire in v0.1.
    UnspecifiedAddress {
        /// Which header field carried the zero address.
        role: AddressRole,
    },
    /// An address field has reserved bit `[0]` set, mirroring the
    /// parse-side rule so a built packet always survives `parse`.
    AddressReservedBitSet {
        /// Which header field carried the malformed address.
        role: AddressRole,
    },
    /// An address field carries a type that v0.1 does not assign as a
    /// routable address type (only private = 1 and public = 2).
    UnsupportedAddressType {
        /// Which header field carried the address.
        role: AddressRole,
        /// The 3-bit type field of the address.
        found: u8,
    },
    /// [`Packet::echo_reply`](crate::Packet::echo_reply) was called on a
    /// packet that is not an [`EchoRequest`](crate::PacketType::EchoRequest).
    NotEchoRequest,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { len, max } => write!(
                f,
                "payload of {len} bytes exceeds the maximum \
                 of {max} bytes"
            ),
            Self::UnspecifiedAddress { role } => {
                write!(f, "{role} address is the unspecified (all-zero) address")
            }
            Self::AddressReservedBitSet { role } => write!(
                f,
                "{role} address has the reserved bit 0 set \
                 (must be zero in v0.1)"
            ),
            Self::UnsupportedAddressType { role, found } => write!(
                f,
                "{role} address has unsupported type {found} \
                 (v0.1 assigns 1 = private, 2 = public)"
            ),
            Self::NotEchoRequest => {
                f.write_str("cannot build ECHO_REPLY from a non-ECHO_REQUEST packet")
            }
        }
    }
}

impl Error for BuildError {}

/// Errors produced when serializing into a caller-provided buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// The output buffer is too small for the encoded bytes.
    BufferTooSmall {
        /// Bytes needed.
        required: usize,
        /// Bytes the buffer provides.
        available: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall {
                required,
                available,
            } => write!(
                f,
                "output buffer too small: {available} bytes available, \
                 {required} required"
            ),
        }
    }
}

impl Error for EncodeError {}
