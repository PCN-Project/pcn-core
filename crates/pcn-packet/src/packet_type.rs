//! The 8-bit Type header field.
//!
//! The numeric assignments below are **provisional** for protocol v0.1
//! and may change in a later specification revision. Peers that do not
//! recognize a type must reject the packet, not guess at its semantics.

/// Semantic type of a PCN packet.
///
/// Wire encoding is the `u8` returned by [`PacketType::to_u8`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketType {
    /// `0x01` - carries upper-layer data.
    Data,
    /// `0x02` - liveness/MTU probe; the receiver should answer with
    /// [`PacketType::EchoReply`].
    EchoRequest,
    /// `0x03` - answer to [`PacketType::EchoRequest`].
    EchoReply,
    /// `0x04` - reports a delivery or processing failure.
    Error,
    /// `0x05` - control-plane message (routing, administration).
    Control,
    /// `0x06` - acknowledges a [`PacketType::Data`] packet. The ACK's
    /// source is the DATA packet's destination (the endpoint that
    /// accepted it), its destination is the DATA source, and its
    /// `packet_id` echoes the DATA `packet_id`; the payload is empty.
    /// Sent by the destination endpoint only - never by routers.
    Ack,
}

impl PacketType {
    /// The wire value for [`PacketType::Data`].
    pub const DATA: u8 = 0x01;
    /// The wire value for [`PacketType::EchoRequest`].
    pub const ECHO_REQUEST: u8 = 0x02;
    /// The wire value for [`PacketType::EchoReply`].
    pub const ECHO_REPLY: u8 = 0x03;
    /// The wire value for [`PacketType::Error`].
    pub const ERROR: u8 = 0x04;
    /// The wire value for [`PacketType::Control`].
    pub const CONTROL: u8 = 0x05;
    /// The wire value for [`PacketType::Ack`].
    pub const ACK: u8 = 0x06;

    /// Maps a wire value to a packet type, or `None` if the value is not
    /// assigned in v0.1.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            Self::DATA => Some(Self::Data),
            Self::ECHO_REQUEST => Some(Self::EchoRequest),
            Self::ECHO_REPLY => Some(Self::EchoReply),
            Self::ERROR => Some(Self::Error),
            Self::CONTROL => Some(Self::Control),
            Self::ACK => Some(Self::Ack),
            _ => None,
        }
    }

    /// The wire encoding of this type.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Data => Self::DATA,
            Self::EchoRequest => Self::ECHO_REQUEST,
            Self::EchoReply => Self::ECHO_REPLY,
            Self::Error => Self::ERROR,
            Self::Control => Self::CONTROL,
            Self::Ack => Self::ACK,
        }
    }

    /// A stable human-readable name, for logs and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Data => "DATA",
            Self::EchoRequest => "ECHO_REQUEST",
            Self::EchoReply => "ECHO_REPLY",
            Self::Error => "ERROR",
            Self::Control => "CONTROL",
            Self::Ack => "ACK",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_types_roundtrip() {
        for ty in [
            PacketType::Data,
            PacketType::EchoRequest,
            PacketType::EchoReply,
            PacketType::Error,
            PacketType::Control,
            PacketType::Ack,
        ] {
            assert_eq!(PacketType::from_u8(ty.to_u8()), Some(ty));
        }
    }

    #[test]
    fn provisional_wire_values() {
        assert_eq!(PacketType::Data.to_u8(), 0x01);
        assert_eq!(PacketType::EchoRequest.to_u8(), 0x02);
        assert_eq!(PacketType::EchoReply.to_u8(), 0x03);
        assert_eq!(PacketType::Error.to_u8(), 0x04);
        assert_eq!(PacketType::Control.to_u8(), 0x05);
        assert_eq!(PacketType::Ack.to_u8(), 0x06);
    }

    #[test]
    fn unknown_values_rejected() {
        assert_eq!(PacketType::from_u8(0x00), None);
        assert_eq!(PacketType::from_u8(0x07), None);
        assert_eq!(PacketType::from_u8(0xff), None);
    }

    #[test]
    fn names_are_stable() {
        assert_eq!(PacketType::Data.name(), "DATA");
        assert_eq!(PacketType::Control.name(), "CONTROL");
    }
}
