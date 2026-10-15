//! `pcn-transport` - the transport-agnostic datagram interface for PCN.
//!
//! PCN packets are carried over arbitrary media: UDP/IP is the first
//! overlay (`pcn-transport-udp`), direct Ethernet and other links are
//! planned later. This crate defines the minimal synchronous interface
//! every transport provides. It deliberately knows nothing about PCN
//! addresses, packet headers, or routing - those layers live in
//! `pcn-address`, `pcn-packet`, and the future routing crate.
//!
//! A transport's *endpoint* is an opaque attachment point owned by the
//! concrete transport (e.g. a `SocketAddr` for UDP). Per the addressing
//! spec (`docs/protocol/addressing.md`) an endpoint must never be treated
//! as a PCN identity or routing address.
//!
//! No delivery, ordering, authentication, or confidentiality is implied:
//! on UDP every one of those is absent, and higher layers must not rely
//! on them here.

use std::io;
use std::time::Duration;

/// A synchronous carrier of single datagrams between transport endpoints.
///
/// The associated [`Endpoint`](Self::Endpoint) type is chosen by the
/// transport: `SocketAddr` for UDP, a MAC/interface pair for Ethernet,
/// and so on. It is bounded only by what a node's link tables need:
/// clonable, comparable, hashable, and printable for logs.
///
/// The interface is intentionally minimal - send one datagram, receive
/// one datagram while learning the sender's endpoint, bound how long a
/// receive may wait, and report the local endpoint. Framing, retries,
/// congestion, and routing are all higher-layer concerns.
///
/// # Errors
///
/// All methods propagate the underlying transport's I/O errors as
/// [`io::Error`] without wrapping; implementations never panic on
/// transport failure.
pub trait Transport {
    /// The transport-specific endpoint identifier.
    ///
    /// For UDP this is [`std::net::SocketAddr`]. Nothing in this trait
    /// constrains the representation beyond the stated bounds.
    type Endpoint: Clone + Eq + core::hash::Hash + core::fmt::Debug;

    /// Sends one complete datagram to `to`.
    ///
    /// Datagram transports transmit `bytes` atomically: either the whole
    /// payload goes out as a single datagram, or an error is returned.
    /// Returns the number of bytes handed to the transport.
    ///
    /// # Errors
    /// Propagates the underlying I/O error. A successful return means the
    /// datagram was handed to the OS - it does **not** mean it arrived.
    fn send_to(&self, bytes: &[u8], to: &Self::Endpoint) -> io::Result<usize>;

    /// Receives one datagram into `buf`.
    ///
    /// Returns the number of bytes written and the sender's real
    /// endpoint. If the incoming datagram is larger than `buf`, the
    /// excess is handled as the underlying transport dictates (UDP
    /// truncates). Receiving into a buffer of the packet layer's maximum
    /// wire size avoids truncation entirely.
    ///
    /// # Errors
    /// Propagates the underlying I/O error. With a read timeout set,
    /// expiry surfaces as a platform-specific timeout error kind
    /// (`WouldBlock` or `TimedOut`).
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Self::Endpoint)>;

    /// Bounds how long [`recv_from`](Self::recv_from) may block.
    ///
    /// `Some(duration)` sets the timeout; `None` restores an unlimited
    /// (blocking) receive.
    ///
    /// # Errors
    /// Propagates any error from the underlying transport.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// The local endpoint this transport is bound to.
    ///
    /// When a transport is bound with an OS-assigned identifier (e.g.
    /// UDP port 0), this returns the actual endpoint peers can reach -
    /// needed for neighbor tables and diagnostics.
    ///
    /// # Errors
    /// Propagates the underlying I/O error.
    fn local_endpoint(&self) -> io::Result<Self::Endpoint>;
}
