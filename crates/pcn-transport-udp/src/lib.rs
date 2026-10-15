//! `pcn-transport-udp` - UDP transport for PCN over `std::net::UdpSocket`.
//!
//! This is the first concrete [`Transport`]: it carries one PCN packet per
//! UDP datagram between [`SocketAddr`] endpoints. It is synchronous and
//! built only on the standard library.
//!
//! Scope boundaries, by design:
//!
//! * The crate knows nothing about PCN addresses, headers, or routing.
//!   Bytes in, bytes out; parsing is `pcn-packet`'s job upstream.
//! * A `SocketAddr` is a transport endpoint - never a PCN identity or
//!   routing address (see `docs/protocol/addressing.md`).
//! * UDP provides no delivery, ordering, authentication, or
//!   confidentiality. This crate adds none on top.

use pcn_transport::Transport;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// A synchronous UDP transport.
///
/// Thin wrapper over [`UdpSocket`] implementing [`Transport`] with
/// `Endpoint = SocketAddr`. IPv4 and IPv6 both work to the extent the
/// underlying socket supports them - bind `0.0.0.0`/`127.0.0.1` for
/// IPv4, `::`/`::1` for IPv6.
///
/// Cloning shares the same underlying socket (via `try_clone`), so clones
/// see the same receive queue - suitable for a single receive loop plus
/// senders, not for competing consumers.
#[derive(Debug)]
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Binds a UDP socket to `local`.
    ///
    /// Any address `ToSocketAddrs` resolves to may be used; port `0`
    /// requests an OS-assigned port, discoverable afterwards via
    /// [`local_endpoint`](Transport::local_endpoint).
    ///
    /// # Errors
    /// Propagates name-resolution and `bind(2)` errors.
    pub fn bind<A: ToSocketAddrs>(local: A) -> io::Result<Self> {
        let socket = UdpSocket::bind(local)?;
        Ok(Self { socket })
    }

    /// Returns the currently configured receive timeout.
    ///
    /// `None` means [`recv_from`](Transport::recv_from) blocks without a
    /// deadline. Mirrors [`UdpSocket::read_timeout`]; kept as an inherent
    /// method because the [`Transport`] interface is intentionally
    /// minimal.
    ///
    /// # Errors
    /// Propagates the underlying `getsockopt` error.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.socket.read_timeout()
    }
}

impl Transport for UdpTransport {
    type Endpoint = SocketAddr;

    /// Sends `bytes` as one UDP datagram to `to`.
    ///
    /// # Errors
    /// Propagates `send_to(2)` errors (unreachable address, oversized
    /// datagram, etc.). Success means handed to the OS, not delivered.
    fn send_to(&self, bytes: &[u8], to: &SocketAddr) -> io::Result<usize> {
        self.socket.send_to(bytes, to)
    }

    /// Receives one datagram into `buf`, returning the byte count and
    /// the sender's actual endpoint.
    ///
    /// Datagrams larger than `buf` are truncated by the OS. With a read
    /// timeout configured, expiry surfaces as `WouldBlock` or `TimedOut`
    /// depending on the platform.
    ///
    /// # Errors
    /// Propagates `recv_from(2)` errors, including timeout expiry.
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf)
    }

    /// Sets (`Some`) or clears (`None`) the receive timeout.
    ///
    /// # Errors
    /// Propagates `setsockopt` errors.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }

    /// The socket's local endpoint; with port `0` binds this is the
    /// OS-assigned address.
    ///
    /// # Errors
    /// Propagates `getsockname` errors.
    fn local_endpoint(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}
