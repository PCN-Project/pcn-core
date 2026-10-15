//! `pcn-routing` - static routing decisions for PCN packets.
//!
//! This crate owns the routing *decision* layer and nothing else:
//!
//! * [`RouteTable`] maps a destination [`Address`] to a [`NextHopId`]
//!   with exact-match semantics - no prefixes, no metrics, no
//!   dynamic updates.
//! * [`decide`] answers "deliver locally, forward, or drop?" for a
//!   received [`Packet`].
//! * [`forward`] produces the forwarded copy of a packet with its
//!   Hop Limit decremented.
//!
//! Layering rule from `docs/architecture/overview.md`: this crate speaks
//! in PCN addresses and opaque next-hop handles only. It has no notion of
//! UDP, `SocketAddr`, or any other transport endpoint - the node layer
//! (`pcnd`) resolves a [`NextHopId`] to a concrete transport endpoint.
//!
//! Every function is pure and socket-free, so the whole routing layer is
//! testable without a network.

use pcn_address::Address;
use pcn_packet::{BuildError, Packet};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

/// Opaque identifier of the next hop a packet should be forwarded to.
///
/// A `NextHopId` names a neighbor or link known to the *node* layer;
/// `pcnd` will map it onto a transport endpoint (e.g. a `SocketAddr`).
/// The routing layer deliberately never carries IP or port information,
/// so the same table works over UDP today and Ethernet later.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NextHopId(pub u32);

impl fmt::Display for NextHopId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "next-hop {}", self.0)
    }
}

impl fmt::Debug for NextHopId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A static routing table with exact-match destination lookup.
///
/// Routes map a full 64-bit [`Address`] to a [`NextHopId`]. There is no
/// prefix or CIDR matching and no metric selection: a lookup either hits
/// the exact destination or misses.
#[derive(Debug, Default)]
pub struct RouteTable {
    routes: HashMap<Address, NextHopId>,
}

impl RouteTable {
    /// An empty routing table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a route to `dest` via `via`.
    ///
    /// Deterministic on duplicates: a second insert for the same
    /// destination **replaces** the previous next hop. The replaced
    /// value is returned so callers can detect the overwrite.
    pub fn insert(&mut self, dest: Address, via: NextHopId) -> Option<NextHopId> {
        self.routes.insert(dest, via)
    }

    /// Removes the route to `dest`, returning the previous next hop if
    /// one existed.
    pub fn remove(&mut self, dest: Address) -> Option<NextHopId> {
        self.routes.remove(&dest)
    }

    /// The next hop for `dest`, or `None` if no route exists.
    #[must_use]
    pub fn lookup(&self, dest: Address) -> Option<NextHopId> {
        self.routes.get(&dest).copied()
    }

    /// The number of routes currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// `true` if the table holds no routes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Why a packet cannot be forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// No route to the destination exists in the table.
    NoRoute,
    /// The packet's Hop Limit is too low to survive another hop: a
    /// packet with `hop_limit <= 1` may be delivered locally but must
    /// not be forwarded.
    HopLimitExhausted,
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoute => f.write_str("no route to destination"),
            Self::HopLimitExhausted => {
                f.write_str("hop limit exhausted: packet may not be forwarded")
            }
        }
    }
}

impl Error for DropReason {}

/// The routing decision for a received packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The destination address belongs to this node; deliver locally.
    Deliver,
    /// A route exists; forward via the given next hop.
    Forward(NextHopId),
    /// The packet must be dropped.
    Drop(DropReason),
}

/// Decides what the local node does with `packet`.
///
/// Rule order is fixed and deliberately puts local delivery first:
///
/// 1. If `packet`'s destination is one of `local_addrs`, return
///    [`Decision::Deliver`]. A packet that reached its destination is
///    delivered even with `hop_limit` already at 1 or 0 - the limit
///    constrains *forwarding*, not receiving.
/// 2. Otherwise, if `hop_limit <= 1`, return
///    [`Decision::Drop`]`(`[`DropReason::HopLimitExhausted`]`)`: the
///    packet may not be forwarded again. This check precedes the table
///    lookup, so a dead packet never produces a `Forward` decision.
/// 3. Otherwise look up the destination: a hit yields
///    [`Decision::Forward`], a miss yields
///    [`Decision::Drop`]`(`[`DropReason::NoRoute`]`)`.
///
/// The packet is only inspected, never modified; building the forwarded
/// copy is [`forward`]'s job. Input is assumed already validated -
/// `Packet` values are only produced by the checked parser/builder.
#[must_use]
pub fn decide(local_addrs: &[Address], table: &RouteTable, packet: &Packet) -> Decision {
    let destination = packet.header().destination();
    if local_addrs.contains(&destination) {
        return Decision::Deliver;
    }
    if packet.header().hop_limit() <= 1 {
        return Decision::Drop(DropReason::HopLimitExhausted);
    }
    match table.lookup(destination) {
        Some(next_hop) => Decision::Forward(next_hop),
        None => Decision::Drop(DropReason::NoRoute),
    }
}

/// Errors produced by [`forward`].
#[derive(Debug, PartialEq)]
pub enum ForwardError {
    /// `hop_limit <= 1`: the packet may be delivered locally but must
    /// not be forwarded (same threshold [`decide`] applies).
    HopLimitExhausted,
    /// Rebuilding through the public [`Packet::builder`] failed.
    ///
    /// Unreachable for packets produced by `Packet::parse` or
    /// `PacketBuilder` - their addresses are already validated and the
    /// payload is already in bounds. Mapped rather than unwrapped so
    /// `forward` never panics.
    Rebuild(BuildError),
}

impl fmt::Display for ForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HopLimitExhausted => {
                f.write_str("hop limit exhausted: packet may not be forwarded")
            }
            Self::Rebuild(e) => write!(f, "failed to rebuild packet for forwarding: {e}"),
        }
    }
}

impl Error for ForwardError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::HopLimitExhausted => None,
            Self::Rebuild(e) => Some(e),
        }
    }
}

/// Builds the forwarded copy of `packet` with Hop Limit decremented by
/// one.
///
/// Everything else is preserved: packet type, flags (always
/// [`pcn_packet::Flags::NONE`] in v0.1 - the parser rejects any other
/// value, so there is nothing to lose), packet ID, payload, and both
/// addresses. A router never rewrites source or destination.
///
/// The rebuild goes through the public [`Packet::builder`], so the result
/// is a fully validated `Packet`, not a hand-patched byte buffer.
///
/// # Errors
/// * [`ForwardError::HopLimitExhausted`] when `hop_limit <= 1`:
///   the packet may still be delivered locally, but must not be
///   forwarded.
/// * [`ForwardError::Rebuild`] if the defensive rebuild fails (cannot
///   happen for a well-formed input packet).
pub fn forward(packet: &Packet) -> Result<Packet, ForwardError> {
    let header = packet.header();
    if header.hop_limit() <= 1 {
        return Err(ForwardError::HopLimitExhausted);
    }
    Packet::builder(header.packet_type(), header.source(), header.destination())
        .packet_id(header.packet_id())
        .hop_limit(header.hop_limit() - 1)
        .payload(packet.payload().to_vec())
        .build()
        .map_err(ForwardError::Rebuild)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcn_address::AddressType;
    use pcn_packet::PacketType;

    fn addr(value: u64) -> Address {
        Address::new(AddressType::Private, value)
    }

    fn packet(src: Address, dst: Address, hop_limit: u8) -> Packet {
        Packet::builder(PacketType::Data, src, dst)
            .packet_id(0x1234_5678)
            .hop_limit(hop_limit)
            .payload(b"payload".to_vec())
            .build()
            .unwrap()
    }

    #[test]
    fn table_insert_lookup_update_remove() {
        let mut table = RouteTable::new();
        assert!(table.is_empty());
        assert_eq!(table.lookup(addr(9)), None);

        // Insert and look up.
        assert_eq!(table.insert(addr(9), NextHopId(7)), None);
        assert_eq!(table.lookup(addr(9)), Some(NextHopId(7)));
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());

        // Duplicate insert replaces and returns the old next hop.
        assert_eq!(table.insert(addr(9), NextHopId(8)), Some(NextHopId(7)));
        assert_eq!(table.lookup(addr(9)), Some(NextHopId(8)));
        assert_eq!(table.len(), 1);

        // Remove returns the stored value; a second remove misses.
        assert_eq!(table.remove(addr(9)), Some(NextHopId(8)));
        assert_eq!(table.remove(addr(9)), None);
        assert!(table.is_empty());
    }

    #[test]
    fn decide_delivers_to_local_address() {
        let table = RouteTable::new();
        let locals = [addr(1)];
        let p = packet(addr(2), addr(1), 64);
        assert_eq!(decide(&locals, &table, &p), Decision::Deliver);
    }

    #[test]
    fn decide_delivers_even_at_hop_limit_edge() {
        // A packet for us must never be dropped just for arriving on its
        // last hop - the limit constrains forwarding, not receiving.
        let table = RouteTable::new();
        let locals = [addr(1)];
        for hop_limit in [1, 0] {
            let p = packet(addr(2), addr(1), hop_limit);
            assert_eq!(decide(&locals, &table, &p), Decision::Deliver);
        }
    }

    #[test]
    fn decide_local_wins_over_existing_route() {
        // Even if a (bogus) route for our own address exists, a packet
        // addressed to us is delivered, not forwarded back out.
        let mut table = RouteTable::new();
        table.insert(addr(1), NextHopId(3));
        let locals = [addr(1)];
        let p = packet(addr(2), addr(1), 64);
        assert_eq!(decide(&locals, &table, &p), Decision::Deliver);
    }

    #[test]
    fn decide_forwards_along_existing_route() {
        let mut table = RouteTable::new();
        table.insert(addr(9), NextHopId(5));
        let locals = [addr(1)];
        let p = packet(addr(2), addr(9), 64);
        assert_eq!(decide(&locals, &table, &p), Decision::Forward(NextHopId(5)));
    }

    #[test]
    fn decide_drops_without_route() {
        let table = RouteTable::new();
        let locals = [addr(1)];
        let p = packet(addr(2), addr(9), 64);
        assert_eq!(
            decide(&locals, &table, &p),
            Decision::Drop(DropReason::NoRoute)
        );
    }

    #[test]
    fn decide_drops_exhausted_hop_limit_before_route_lookup() {
        // The packet would route, but hop_limit <= 1 forbids forwarding -
        // the hop check must win over the table hit.
        let mut table = RouteTable::new();
        table.insert(addr(9), NextHopId(5));
        let locals = [addr(1)];
        for hop_limit in [1, 0] {
            let p = packet(addr(2), addr(9), hop_limit);
            assert_eq!(
                decide(&locals, &table, &p),
                Decision::Drop(DropReason::HopLimitExhausted)
            );
        }
    }

    #[test]
    fn decide_handles_empty_locals_and_table() {
        let table = RouteTable::new();
        let p = packet(addr(2), addr(9), 64);
        assert_eq!(decide(&[], &table, &p), Decision::Drop(DropReason::NoRoute));
    }

    #[test]
    fn forward_decrements_and_preserves_everything() {
        let p = packet(addr(2), addr(9), 64);
        let forwarded = forward(&p).unwrap();
        let (orig, fwd) = (p.header(), forwarded.header());

        // Addresses are never rewritten by a router.
        assert_eq!(fwd.source(), orig.source());
        assert_eq!(fwd.destination(), orig.destination());
        // Type, flags, packet ID and payload survive.
        assert_eq!(fwd.packet_type(), orig.packet_type());
        assert_eq!(fwd.flags(), orig.flags());
        assert_eq!(fwd.packet_id(), orig.packet_id());
        assert_eq!(forwarded.payload(), p.payload());
        // Exactly one hop consumed.
        assert_eq!(fwd.hop_limit(), orig.hop_limit() - 1);
    }

    #[test]
    fn forward_chain_ends_at_limit() {
        // Forward repeatedly: each hop decrements; once hop_limit hits 1
        // the packet must not be forwarded again.
        let mut p = packet(addr(2), addr(9), 3);
        p = forward(&p).unwrap();
        assert_eq!(p.header().hop_limit(), 2);
        p = forward(&p).unwrap();
        assert_eq!(p.header().hop_limit(), 1);
        assert_eq!(forward(&p).unwrap_err(), ForwardError::HopLimitExhausted);
        // Packet is left untouched by the failed call (we only ever
        // received a reference).
        assert_eq!(p.header().hop_limit(), 1);
    }

    #[test]
    fn forward_rejects_zero_hop_limit() {
        let p = packet(addr(2), addr(9), 0);
        assert_eq!(forward(&p).unwrap_err(), ForwardError::HopLimitExhausted);
    }

    #[test]
    fn forwarded_packet_still_parses() {
        // A forwarded packet is a fully valid wire packet, not a patched
        // buffer: it survives the validating parser.
        let p = packet(addr(2), addr(9), 10);
        let forwarded = forward(&p).unwrap();
        let reparsed = Packet::parse(&forwarded.encode()).unwrap();
        assert_eq!(reparsed, forwarded);
    }

    #[test]
    fn forwarded_packet_matches_parser_roundtrip() {
        // End-to-end consistency: parse a datagram, forward it, re-parse -
        // identical to forwarding the already-parsed value.
        let wire = packet(addr(2), addr(9), 42).encode();
        let inbound = Packet::parse(&wire).unwrap();
        let forwarded = forward(&inbound).unwrap();
        assert_eq!(forwarded.header().hop_limit(), 41);
        assert_eq!(Packet::parse(&forwarded.encode()).unwrap(), forwarded);
    }

    #[test]
    fn decide_and_forward_never_panic_on_edge_inputs() {
        let mut table = RouteTable::new();
        table.insert(addr(9), NextHopId(5));
        let locals = [addr(1)];
        // Every combination of local/remote destination and the full
        // hop-limit edge range must produce a decision, not a panic.
        for dst in [addr(1), addr(9), addr(10)] {
            for hop_limit in [0u8, 1, 2, 64, 255] {
                let p = packet(addr(2), dst, hop_limit);
                let _ = decide(&locals, &table, &p);
                let _ = forward(&p);
            }
        }
    }
}
