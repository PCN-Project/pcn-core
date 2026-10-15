# PCN Core - Architecture Overview

PCN is a multi-transport network architecture. PCN Core is its reference
protocol implementation, written in Rust, targeting Linux and Android first.

## 1. Design principles

- **Identity ≠ location.** A node's PCN-ID is stable regardless of where
  the node attaches. Routing addresses describe location; transport
  endpoints describe how the bits get there today. The three never blur.
- **Multi-transport by construction.** UDP/IP is the first overlay, not a
  foundation. Direct Ethernet and other media must slot under the same
  routing and identity layers without redesign.
- **Decentralized data plane.** Packets forward node-to-node or via
  routers; no packet is required to traverse a central server. Central
  services exist only in the control plane (registries, authority,
  policy distribution).
- **Federated authority.** PCN Global is hierarchical: a Root Authority
  delegates bounded permissions to operators; private domains remain
  sovereign over local configuration.
- **Honest capability claims.** Components that are designed but not built
  are documented as planned, never stubbed into looking real.

## 2. Layering

```text
+----------------------------------------------------------+
| Applications: pcnd, pcn, services (pcn-registry, ...)     |
+-------------------------------+--------------------------+
| Control plane                 | Data plane               |
| pcn-protocol (planned)        | pcn-routing (built)      |
| pcn-config   (planned)        | pcn-packet  (built)      |
| pcn-identity (planned)        | pcn-address (built)      |
+-------------------------------+--------------------------+
| Transport abstraction: pcn-transport (built)             |
|   pcn-transport-udp (built)   | ethernet | ...           |
+----------------------------------------------------------+
| Underlay: UDP/IP today; Ethernet and other media later   |
+----------------------------------------------------------+
```

Rules of the layering:

- `pcn-packet` knows nothing about sockets, IP, or UDP.
- `pcn-routing` will know nothing about how packets are carried.
- Transport crates own endpoints; routing owns PCN addresses; identity
  will own PCN-ID. Cross-layer short-circuits are prohibited.

## 3. Current milestone (v0.1)

Built now:

- Cargo workspace (`apps/`, `crates/`).
- `pcn-address` - 64-bit PCN-ADDR `Address` (typed: private/public,
  `pcn~` Base32 text form), `DomainId`, `ScopedAddress`.
- `pcn-packet` - v0.1 wire format: typed header, deterministic
  serialization, validating parser, typed errors.
- `pcn-transport` - transport-agnostic synchronous datagram interface.
- `pcn-transport-udp` - UDP transport on `std::net::UdpSocket`:
  bind/send/recv/timeout, `SocketAddr` endpoints.
- `pcn-routing` - static exact-match route table and the
  deliver/forward/drop decision with hop-limit handling.
- `pcnd` - node daemon: `run` binds a UDP socket and drives the routing
  decision loop (deliver locally - logged only, forward with Hop Limit
  decrement, or drop); `selftest`/`check` remain.
- Provisional specs under `docs/protocol/`.

Explicitly not built: echo responder and ping, identity crypto,
registry, policy, NAT traversal, Android packaging. See the README
status table.

## 4. Platforms

- **Linux:** first-class. Transport and daemon code may use Linux APIs
  inside `pcn-transport-*`/`pcnd`; library crates stay portable.
- **Android:** the protocol libraries are portable Rust and must compile
  for Android targets (e.g. `aarch64-linux-android`) from day one. A
  Rust library is *not* an Android app: packaging, the NDK/VpnService
  integration, and lifecycle management are future deliverables under
  `deploy/android/`.
