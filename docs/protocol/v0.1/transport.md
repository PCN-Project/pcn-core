# PCN Transport — v0.1

**Status:** provisional design note. No transport code ships in this
milestone; this document fixes the constraints the transport layer will
operate under.

## 1. Position in the architecture

PCN packets are transport-independent. The routing layer speaks in PCN
addresses and never sees transport details; the transport layer maps PCN
packets onto an underlying medium. UDP over IP is the **first** transport,
not a protocol dependency.

Planned transports (roughly in order):

1. UDP over IPv4/IPv6 — the initial overlay.
2. Direct Ethernet — PCN ethertype, no IP involved.
3. Others (e.g. serial/tunnel media) as needed.

Node identity and addressing must not need redesign when a new transport
arrives; that is why transport endpoints are never PCN identities
(`addressing.md`).

## 2. What UDP does *not* provide

Implementations must not assume the transport delivers anything:

- no delivery guarantee (packets may be dropped or duplicated),
- no ordering,
- no authentication (source addresses can be spoofed),
- no confidentiality,
- no integrity beyond the UDP checksum (which is optional on IPv4 and
  absent entirely on non-IP transports).

Reliability, ordering, and security are either protocol-layer concerns
(future work) or explicitly out of scope.

## 3. MTU and maximum packet size

v0.1 bounds a PCN packet to **65 535 bytes total** so that it can always
fit in one UDP datagram. This is an absolute ceiling, not a promised
working size:

- Real path MTUs are far smaller (commonly ~1 500 bytes; less through
  tunnels). Transports must expose a configurable maximum payload size
  and reject or handle oversized packets accordingly.
- v0.1 defines no fragmentation or PMTU discovery; senders must keep
  packets within the path's actual capacity. `ECHO_REQUEST`/`ECHO_REPLY`
  exist partly to probe this.
- The packet library enforces only the 65 535-byte ceiling; per-link MTU
  enforcement is the transport's job.

## 4. Socket/transport requirements (when implemented)

- Map `(transport endpoint) → nothing semantic`: endpoints are ephemeral
  attachment points, re-resolved through the routing/discovery layer.
- Keep PCN headers byte-exact across transport boundaries; no
  transport-specific header rewriting.
- Surface drop/error events for diagnostics but never fabricate
  reliability semantics on top of UDP.
