# PCN Network Model

**Status:** architectural direction. Components described here are planned
unless the README marks them built. This document fixes invariants the
implementation must preserve as it grows.

## 1. Domains

A *domain* is an independently administered PCN network:

- Anyone may create an **isolated private domain**: pick a `DomainId`,
  assign local addresses, run nodes. No registration is required and none
  may be demanded.
- Domains that want global reachability register with **PCN Global**
  operators and advertise routes under operator authorization.
- A local address means nothing without its domain. Two domains may use
  the same address range; resolution always happens in domain context
  (`ScopedAddress`).

## 2. Global authority model

```text
Root Authority
   └─ delegates bounded permissions ──> Operators
        └─ administer ──> registered domains / address blocks
   (private domains: sovereign over local config, always)
```

- The **Root Authority** delegates *bounded* permissions to registered
  operators - e.g. the right to advertise specific global address ranges
  or operate registries.
- **Operators** administer allocations for the domains they serve.
- **Local administrators** keep full control of their private domains.
- **Revocation** of an operator's authorization stops its *official global*
  participation; it must never destroy or reconfigure the private domain's
  local state.
- Registries and authority services **may be replicated** across machines;
  nothing in the model requires a single physical server.
- Control-plane centralization never implies data-plane centralization:
  registry lookups and policy distribution must not become packet
  forwarding paths.

## 3. Routing and forwarding

- Forwarding decisions are made by routers/nodes using local tables built
  from static routes, domain configuration, and (future) inter-domain
  routing.
- No packet is required to pass through a central server, registry, or
  authority node.
- The routing layer is transport-independent: it consumes PCN addresses
  and next-hop handles, never UDP sockets or Ethernet frames directly.
- Planned elements: static routes (first), gateways between domains,
  inter-domain route advertisement under operator authorization.
- The routing layer interprets **Hop Limit** (decrement per forward, drop
  at zero, emit `ERROR` where appropriate); the packet layer only carries
  the field.

## 4. Policy enforcement (future)

- PCN Global may distribute **authenticated, signed policy** objects.
- Participating operators and routers **enforce locally**; enforcement is
  a property of cooperative infrastructure.
- Honest limit: signed policy cannot prevent traffic over uncontrolled
  tunnels or foreign networks. PCN policy governs PCN participants; it is
  not an internet-wide control mechanism.

## 5. Trust boundaries

- Between node and transport: none - endpoints are untrusted input.
- Between domain and PCN Global: operator authorization, bounded and
  revocable.
- Between private domain internals and outsiders: the domain's own
  gateways define what is advertised and reachable.
