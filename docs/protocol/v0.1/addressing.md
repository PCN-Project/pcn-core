# PCN Addressing — v0.1 (provisional)

**Status:** provisional. The 16-byte wire size is fixed; the internal
structure of the address space is *not* defined in v0.1.

## 1. Three different names

PCN keeps three concepts strictly separate. Implementations must not treat
one as another:

| Concept | Type | Changes when the node moves? |
|---|---|---|
| **PCN-ID** | stable cryptographic node identity | no — it *is* the node |
| **PCN routing address** | 16-byte locator in packet headers | may change with attachment |
| **Transport endpoint** | e.g. IP address + UDP port | may change per link/session |

Consequences:

- An IP address and UDP port is a *transport endpoint*, owned entirely by
  the transport layer. It must never be used as, or embedded in, a PCN
  identity or routing address.
- A PCN routing address is a locator, not an identity. When the mapping
  "PCN-ID ↔ address" is defined (future `pcn-identity` work), address
  changes will not require a new identity.
- PCN-ID is future work. Nothing in v0.1 claims authenticated identity.

## 2. Address scopes

- **Local addresses** are meaningful only inside a *PCN domain*. The same
  16-byte local address may be allocated independently in different
  domains, so resolving a local address always requires domain context
  (`pcn_address::ScopedAddress` pairs an `Address` with a `DomainId`).
- **Global addresses** are allocated from the centrally administered
  PCN Global space by authorized operators.
- A node is not required to hold a global address; local-only operation
  inside a private domain is fully supported.

v0.1 deliberately does **not** define which bits of the 16-byte space
distinguish local from global, how domains are numbered, or how global
allocation is delegated. Treating addresses as opaque now avoids baking a
premature structure into the wire format.

## 3. Text representation (diagnostics only)

For configs and logs an address is written as eight groups of 1–4
lowercase hex digits separated by colons:

```text
2001:0db8:0000:0000:0000:0000:0000:0001
```

Canonical form pads every group to four digits. There is no `::`
compression in v0.1. This format never appears on the wire — the wire
form is always 16 raw bytes.

## 4. Domains

A *domain* is the administrative scope of local addressing. Anyone may
create an isolated private domain; domains that want global reachability
register with PCN Global operators (see `docs/architecture/network-model.md`).

`DomainId` is a 64-bit identifier. In v0.1 it is chosen by the domain's
administrator; a collision-resistant allocation scheme is future work.
`DomainId::UNSPECIFIED` (0) means "no domain context".

## 5. Planned (not implemented)

- Bit-level split of local/global ranges.
- Address assignment rules inside a domain.
- PCN-ID ↔ address binding and its cryptographic proof.
- Inter-domain and global routing addressing policy.
