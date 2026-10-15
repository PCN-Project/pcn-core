# PCN Security - v0.1

**Status:** honest-statement document. v0.1 ships **no** cryptographic
mechanisms. This file exists to record what is and is not claimed.

## 1. What v0.1 provides

- Deterministic encoding/decoding with strict validation
  (`packet-format.md` §5): short buffers, bad versions, unknown types,
  nonzero reserved fields, unknown flags, and length mismatches are all
  rejected.
- No `unsafe` code; no parsing panics; no length-driven allocation.
- Type-safe separation of identity, routing address, and transport
  endpoint, so future authentication can bind the right things.

## 2. What v0.1 does *not* provide

Do not claim otherwise:

- **No authentication.** Any party can forge any header field, including
  the source address and packet ID. `ECHO_REPLY` proves nothing about
  who sent it.
- **No confidentiality or integrity.** Payloads are plaintext;
  modification in transit is undetectable.
- **No identity.** PCN-ID does not exist yet; a source routing address
  identifies a location claim, not a node.
- **No replay protection.** Packet IDs have no uniqueness guarantee.
- **No authorization.** CONTROL/ERROR semantics are undefined; nothing
  prevents injection.

## 3. Threat model (forward-looking)

The design anticipates:

- on-path observers and active modification on untrusted links,
- spoofed transport endpoints (UDP source addresses),
- malicious or compromised routers in private domains,
- policy tampering, countered by *signed* policy distribution rather than
  trusted distribution channels.

## 4. Planned components (not implemented)

- `pcn-identity`: cryptographic node identity (keypair-bound PCN-ID),
  stable across address changes.
- Session establishment and per-packet authentication/encryption.
- Signed policy objects distributed by PCN Global and enforced locally
  by participating operators/routers. Note the honest limit: signed
  policy can govern participating infrastructure; it cannot block traffic
  on uncontrolled external tunnels or networks.
- Anti-replay (counters/timestamps) once packet authentication exists.

## 5. Interim guidance

- Treat every received packet as untrusted input.
- Use ECHO packets only for reachability diagnostics, never as proof of
  identity or authorization.
- Deployments needing confidentiality must wrap PCN in an external secure
  channel today - and should say so plainly.
