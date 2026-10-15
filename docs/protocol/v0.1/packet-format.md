# PCN Packet Format - v0.1 (provisional)

**Status:** provisional specification. Wire values and semantics may change
in a later revision; peers must reject anything they do not recognize rather
than guess.

## 1. Scope

This document defines the v0.1 PCN packet wire format: the fixed base header,
the packet types, and the validation rules every implementation must apply.

It does not define routing behavior, cryptographic protection, or transport
details (see `transport.md` and `security.md`).

## 2. Base header

Every PCN packet begins with a header of exactly **32 bytes**. All multi-byte
integer fields are **big-endian**. The layout is fixed; it is not derived
from any programming-language struct and must be serialized explicitly.

| Offset | Field | Size | Description |
|---:|---|---:|---|
| 0 | Version | 1 | `1` for protocol v0.1 |
| 1 | Type | 1 | packet type (below) |
| 2 | Flags | 2 | reserved extension flags; must be `0` in v0.1 |
| 4 | Header Length | 2 | total header length; `32` in v0.1 |
| 6 | Payload Length | 2 | bytes following the header |
| 8 | Hop Limit | 1 | forwarding hop budget |
| 9 | Reserved | 3 | must be `0` in v0.1 |
| 12 | Source Address | 8 | source PCN routing address |
| 20 | Destination Address | 8 | destination PCN routing address |
| 28 | Packet ID | 4 | sender-assigned identifier |

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Type      |             Flags             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Header Length         |        Payload Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Hop Limit   |                  Reserved                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Source Address (64)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   Destination Address (64)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Packet ID                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## 3. Packet types (provisional)

| Value | Name | Meaning |
|---:|---|---|
| `0x01` | `DATA` | upper-layer data |
| `0x02` | `ECHO_REQUEST` | liveness probe; recipient should answer `ECHO_REPLY` |
| `0x03` | `ECHO_REPLY` | answer to `ECHO_REQUEST` |
| `0x04` | `ERROR` | reports a delivery/processing failure |
| `0x05` | `CONTROL` | control-plane message (routing, administration) |

These values are provisional and may be renumbered before the format is
frozen. Payload semantics per type are not defined in v0.1.

## 4. Field notes

- **Version.** Wire-format generation. Release 0.1 is encoded as `1`.
  A packet with any other version must be rejected; version negotiation
  does not exist yet.
- **Flags.** No flag bits are defined in v0.1. The field exists to let a
  later version signal optional features. Any nonzero value must be
  rejected, never ignored - silently dropping unknown flags would break
  future signaling.
- **Header Length.** Always `32` in v0.1. The field is reserved so later
  versions can add extensions between the base header and the payload.
  No extension format is defined yet, so any other value is invalid.
- **Payload Length.** Bytes following the header. `0` is legal.
- **Hop Limit.** Forwarding budget, semantics defined by the routing layer
  (planned: decrement per hop, drop at zero). The packet layer carries
  the field without interpreting it.
- **Reserved.** Must be zero. Reserved bits exist to be defined later;
  nonzero values indicate a peer speaking a newer or corrupt format.
- **Source / Destination Address.** 8-byte (64-bit) PCN-ADDR routing
  addresses (`addressing.md`): bits `[63:61]` are the address type
  (1 = private, 2 = public), bits `[60:1]` the value, and bit `[0]` a
  reserved bit that must be `0`. These are *routing* addresses: they
  are not node identities and are unrelated to transport endpoints
  such as IP address + UDP port. An address is routable only if its
  type is assigned (1 or 2) and its reserved bit is clear; the
  all-zero unspecified address is never legal in either field.
- **Packet ID.** Opaque sender-assigned identifier, e.g. to correlate
  `ECHO_REQUEST`/`ECHO_REPLY`. No uniqueness or ordering is guaranteed.

## 5. Validation rules

A receiver must reject a datagram when any of the following holds, and must
not inspect fields beyond what is needed for the check that fails:

1. Fewer than 32 bytes received (no field may be read before this check).
2. Version ≠ `1`.
3. Header Length ≠ `32`.
4. `Header Length + Payload Length` ≠ received datagram length
   (compute in a width that cannot overflow, e.g. `usize`).
5. Declared total length exceeds the implementation's maximum packet size
   (v0.1 absolute ceiling: 65 535 bytes, chosen so a packet fits one UDP
   datagram).
6. Any Reserved byte ≠ `0`.
7. Any Flags bit set (v0.1 defines none).
8. Type is not one of the assigned values.
9. Source or Destination Address is the all-zero unspecified address.
10. An address field has reserved bit `[0]` set.
11. An address type field is not assigned in v0.1 (only `1` = private
    and `2` = public are routable; this includes reserved type `0`
    with a nonzero value).

Additional implementation requirements:

- Never use `unsafe` for parsing.
- Never allocate memory based on an unverified length field; only allocate
  after declared and actual lengths are proven equal and in bounds.
- Do not panic on malformed input; report a typed error.
- Serialization must be deterministic and must not depend on host
  endianness or in-memory layout.

## 6. Extensibility

Deliberately undefined in v0.1: header extensions, flag bits, per-type
payload structures, fragmentation, and any cryptographic envelope. The
format reserves the mechanisms (Flags, Header Length, Reserved bytes) that
later versions will define them through.
