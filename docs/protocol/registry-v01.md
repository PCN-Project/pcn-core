# Address registry protocol v0.1

`pcn-registry` serves name → private-address allocations over TCP.
This is a local prototype for a future registry system — it is not PCN
Global, stores no IP endpoints, and changes nothing about routing.

## Framing

Every message is one frame:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        length (u32 BE)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     UTF-8 payload (length)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `length` counts the payload bytes, excludes itself.
- `0 < length <= 8192` (`MAX_FRAME`). A zero or oversized length
  closes the connection; a partial frame is an error; TCP read
  boundaries never define message boundaries.
- Payload is UTF-8 text, tokens separated by single spaces.

## Requests

| Request | Semantics |
|---|---|
| `alloc <name>` | Return `name`'s allocation, else allocate the lowest free value. Idempotent. |
| `alloc <name> <addr>` | Prefer `<addr>`: taken-by-other → `err addr_taken`; `name` already holds a different address → `err name_taken`; free → allocate. |
| `reserve <name> <addr>` | Strictly claim `<addr>` for a NEW `<name>` — never idempotent. |
| `lookup <name>` | name → address. |
| `whois <addr>` | address → name. |
| `list` | All records, sorted by name. |

## Responses

| Response | Meaning |
|---|---|
| `ok registered <name> <addr>` | `alloc`/`reserve` outcome. |
| `ok addr <addr>` | `lookup` result. |
| `ok name <name>` | `whois` result. |
| `ok list <n>` + n lines `<name> <addr>` | `list` result. |
| `err <code> <message>` | Failure; codes below. |

## Error codes

`bad_request` (malformed frame payload), `invalid_name`,
`bad_address` (not a private address or out of range), `name_taken`,
`addr_taken`, `not_found`, `addr_not_found`, `exhausted`, `io`
(persist failed — the in-memory change was rolled back).

## Names

Normalized to lowercase; allowed `[a-z0-9._-]`, 1–64 bytes, first and
last character alphanumeric.

## Addresses

v0.1 allocates **private (type-1) addresses only**, value range
`--range-min..=--range-max` (defaults `1-1048575`, a deliberately small
slice of the 60-bit space). Auto-allocation picks the lowest free
value — deterministic, no randomness, no consensus.

## Persistence

State file: one `name<TAB>pcn~address` line per record, rewritten
atomically (tmp + rename) before every successful mutation is
reported. A restart reloads it; corrupt lines or duplicate
name/address refuse startup rather than silently patching.

## Limits (by design)

- No authentication or authorization — any TCP client may allocate.
- No release/renew: allocations never expire.
- Single-node state; no replication or distributed consensus.
- `list` responses are bounded by `MAX_FRAME` (~270 records).
