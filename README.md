# PCN Core

PCN Core is the reference implementation of **PCN**, a multi-transport
network architecture, written in Rust for Linux and Android.

PCN separates node **identity** (stable PCN-ID, future work), **routing
addresses** (64-bit PCN-ADDR locators in packet headers), and **transport
endpoints** (e.g. IP + UDP port). UDP/IP is the first transport - an
overlay - not a permanent dependency; direct Ethernet and other media are
planned under the same identity and routing model.

> **Status: early development.** Protocol v0.1 is provisional. There is no
> cryptography, no routing, and no networking yet - see
> [docs/protocol/security.md](docs/protocol/security.md) for an
> honest list of what is and is not provided.

## Workspace layout

```text
pcn-core/
├── Cargo.toml              # workspace manifest (resolver 2, MSRV 1.75)
├── rust-toolchain.toml     # stable toolchain + rustfmt/clippy
├── docs/
│   ├── architecture/       # overview.md, network-model.md
│   └── protocol/           # packet-format, addressing, transport, security
├── apps/
│   ├── pcn/                # client CLI (pcn ping over PCN-over-UDP)
│   └── pcnd/               # node daemon (pcnd run/selftest/check)
├── crates/
│   ├── pcn-address/        # Address, DomainId, ScopedAddress
│   ├── pcn-packet/         # v0.1 wire format: encode/parse/validate
│   ├── pcn-routing/        # static route table + forwarding decision lib
│   ├── pcn-transport/      # transport-agnostic datagram interface
│   └── pcn-transport-udp/  # UDP transport over UdpSocket (sync)
├── services/               # pcn-registry (planned - not created yet)
├── tests/                  # cross-crate integration/interop (planned)
└── deploy/                 # packaging notes (planned)
```

### Built in this milestone

| Component | What it does |
|---|---|
| `pcn-address` | 64-bit PCN-ADDR `Address` (type + 60-bit value + reserved bit; `pcn~TXXX-XXXX-XXXXX` Base32 text form), `AddressType`, `DomainId`, domain-qualified `ScopedAddress` |
| `pcn-routing` | Static exact-match `RouteTable`, deliver/forward/drop decision, hop-limit-aware `forward` helper - drives `pcnd run` |
| `pcn-transport` + `pcn-transport-udp` | `Transport` trait (send/recv/timeout/local endpoint) and a synchronous `UdpSocket` implementation |
| `pcn-packet` | Typed `Header`/`Packet`/`PacketType`, deterministic big-endian encoding, validating parser with typed `ParseError`, `PacketBuilder` with `BuildError` |
| `pcnd` | `pcnd run` starts a real node: UDP receive loop, static routes, local delivery, forwarding with Hop Limit decrement, ECHO_REQUEST -> ECHO_REPLY responder. `selftest`/`check` still work |
| `pcn` | `pcn ping` sends real PCN ECHO_REQUESTs over UDP through a configured next hop, matches replies (type + both addresses + packet_id), reports RTT and loss. `pcn send`/`pcn recv` move UTF-8 DATA payloads the same way, acknowledged end-to-end with `ACK` packets |

### Planned (not created - no empty crates)

`services/pcn-registry` (PCN Global registry),
`crates/pcn-protocol` (message semantics), `crates/pcn-identity`
(cryptographic PCN-ID), `crates/pcn-config` (configuration).

Deviation from the original sketch: `tests/` and `deploy/` exist as
documentation placeholders only; per-crate tests live in
`crates/*/tests/` following Rust convention.

## Build & test

Requires stable Rust ≥ 1.75 (MSRV, declared in `Cargo.toml`).

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```

Run the daemon's self-test and packet inspector:

```bash
cargo run -p pcnd -- selftest
cargo run -p pcnd -- check "0102 0000 0020 0004 40000000 20000000 00000002 40000000 00000004 abcd1234 deadbeef"
```

Run a node (`pcnd run --help` for the full flag list):

```bash
# Node B on 127.0.0.1:41003 with PCN address pcn~1000-0000-00002
pcnd run --listen 127.0.0.1:41003 \
    --address pcn~1000-0000-00002 \
    --next-hop 1=127.0.0.1:41002 \
    --route pcn~1000-0000-00001=1
```

The node parses every UDP datagram as a PCN packet, applies the static
route table, and logs each decision: `delivered:` (local destination),
`forwarded:`/`replied:` (sent toward the next hop's endpoint),
or `dropped:`.

Ping end-to-end - A (client) -> R1 (router) -> B (node) and back,
all on loopback. Note the return routes: ping only works if every node
on the path knows the way back to A's PCN address.

```bash
# B - destination, answers ECHO_REQUEST; route back to A via R1
pcnd run --listen 127.0.0.1:41003 --address pcn~1000-0000-00002 \
    --next-hop 1=127.0.0.1:41002 --route pcn~1000-0000-00001=1

# R1 - router, routes to B (next-hop 1) and back to A (next-hop 2)
pcnd run --listen 127.0.0.1:41002 --address pcn~1000-0000-00009 \
    --next-hop 1=127.0.0.1:41003 --route pcn~1000-0000-00002=1 \
    --next-hop 2=127.0.0.1:41001 --route pcn~1000-0000-00001=2

# A - the ping client IS a PCN endpoint; --via is its gateway
pcn ping --listen 127.0.0.1:41001 --source pcn~1000-0000-00001 \
    --target pcn~1000-0000-00002 --via 127.0.0.1:41002 \
    --count 4 --timeout-ms 1000 --interval-ms 1000
```

Each `reply from pcn~...` line reports RTT on a monotonic clock; the
summary prints sent/received/lost, loss percentage and rtt min/avg/max.

Send DATA (application payload) instead of a probe:

```bash
# B - receive DATA for its address; --via is the first hop for ACKs
pcn recv --listen 127.0.0.1:41003 --source pcn~1000-0000-00002 \
    --via 127.0.0.1:41002

# A - one DATA packet through R1 to B; exit 0 only after B's ACK
pcn send --listen 127.0.0.1:41001 --source pcn~1000-0000-00001 \
    --target pcn~1000-0000-00002 --via 127.0.0.1:41002 \
    --message "Zażółć gęślą jaźń"
```

`pcn recv` prints `data from pcn~...: <payload>` for DATA packets
addressed to `--source` and answers each with an `ACK` sent via
`--via`; `pcnd` nodes log delivered payloads and ACK them through their
route table. By default `send` requires a matching `ACK` (type + both
addresses + packet_id) within `--timeout-ms` (default 1000) and retries
`--retries` times (default 2) with the SAME packet_id; `--no-ack`
restores fire-and-forget. A retry can deliver a duplicate `DATA` -
receivers dedup by `(source, packet_id)` and print retries as
`(duplicate)`, so at-most-once holds at the application level, while
the ACK may arrive late. `pcnd` uses the same `(source, packet_id)`
dedup before logging `delivered:`.

Inter-node transport is UDP only; there is no dynamic routing,
cryptographic neighbor identity, or PCN Global.

## Engineering rules

- No `unsafe` (forbidden workspace-wide via `[workspace.lints]`).
- No panics on malformed network input; parsing returns typed errors.
- Big-endian wire fields only; never serialize native struct layout.
- No unused dependencies; keep the dependency tree near zero until a need
  is demonstrated.
- Public APIs carry doc comments (`cargo doc --workspace` should be clean).

## License

[PCN Source-Available License 1.0 (PCN-SAL-1.0)](LICENSE) - a draft
source-available license: audit, study, and non-commercial use are
permitted; commercial use requires a separate PCN Commercial License. It
is **not** an open source license within the meaning of the Open Source
Definition.
