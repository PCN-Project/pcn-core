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
│   └── pcnd/               # node daemon (milestone: selftest + packet check)
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
| `pcnd` | `pcnd run` starts a real node: UDP receive loop, static routes, local delivery (log only), forwarding with Hop Limit decrement. `pcnd selftest`/`check <hex>` still work |

### Planned (not created - no empty crates)

`apps/pcn` (CLI for node management), `services/pcn-registry` (PCN Global
registry), `crates/pcn-protocol` (message semantics), `crates/pcn-identity`
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
`forwarded:` (rebuilt with Hop Limit - 1 toward the next hop's endpoint),
or `dropped:`. Delivered packets are only logged - there is no echo
responder or ping yet.

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
