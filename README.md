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
> [docs/protocol/v0.1/security.md](docs/protocol/v0.1/security.md) for an
> honest list of what is and is not provided.

## Workspace layout

```text
pcn-core/
├── Cargo.toml              # workspace manifest (resolver 2, MSRV 1.75)
├── rust-toolchain.toml     # stable toolchain + rustfmt/clippy
├── docs/
│   ├── architecture/       # overview.md, network-model.md
│   └── protocol/v0.1/      # packet-format, addressing, transport, security
├── apps/
│   └── pcnd/               # node daemon (milestone: selftest + packet check)
├── crates/
│   ├── pcn-address/        # Address, DomainId, ScopedAddress
│   └── pcn-packet/         # v0.1 wire format: encode/parse/validate
├── services/               # pcn-registry (planned - not created yet)
├── tests/                  # cross-crate integration/interop (planned)
└── deploy/                 # packaging notes (planned)
```

### Built in this milestone

| Component | What it does |
|---|---|
| `pcn-address` | 64-bit PCN-ADDR `Address` (type + 60-bit value + reserved bit; `pcn~TXXX-XXXX-XXXXX` Base32 text form), `AddressType`, `DomainId`, domain-qualified `ScopedAddress` |
| `pcn-packet` | Typed `Header`/`Packet`/`PacketType`, deterministic big-endian encoding, validating parser with typed `ParseError`, `PacketBuilder` with `BuildError` |
| `pcnd` | `pcnd selftest` exercises the codec; `pcnd check <hex>` decodes a datagram. No sockets, no async |

### Planned (not created - no empty crates)

`apps/pcn` (CLI for node management), `services/pcn-registry` (PCN Global
registry), `crates/pcn-transport` + `pcn-transport-udp` (transport
abstraction and UDP impl), `crates/pcn-routing` (tables/forwarding),
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
