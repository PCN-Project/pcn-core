# tests/ — cross-crate test suites (planned)

This directory is reserved for tests that exercise multiple workspace
crates together. It is intentionally **not** a Cargo package yet — there
is no second crate to integrate with. Per-crate tests live where Rust
expects them (`crates/<name>/tests/` and inline `#[cfg(test)]` modules).

Planned contents:

- `integration/` — multi-crate end-to-end checks, e.g.
  `pcn-transport-udp` carrying `pcn-packet` datagrams between two in-process
  nodes once the transport exists.
- `interoperability/` — captured wire vectors exchanged with other PCN
  implementations to detect encoder drift.
- `fixtures/` — shared datagram/address corpora used by the suites above.

A `Cargo.toml` turning this into a workspace test package will be added
with the first real suite; until then these directories exist to keep the
structure documented rather than fake code.
