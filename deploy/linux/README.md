# deploy/linux/ (planned)

Linux packaging for `pcnd` will live here: systemd unit, filesystem
layout, and distro notes. Nothing exists yet — the v0.1 daemon performs
no network I/O and is run directly with `cargo run -p pcnd -- <cmd>`.

Anticipated concerns when packaging lands:

- `pcnd` will need CAP_NET_RAW/TUN privileges once real transports land.
- systemd hardening directives should ship with the unit.
