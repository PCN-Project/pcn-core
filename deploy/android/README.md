# deploy/android/ (planned)

Android is a first-class target for PCN Core, but a portable Rust library
is **not** an Android application. This directory will eventually hold
what turns the libraries into one.

Status and honest constraints:

- The protocol crates (`pcn-packet`, `pcn-address`) are portable Rust with
  no Linux-specific APIs and must compile for Android ABIs
  (`aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`).
- Missing pieces, all future work: an Android app shell, `VpnService`
  integration (the only unprivileged way to move packets on Android),
  JNI/NDK glue, and lifecycle/battery handling.
- Expect to build with `cargo ndk` or Gradle + rustup Android targets;
  toolchain notes will land here with the first working build.

Cross-compile smoke check once the NDK targets are installed:

```bash
rustup target add aarch64-linux-android
cargo check -p pcn-packet --target aarch64-linux-android
```
