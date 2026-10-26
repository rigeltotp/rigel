# ADR 0001: Foundation choices

Status: accepted (2026-10-25, from the reviewed architecture plan)

## Context

Rigel needs one security-critical implementation for five platforms, without
network code, with a UI that can be replaced.

## Decisions

- **Flutter UI, Rust core, native extensions.** All secrets live in the Rust
  core. Bindings: flutter_rust_bridge (Dart) and UniFFI (Swift/Kotlin).
- **Four crates to start**, named `rigel-core`, `rigel-platform`,
  `rigel-ffi-dart`, `rigel-ffi-uniffi` (directories `core/crates/<name>`).
  The core crate is called `rigel-core` (library `rigel_core`), because a
  crate named `core` would shadow Rust's own `core` library.
- **Rust edition 2024, toolchain pinned** in `core/rust-toolchain.toml`
  (1.97.0). `unsafe` is denied workspace-wide and forbidden in `rigel-core`.
- **Minimum platform versions:** iOS 17, Android 9 (API 28), Windows 10,
  macOS 13, current LTS Linux distributions.
- **Flutter pinned** to 3.47.8 (`app/pubspec.yaml`, `tools/ci/install-flutter.sh`
  with checksums).
- **License:** GPL-3.0-or-later with an additional permission for app stores
  (`LICENSE`, `COPYING`); contributions under DCO.
- **CI without third-party actions.** Checkout is a plain `git fetch`; tools
  are installed at pinned versions from crates.io, PyPI, the Go module proxy
  and checksum-verified downloads. Reason: action versions cannot be
  verified offline, and every action is supply-chain surface (CLAUDE.md
  rule 17). If actions are added later, they are pinned to commit SHAs;
  `tools/ci/check_policy.py` enforces that.
- **Android application ID `org.rigel.rigel`** and Apple bundle identifier
  prefix `org.rigel` are placeholders until the project name and the
  publishing organisation are final.
- **Project name "Rigel"** is provisional; check for collisions with apps and
  trademarks before the first public release.

## Consequences

Renaming the application ID later is cheap now and expensive after the first
store release; decide before M1 ends.
