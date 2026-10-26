# Quality assurance

Quality is checked automatically on three levels. This directory holds the
reports and the rules around them.

1. **Every pull request** (target: under 20 minutes). Workflow
   [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml). A red check
   blocks the merge; see [branch-protection.md](branch-protection.md).
2. **Nightly**. Workflow
   [`.github/workflows/nightly.yml`](../../.github/workflows/nightly.yml):
   long fuzzing, mutation tests, Miri, emulator/simulator integration tests,
   `age` interoperability. A red scheduled run opens an issue.
3. **After every epic**: an independent QA pass checks the epic against its
   Definition of Done and writes `E<n>.md` here.

The full concept (what runs when, Definition of Done per epic, QA pass
procedure) is maintained in `docs/qa/` as it is adopted from the QA concept;
this file lists what exists today.

## What CI runs today (E1)

| Job | Checks |
| --- | ------ |
| `policy` | `tools/ci/check_policy.py` (no network in Cargo.lock, pubspec.lock, Dart sources, Android manifest, macOS/iOS entitlements, Flatpak; crypto only in the facade; actions pinned to SHAs; SPDX headers) with self-tests; `reuse lint` |
| `dco` | DCO sign-off on every commit; Conventional Commit subjects |
| `rust` (Linux, macOS, Windows) | `cargo fmt --check` (Linux), `clippy -D warnings`, `cargo nextest`, doc tests |
| `coverage` | `cargo llvm-cov` for `rigel-core`, threshold in `core/coverage-thresholds.txt` |
| `rust-supply-chain` | `cargo deny` (advisories, licenses, bans, sources), `cargo audit`, `cargo vet` |
| `security-scans` | `gitleaks`, `zizmor`, `osv-scanner` on `pubspec.lock` and `Cargo.lock` |
| `flutter` | `dart format`, `flutter analyze`, `flutter test` with the lockfile enforced |
| `build` (Android, Linux, Windows, macOS, iOS) | release builds; no URL strings in binaries; no network permission in the release APK; no network entitlement in the macOS app |
| `formats` | Test files of all formats are valid / invalid as intended |

Not yet possible, added with the epic named: bindings-diff check (E6, E10),
FFI API snapshot (E6), fuzz smoke on parser changes (E3), Miri on `unsafe`
changes (E4/E5), Semgrep rules (open), CodeQL as GitHub "default setup"
(see branch-protection.md).

## Reports

`E<n>.md` per epic, written by the QA pass.
