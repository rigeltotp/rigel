## What and why

<!-- What does this change do, and why? Reference the epic (E1, E2, …) and issues. -->

## How it was tested

<!-- Commands you ran and their result (fmt, clippy, tests, cargo deny, flutter analyze/test). -->

## New dependencies

<!-- One line per new Rust or Dart dependency: name, version, why it is needed. "None" if none. -->

## Security checklist

- [ ] No network code, permissions or entitlements added
- [ ] No secrets, issuers or account names in logs, errors, `Debug` output or test snapshots
- [ ] Vault/slot keys do not cross the FFI boundary; seeds only where `CLAUDE.md` allows
- [ ] Untrusted input is parsed in Rust with size limits and has a fuzz target
- [ ] Format changes come with a spec update in `docs/`, a version bump, test files and a migration
- [ ] Touches an area that needs maintainer review (crypto, vault, key stores, formats, FFI, manifests, CI, `deny.toml`, `SECURITY.md`, `LICENSE`): **yes / no**

## DCO

- [ ] All commits are signed off (`git commit -s`) and signed
