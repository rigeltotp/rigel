# Contributing to Rigel

Thank you for helping. Rigel protects the second factor of people's accounts,
so the bar for changes is high, and security and privacy win over convenience.
Please read [`CLAUDE.md`](CLAUDE.md) (the working rules for humans and AI
assistants alike) and the specs in [`docs/`](docs/README.md) before you start.

**Security problems are never reported in public.** See
[`SECURITY.md`](SECURITY.md).

## License of contributions

Rigel is licensed under the GNU GPL version 3 or later **with an additional
permission for App Store distribution** (see [`LICENSE`](LICENSE)). By
contributing you agree that your contribution is licensed under exactly
these terms, including the additional permission. Without that, Rigel could
not be shipped through the App Store or Google Play.

## Developer Certificate of Origin (DCO)

Every commit must carry a `Signed-off-by` line with your real name or a
known pseudonym and an e-mail address you control. It certifies the
[Developer Certificate of Origin](DCO): that you wrote the change or have the
right to submit it under the project license.

```sh
git commit -s -m "feat(core): add HOTP counter resync"
```

The `Signed-off-by` e-mail must match the commit author. CI checks every
commit of a pull request and fails if a sign-off is missing.

Forgot it? Add it to the commits of your branch with:

```sh
git rebase --signoff origin/main
git push --force-with-lease
```

## Signed commits

`main` accepts only signed commits (GPG or SSH signing). Set it up once:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

## Workflow

1. Open an issue or comment on an existing one before larger work, so we can
   agree on the approach. Security-relevant designs are discussed in `docs/`
   first.
2. Work on a feature branch. Never push to `main`.
3. Use [Conventional Commits](https://www.conventionalcommits.org/):
   `feat(core): …`, `fix(app): …`, `docs(spec): …`, `ci: …`. One logical
   change per commit.
4. Keep pull requests small and reference the epic (`E3`, …).
5. Fill in the pull request template, including the security checklist.

## Before you open a pull request

Run the checks for the parts you touched (see `CLAUDE.md`, section 4):

```sh
# Rust, from core/
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check

# Flutter, from app/
dart format --output=none --set-exit-if-changed .
flutter analyze
flutter test

# Repository policy (no network code, pinned CI), from the repo root
python3 tools/ci/check_policy.py
```

## Rules that are never negotiable

- No network code or network dependencies, no telemetry, no analytics.
- No home-made cryptography. Only the `core` crypto facade calls primitives.
- No secrets, issuers or account names in logs, errors or test snapshots.
- New dependencies need a one-line justification and must pass `cargo deny`
  and `cargo vet`. Third-party GPL dependencies are not accepted, because the
  App Store permission cannot cover code we do not own.
- Tests, lints and CI checks are never weakened or skipped to get green.
- Test data uses RFC test vectors or freshly generated fake seeds, never real
  accounts.
- Changes to the vault, backup or sync formats need a spec update in `docs/`,
  a schema version bump, new test files and a migration.

## Areas that need maintainer review

Changes to these areas always need an explicit review by a maintainer:
the crypto facade, vault and slot code, key-store integrations, file formats
and migrations, the FFI surface, permissions/entitlements/manifests,
`core/deny.toml`, CI/release/signing workflows, `SECURITY.md`, `LICENSE`.

## Using AI assistants

AI-assisted contributions are welcome under the same rules. You remain
responsible for every line: review it, test it, and sign off only what you
can certify under the DCO.
