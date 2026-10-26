# Branch protection and required checks

These repository settings are not code and must be configured by a
repository admin on GitHub. They are part of the Definition of Done of E1.

## Ruleset for `main`

Settings → Rules → Rulesets → New branch ruleset, target `main`:

- Restrict deletions and block force pushes.
- Require a pull request before merging: at least 1 approval, dismiss stale
  approvals on new pushes, require review from code owners (`CODEOWNERS`),
  require conversation resolution.
- Require signed commits.
- Require linear history.
- Require status checks to pass, branches up to date before merging.
  Required checks (job names from `ci.yml`):
  - `Policy (no network, manifests, pinned actions, SPDX)`
  - `DCO sign-off`
  - `Rust (ubuntu-24.04)`, `Rust (macos-15)`, `Rust (windows-2025)`
  - `Coverage (cargo-llvm-cov)`
  - `Rust supply chain (cargo-deny, cargo-vet)`
  - `Secret scan, workflow audit, Dart advisories`
  - `Flutter (format, analyze, test)`
  - `Formats (test files)`
  - `Build android`, `Build linux`, `Build windows`, `Build macos`, `Build ios`
  - `CodeQL` (see below)
- Do not allow bypassing, also not for admins.

## Other repository settings

- Actions → General: allow only actions from the repository itself;
  workflow permissions default to read-only; do not allow Actions to create
  pull requests. (CI uses no third-party actions.)
- Code security: enable private vulnerability reporting, Dependabot alerts
  and security updates, secret scanning with push protection.
- **CodeQL**: Code security → Code scanning → "Set up" → *Default setup*
  for Rust, Swift, Kotlin/Java and GitHub Actions. Default setup is used
  instead of a workflow, because a workflow would need the third-party
  `github/codeql-action`, which this repository does not use in CI. Add it
  as a required check once the first run exists.
- Maintainers use hardware-key two-factor authentication; require 2FA for
  the organisation.
- Tag protection for `v*` tags; releases only from signed tags.

## Keeping this list current

When a CI job is added, renamed or removed, update this file in the same
pull request and ask an admin to adjust the ruleset.
