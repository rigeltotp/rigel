# Security policy

Rigel stores the secrets that protect people's accounts. We treat every
security report as a priority and we are grateful to anyone who helps us find
problems before attackers do.

## Supported versions

Rigel has not been released yet. Until 1.0, only the latest commit on `main`
and the latest pre-release receive security fixes. This table will list
supported release lines once releases exist.

| Version        | Supported |
| -------------- | --------- |
| `main`         | yes       |
| pre-releases   | latest only |

## How to report a vulnerability

**Please do not open a public issue, discussion or pull request for a
security problem.**

Report privately through GitHub's private vulnerability reporting:
go to the repository's **Security** tab and choose
**Report a vulnerability**. Only the maintainers can see these reports.

Until release 1.0 this is the only reporting channel; an e-mail contact is
added with 1.0. You need a GitHub account to report.

Please include, as far as you can:

- the affected component (core, platform crate, app, AutoFill extension,
  backup or sync format, build/release pipeline) and version or commit,
- the platform and OS version,
- a description of the problem and its impact,
- steps to reproduce or a proof of concept,
- whether you want to be credited, and under which name.

**Never send real secrets** (OTP seeds, backups of real accounts, recovery
codes). Use freshly generated test accounts or RFC test vectors.

## What happens next

| Step | Target time |
| ---- | ----------- |
| Acknowledgement of your report | within 3 working days |
| First assessment (confirmed or not, severity) | within 10 working days |
| Fix for critical and high severity issues | as fast as possible, aim: 30 days |
| Fix for medium and low severity issues | aim: 90 days |
| Public advisory | when a fixed release is available, coordinated with you |

We follow coordinated disclosure. We aim to publish an advisory within
90 days of the report. If a fix takes longer, we will explain why and agree a
new date with you. We publish advisories through GitHub Security Advisories
and request CVE identifiers where appropriate.

## Scope

In scope, among others:

- disclosure of OTP seeds, vault keys, recovery codes or entry metadata
  (issuers, account names) to anyone but the user,
- bypassing the app lock, unlock slots or AutoFill domain matching,
- weaknesses in the vault, backup or sync formats (`docs/`) or their
  implementation,
- crashes or memory unsafety triggered by import files, QR codes, otpauth
  URIs, backups, sync journals or icon packs,
- any network connection made by the app (Rigel must make none),
- data loss caused by updates or migrations,
- problems in the build, signing and release process.

Out of scope (see `docs/threat-model.md` for the reasoning):

- attacks that need a fully compromised operating system (root, jailbreak,
  malware with debugging rights),
- phishing of one-time codes, which TOTP cannot prevent by design,
- missing hardening on platforms or OS versions that Rigel does not support.

## Safe harbour

We will not take legal action against people who research and report in good
faith under this policy: who avoid privacy violations and data destruction,
use only their own accounts and test data, and give us reasonable time to fix
the problem before disclosure.

## Security design

The threat model and the formats are documented in
[`docs/`](docs/README.md).
