# Definition of Done and QA pass

An epic counts as done only after its QA pass has the result **passed**.
Dependent epics may start earlier.

## QA pass procedure

When an epic thread reports "Epic E<n> done" (with its PR links), the
coordinator starts a thread "QA-Pass E<n>" without asking. That thread:

1. runs the PR checks (see [README.md](README.md)) and the relevant nightly
   jobs on current `main`;
2. checks every item in "All epics" and the epic's row below;
3. reviews the whole epic diff for security and correctness;
4. fixes small, unambiguous findings itself in a PR;
5. submits security-relevant findings, and anything in the "always needs human
   review" areas of `CLAUDE.md`, to the maintainer for a decision;
6. writes `docs/qa/E<n>.md` with the result **passed**, **passed with
   conditions** or **failed**.

## All epics

- [ ] All PRs of the epic are merged; PR checks are green on `main`; the last
      nightly run is green.
- [ ] New logic has unit tests; new parsers have property tests **and** a
      fuzz target.
- [ ] Coverage targets met: `rigel-core` at least 90 % lines; crypto facade,
      OTP and backup at least 95 %; coverage must not drop per PR.
- [ ] No new dependency without justification; `cargo deny` and `cargo vet`
      are green.
- [ ] Network check and URL check are green; no new permission without an
      entry in the permission review.
- [ ] Security review of the whole epic diff done; findings fixed or
      knowingly accepted (with reasoning).
- [ ] Threat model in `docs/` checked and extended where needed.
- [ ] Specs, `CLAUDE.md` and ADRs updated.
- [ ] User-facing text in German and English; screens usable with a screen
      reader (UI epics only).
- [ ] QA report `docs/qa/E<n>.md` exists.

## Additional criteria per epic

| Epic | Additional criteria |
| ---- | ------------------- |
| E1 Foundation | All PR jobs exist and are required checks for `main`; branch protection active; nightly workflow runs; SBOM generated per PR |
| E2 Specs | Every spec has test files (valid and intentionally broken); threat model covers all assets and attackers |
| E3 OTP core | All RFC vectors; fuzz targets for the otpauth parser and QR decoding; time edges (period change, time offset, year 2038) tested |
| E4 Crypto/vault | Known-answer tests and Wycheproof green; AAD binding proven by negative test (swapped entries are rejected); migration with snapshot against real old files; Miri green; `secure_delete` + `VACUUM` proven by test |
| E5 Key stores | Instrumented tests on emulator/device; biometrics release only a hardware-bound key; minimum password strength tested |
| E6 Bridge | FFI API snapshot created; no seed type crosses the boundary |
| E7 Core UI | Widget and golden tests; clipboard timeout tested; accessibility checked |
| E8 Backup | `age` interop in both directions; restore test; plaintext export only after unlock and warning (UI test) |
| E9 Import | Synthetic test files and a fuzz target per source app; size limits tested |
| E10 Platform | Negative tests for domain/app-ID matching (no code on wrong domain); widgets do not link the core (build check) |
| E11 Hardening | All hardening checks from the nightly integration tests green on all platforms; permission review documented |
| E12 Sync | Model-based property tests for conflict resolution; signature checks with tampered journals; fuzz target for journals |
| E13 Browser | Fuzz target for Native Messaging messages; minimal extension permissions; no remote content (CSP) |
| E14 Hardware keys | Manual test protocol with real YubiKeys (USB, NFC) documented; failure cases (key removed) tested |
| E15 Quality | Reporting process tested; coverage and fuzz targets met |
| E16 Distribution | Reproducible build confirmed bit-identical; signed SBOM and build provenance published |
| E17 Aegis | Icon-pack fuzzing; SVG sanitising tested with malicious SVGs; Aegis can read our export (interop test) |
