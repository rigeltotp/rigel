# Spikes (milestone M0)

Short, time-boxed experiments that answer open feasibility questions of the
specs. Each spike gets a file `<name>.md` with question, method, result and
the spec section it changes.

| Spike | Question | Changes |
| ----- | -------- | ------- |
| `fido2-windows` | Can `hmac-secret`/PRF be used through the Windows WebAuthn API? | vault-format.md 4.5 |
| `fido2-ios` | Can `hmac-secret`/PRF be used over NFC/USB-C on iOS, and with which `rp_id`? | vault-format.md 4.5 (V-42) |
| `fido2-android` | Platform API or direct CTAP over USB/NFC? | vault-format.md 4.5 |
| `ios-autofill-memory` | Does the AutoFill extension stay within its memory limit when opening the vault and computing a code? | threat-model.md 7 |
| `qr-rust` | Does `rqrr` (or alternatives) decode real-world screenshots and camera frames reliably? | backup-format.md, E3 |
| `windows-hello-slot` | Is the Windows Hello signature deterministic enough for the device slot? | vault-format.md V-38 |
| `age-pq` | Does `rage` support hybrid post-quantum identities with decryption? | backup-format.md B-6 |

Status: `qr-rust` done (decision pending); the others not started.
