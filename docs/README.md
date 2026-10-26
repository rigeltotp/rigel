# Rigel documentation

The documents in this directory are the **source of truth** for Rigel's
security design and file formats. Where code, `CLAUDE.md` or comments
disagree with them, these documents win, and the disagreement is a bug.

| Document | Content | Status |
| -------- | ------- | ------ |
| [threat-model.md](threat-model.md) | Assets, adversaries, trust boundaries, security requirements | Draft 1, for review |
| [specs/vault-format.md](specs/vault-format.md) | Key hierarchy, unlock slots, record encryption, SQLite container | Draft 1, for review |
| [specs/backup-format.md](specs/backup-format.md) | `*.rigel.age` backups, plaintext exports, import limits | Draft 1, for review |
| [specs/sync-format.md](specs/sync-format.md) | Folder sync protocol (release 1.1) | Draft 1, protocol details open |
| [schemas/](schemas/) | Machine-readable JSON schemas | Draft 1 |
| [formats/](formats/) | Test files for every format version | Draft 1 |
| [spikes/](spikes/README.md) | Feasibility spikes of milestone M0 | Planned |
| [decisions/](decisions/) | Architecture decision records (ADR) | Ongoing |

## Conventions

- The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and
  **MAY** are used as described in RFC 2119 and RFC 8174 when written in
  capitals.
- Requirement IDs (`SR-…` in the threat model, `V-…`, `B-…`, `S-…` in the
  specs) are stable. Code and tests reference them in comments, for example
  `// V-17: AAD binds vault ID, record ID, kind and schema version`.
- All multi-byte integers in binary structures are **big-endian** unless
  stated otherwise.
- `||` is byte concatenation. `"text"` in a byte context means the UTF-8
  bytes of the text without a terminator.
- Lengths are in bytes unless stated otherwise. `KiB` and `MiB` are binary.

## Changing a format

A change to the vault, backup or sync format MUST (CLAUDE.md, rule 7):

1. update the spec here, with a changelog entry at the end of the spec,
2. bump the relevant version number,
3. add test files for the new version under `formats/` and keep all old ones,
4. come with a migration that takes an encrypted snapshot first, tested
   against the stored files of every older version.

Old test files are never edited or deleted: they are the proof that Rigel can
still read what earlier versions wrote.
