#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Interop check: every stored Rigel test backup must be decryptable with the
# plain `age` CLI, and must contain a JSON document with format "rigel-backup".
# Test passphrases live next to the files (docs/formats/backup/README.md).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
status=0
for f in "$root"/docs/formats/backup/v*/valid-*.rigel.age; do
  [ -e "$f" ] || { echo "no valid test backups"; exit 0; }
  pass_file="${f%.rigel.age}.passphrase"
  out="$(mktemp)"
  # age reads the passphrase from the terminal; `script` provides a pty.
  if AGE_PASSPHRASE="$(cat "$pass_file")" age -d -o "$out" "$f" 2>/dev/null \
     || printf '%s\n' "$(cat "$pass_file")" | script -qec "age -d -o '$out' '$f'" /dev/null >/dev/null 2>&1; then
    if python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['format']=='rigel-backup'" "$out"; then
      echo "ok   $(basename "$f")"
    else
      echo "FAIL $(basename "$f"): decrypted but not a rigel-backup payload"; status=1
    fi
  else
    echo "FAIL $(basename "$f"): age could not decrypt it"; status=1
  fi
  rm -f "$out"
done
exit "$status"
