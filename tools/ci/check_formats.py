#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validates the stored format test files in docs/formats against the JSON
schemas in docs/schemas: valid-* must validate, invalid-* must be rejected.

Requires the `jsonschema` package (pinned in CI).
Usage: check_formats.py [--root PATH]
"""

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

# directory (relative to docs/formats) + file-name prefix -> schema file
RULES = [
    ("backup", "", "backup-v1.schema.json"),
    ("vault/v1/records", "valid-meta", "vault-record-meta-v1.schema.json"),
    ("vault/v1/records", "invalid-meta", "vault-record-meta-v1.schema.json"),
    ("vault/v1/records", "valid-secret", "vault-record-secret-v1.schema.json"),
    ("vault/v1/records", "invalid-secret", "vault-record-secret-v1.schema.json"),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    root = parser.parse_args().root
    formats, schemas = root / "docs/formats", root / "docs/schemas"
    failures, checked = 0, 0

    for schema_file in sorted(schemas.glob("*.json")):
        Draft202012Validator.check_schema(json.loads(schema_file.read_text(encoding="utf-8")))

    for sub, prefix, schema_name in RULES:
        validator = Draft202012Validator(json.loads((schemas / schema_name).read_text(encoding="utf-8")))
        for path in sorted((formats / sub).rglob("*.json")):
            name = path.name
            if prefix and not (name.startswith(prefix)):
                continue
            expect_valid = name.startswith("valid-")
            if not expect_valid and not name.startswith("invalid-"):
                continue
            checked += 1
            errors = list(validator.iter_errors(json.loads(path.read_text(encoding="utf-8"))))
            if expect_valid and errors:
                failures += 1
                print(f"FAIL {path.relative_to(root)}: should be valid, but: {errors[0].message[:160]}")
            elif not expect_valid and not errors:
                failures += 1
                print(f"FAIL {path.relative_to(root)}: should be rejected, but validates")

    if checked == 0:
        print("FAIL no format test files found")
        return 1
    print(f"{'FAIL' if failures else 'OK  '} {checked} format test file(s) checked, {failures} problem(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
