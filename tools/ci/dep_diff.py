#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Lists dependencies added, removed or changed between two git revisions, for
Cargo.lock and pubspec.lock. Output is Markdown for the job summary; it never
fails the build, it only makes new dependencies visible to the reviewer
(CLAUDE.md rule 16 asks for a justification per new dependency).

Usage: dep_diff.py BASE HEAD
"""

import subprocess
import sys
import tomllib

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from sbom_dart import parse_lock  # noqa: E402


def show(rev: str, path: str) -> str:
    r = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def cargo(text: str) -> dict[str, str]:
    if not text:
        return {}
    pkgs = tomllib.loads(text).get("package", [])
    return {f"{p['name']}": p["version"] for p in pkgs if p.get("source")}


def dart(text: str) -> dict[str, str]:
    return {p["name"]: p.get("version", "?") for p in parse_lock(text)} if text else {}


def diff(old: dict[str, str], new: dict[str, str]):
    added = sorted(k for k in new if k not in old)
    removed = sorted(k for k in old if k not in new)
    changed = sorted(k for k in new if k in old and old[k] != new[k])
    return added, removed, changed


def main(base: str, head: str) -> int:
    any_change = False
    for label, path, parse in (("Rust", "core/Cargo.lock", cargo), ("Dart", "app/pubspec.lock", dart)):
        old, new = parse(show(base, path)), parse(show(head, path))
        added, removed, changed = diff(old, new)
        if not (added or removed or changed):
            continue
        any_change = True
        print(f"### {label} dependencies ({path})")
        for k in added:
            print(f"- **NEW** `{k}` {new[k]}: add a one-line justification to the PR")
        for k in changed:
            print(f"- changed `{k}` {old[k]} -> {new[k]}")
        for k in removed:
            print(f"- removed `{k}` {old[k]}")
        print()
    if not any_change:
        print("No dependency changes.")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
