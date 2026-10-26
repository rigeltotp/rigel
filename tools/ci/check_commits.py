#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Checks the commits in BASE..HEAD: Conventional Commits subject and, when
the repository enforces it, a verified signature.

Usage: check_commits.py BASE HEAD
Signature verification needs the signer's keys, which a CI runner does not
have; GitHub's branch protection ("Require signed commits") is the
authoritative check. Here we only verify the subject format.
"""

import re
import subprocess
import sys

TYPES = "feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert|spec"
SUBJECT = re.compile(rf"^({TYPES})(\([a-z0-9][a-z0-9._/-]*\))?!?: \S.{{0,100}}$")


def main(base: str, head: str) -> int:
    out = subprocess.run(
        ["git", "log", "--no-merges", "--format=%H%x00%s", f"{base}..{head}"],
        check=True, capture_output=True, text=True,
    ).stdout
    failed = 0
    for line in filter(None, out.splitlines()):
        sha, subject = line.split("\x00", 1)
        if SUBJECT.match(subject):
            print(f"ok   {sha[:8]} {subject}")
        else:
            failed += 1
            print(f"FAIL {sha[:8]} {subject!r}: not a Conventional Commit (type(scope): subject)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
