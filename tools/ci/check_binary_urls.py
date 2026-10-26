#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fails if a built binary contains http(s):// or ws(s):// strings that are not
on the allowlist (tools/ci/binary-url-allowlist.txt).

Rigel makes no network connections, so shipped binaries should contain no
URLs except license texts, documentation links of the toolchain and similar.
Every allowlist line is a prefix; add entries only with a justification.

Usage: check_binary_urls.py FILE_OR_DIR [...]
"""

import re
import sys
from pathlib import Path

URL = re.compile(rb"(?:https?|wss?)://[\x21-\x7e]{3,200}")
ALLOWLIST = Path(__file__).with_name("binary-url-allowlist.txt")
SUFFIXES = {"", ".so", ".dll", ".exe", ".dylib", ".a", ".apk", ".app"}


def allowed_prefixes() -> list[str]:
    lines = ALLOWLIST.read_text(encoding="utf-8").splitlines()
    return [l.split("#")[0].strip() for l in lines if l.split("#")[0].strip()]


def files(paths: list[str]):
    for p in map(Path, paths):
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and (f.suffix in SUFFIXES or f.name.endswith(".so")):
                    yield f
        elif p.is_file():
            yield p


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    prefixes = allowed_prefixes()
    bad: dict[str, set[str]] = {}
    scanned = 0
    for f in files(argv):
        scanned += 1
        for m in URL.finditer(f.read_bytes()):
            url = m.group(0).decode("ascii", "replace")
            if not any(url.startswith(p) for p in prefixes):
                bad.setdefault(str(f), set()).add(url)
    for f, urls in bad.items():
        for u in sorted(urls)[:20]:
            print(f"FAIL {f}: {u}")
    if bad:
        print("Unexpected URL strings in binaries. Remove the dependency or justify an allowlist entry.")
        return 1
    print(f"OK   {scanned} file(s) scanned, no unexpected URLs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
