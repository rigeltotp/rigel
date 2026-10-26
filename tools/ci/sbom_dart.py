#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Writes a CycloneDX 1.5 JSON SBOM for the Dart/Flutter dependencies, from
app/pubspec.lock (no network, standard library only).

Usage: sbom_dart.py [pubspec.lock] [output.json]
"""

import json
import re
import sys
from pathlib import Path


def parse_lock(text: str) -> list[dict[str, str]]:
    packages, current = [], None
    in_packages = False
    for line in text.splitlines():
        if line.startswith("packages:"):
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            in_packages = False
        if not in_packages:
            continue
        m = re.match(r"^  ([A-Za-z0-9_]+):\s*$", line)
        if m:
            current = {"name": m.group(1)}
            packages.append(current)
            continue
        m = re.match(r"^    (dependency|source|version): \"?([^\"]+)\"?\s*$", line)
        if m and current is not None:
            current[m.group(1)] = m.group(2)
        m = re.match(r"^      sha256: \"?([0-9a-f]{64})\"?\s*$", line)
        if m and current is not None:
            current["sha256"] = m.group(1)
    return packages


def to_bom(packages: list[dict[str, str]]) -> dict:
    components = []
    for p in packages:
        if "version" not in p:
            continue
        c = {
            "type": "library",
            "name": p["name"],
            "version": p["version"],
            "purl": f"pkg:pub/{p['name']}@{p['version']}",
        }
        if p.get("sha256"):
            c["hashes"] = [{"alg": "SHA-256", "content": p["sha256"]}]
        if p.get("source") == "sdk":
            c["scope"] = "required"
        components.append(c)
    components.sort(key=lambda c: c["name"])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "rigel-app"}},
        "components": components,
    }


def main(argv: list[str]) -> int:
    lock = Path(argv[0] if argv else "app/pubspec.lock")
    out = Path(argv[1] if len(argv) > 1 else "sbom-dart.cdx.json")
    bom = to_bom(parse_lock(lock.read_text(encoding="utf-8")))
    out.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} with {len(bom['components'])} components")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
