#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Repository policy checks for Rigel.

Enforces the promises in CLAUDE.md that tools like cargo-deny cannot see:

  no-network-rust     Cargo.lock contains no crate from the deny list in
                      core/deny.toml (second line of defence after cargo-deny).
  no-network-dart     pubspec.lock contains no networking, analytics, crash
                      reporting or Google-services packages.
  no-network-source   Dart sources use no sockets, HTTP or WebSockets.
  android-manifest    The main Android manifest requests no network
                      permission, disables auto-backup and exports nothing but
                      the launcher activity.
  apple-entitlements  macOS release entitlements contain no network
                      entitlement and keep the app sandbox.
  flatpak             Flatpak manifests grant no network access.
  crypto-facade       Only core/crates/core/src/crypto uses cryptographic or
                      randomness crates (CLAUDE.md rule 5).
  pinned-actions      Every GitHub Actions `uses:` is a local action or pinned
                      to a full commit SHA.
  spdx-headers        Every source file starts with an SPDX license header.

Usage: python3 tools/ci/check_policy.py [--root PATH] [check ...]
Exit status 0 when all selected checks pass, 1 otherwise.
Standard library only, so it runs on every CI runner without installs.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

NETWORK_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.NEARBY_WIFI_DEVICES",
}

# Dart packages that do networking, analytics, crash reporting, ads, remote
# web content or pull in Google Play services / ML Kit.
BANNED_DART_PACKAGES = {
    "http", "http2", "dio", "chopper", "retrofit", "graphql", "graphql_flutter",
    "grpc", "web_socket_channel", "socket_io_client", "mqtt_client",
    "connectivity_plus", "network_info_plus", "cached_network_image",
    "webview_flutter", "flutter_inappwebview", "url_launcher",
    "sentry", "sentry_flutter", "google_mobile_ads", "in_app_review",
    "mobile_scanner", "google_sign_in", "app_tracking_transparency",
    "upgrader", "package_info_plus_web",
}
BANNED_DART_PREFIXES = (
    "firebase_", "cloud_", "google_mlkit_", "google_ml_kit", "sentry_",
    "amplitude", "mixpanel", "posthog", "datadog", "bugsnag", "appcenter",
    "onesignal", "segment_", "matomo", "countly", "instabug", "crashlytics",
)

# Dart identifiers that open network connections.
DART_NETWORK_PATTERNS = [
    re.compile(r"\b(HttpClient|HttpServer|HttpRequest)\b"),
    re.compile(r"\b(Raw)?(Secure)?(Server)?Socket\b"),
    re.compile(r"\bRawDatagramSocket\b"),
    re.compile(r"\bWebSocket\b"),
    re.compile(r"\bInternetAddress\b"),
    re.compile(r"""import\s+['"]dart:html['"]"""),
    re.compile(r"""import\s+['"]package:web/"""),
]

APPLE_NETWORK_ENTITLEMENTS = (
    "com.apple.security.network.client",
    "com.apple.security.network.server",
)

# Crates that only the crypto facade may use directly.
CRYPTO_CRATES = (
    "chacha20poly1305", "chacha20", "poly1305", "aead", "argon2", "scrypt",
    "hkdf", "hmac", "sha1", "sha2", "sha3", "blake2", "blake3", "ed25519_dalek",
    "x25519_dalek", "curve25519_dalek", "ml_kem", "x_wing", "hpke", "age",
    "aes", "aes_gcm", "p256", "ring", "aws_lc_rs", "rand", "rand_core",
    "getrandom",
)
CRYPTO_USE = re.compile(r"\b(" + "|".join(CRYPTO_CRATES) + r")::")
CRYPTO_FACADE = ("core/crates/core/src/crypto.rs", "core/crates/core/src/crypto/")

SHA_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")

SPDX_SUFFIXES = {".rs", ".dart", ".py", ".sh", ".kt", ".kts", ".swift"}
SPDX_DIRS = ["core/crates", "core/fuzz", "app/lib", "app/test", "tools", "native"]
SPDX_SKIP = re.compile(r"(^|/)(app_localizations[^/]*\.dart|.*\.g\.dart|.*\.freezed\.dart|frb_generated[^/]*)$")
# REUSE-IgnoreStart
SPDX_MARKER = "SPDX-License-Identifier: GPL-3.0-or-later"
# REUSE-IgnoreEnd


class Result:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def fail(self, check: str, message: str) -> None:
        self.errors.append(f"[{check}] {message}")


def banned_rust_crates(root: Path) -> set[str]:
    deny = tomllib.loads((root / "core/deny.toml").read_text(encoding="utf-8"))
    names = set()
    for item in deny.get("bans", {}).get("deny", []):
        names.add(item["crate"] if isinstance(item, dict) else str(item))
    return names


def check_no_network_rust(root: Path, res: Result) -> None:
    lock = root / "core/Cargo.lock"
    if not lock.exists():
        res.fail("no-network-rust", "core/Cargo.lock is missing; commit it")
        return
    banned = banned_rust_crates(root)
    if not banned:
        res.fail("no-network-rust", "core/deny.toml has an empty [bans] deny list")
    packages = tomllib.loads(lock.read_text(encoding="utf-8")).get("package", [])
    for pkg in packages:
        if pkg["name"] in banned:
            res.fail("no-network-rust", f"banned crate in Cargo.lock: {pkg['name']} {pkg.get('version', '')}")


def dart_package_banned(name: str) -> bool:
    return name in BANNED_DART_PACKAGES or name.startswith(BANNED_DART_PREFIXES)


def check_no_network_dart(root: Path, res: Result) -> None:
    lock = root / "app/pubspec.lock"
    if not lock.exists():
        res.fail("no-network-dart", "app/pubspec.lock is missing; commit it")
        return
    in_packages = False
    for line in lock.read_text(encoding="utf-8").splitlines():
        if line.startswith("packages:"):
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            in_packages = False
        m = re.match(r"^  ([A-Za-z0-9_]+):\s*$", line)
        if in_packages and m and dart_package_banned(m.group(1)):
            res.fail("no-network-dart", f"banned Dart package in pubspec.lock: {m.group(1)}")


def strip_dart_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def check_no_network_source(root: Path, res: Result) -> None:
    for base in ("app/lib", "app/test"):
        for path in sorted((root / base).rglob("*.dart")):
            code = strip_dart_comments(path.read_text(encoding="utf-8"))
            for pattern in DART_NETWORK_PATTERNS:
                m = pattern.search(code)
                if m:
                    rel = path.relative_to(root)
                    res.fail("no-network-source", f"{rel}: network API '{m.group(0)}' is not allowed")


def check_android_manifest(root: Path, res: Result) -> None:
    path = root / "app/android/app/src/main/AndroidManifest.xml"
    if not path.exists():
        res.fail("android-manifest", f"{path.relative_to(root)} is missing")
        return
    tree = ET.parse(path)
    manifest = tree.getroot()
    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for perm in manifest.iter(tag):
            name = perm.get(f"{ANDROID_NS}name", "")
            if name in NETWORK_PERMISSIONS:
                res.fail("android-manifest", f"network permission requested: {name}")
    app = manifest.find("application")
    if app is None:
        res.fail("android-manifest", "no <application> element")
        return
    if app.get(f"{ANDROID_NS}allowBackup") != "false":
        res.fail("android-manifest", 'application must set android:allowBackup="false"')
    if not app.get(f"{ANDROID_NS}dataExtractionRules"):
        res.fail("android-manifest", "application must set android:dataExtractionRules")
    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        for comp in app.iter(kind):
            name = comp.get(f"{ANDROID_NS}name", "?")
            if comp.get(f"{ANDROID_NS}exported") != "true":
                continue
            is_launcher = any(
                cat.get(f"{ANDROID_NS}name") == "android.intent.category.LAUNCHER"
                for f in comp.iter("intent-filter")
                for cat in f.iter("category")
            )
            if not (kind == "activity" and is_launcher):
                res.fail("android-manifest", f"exported {kind} {name}: only the launcher activity may be exported")


def check_apple_entitlements(root: Path, res: Result) -> None:
    path = root / "app/macos/Runner/Release.entitlements"
    if not path.exists():
        res.fail("apple-entitlements", f"{path.relative_to(root)} is missing")
        return
    text = path.read_text(encoding="utf-8")
    for ent in APPLE_NETWORK_ENTITLEMENTS:
        if ent in text:
            res.fail("apple-entitlements", f"{path.relative_to(root)}: network entitlement {ent}")
    if not re.search(r"<key>com\.apple\.security\.app-sandbox</key>\s*<true/>", text):
        res.fail("apple-entitlements", f"{path.relative_to(root)}: app sandbox must stay enabled")
    for ios_ent in sorted((root / "app/ios").rglob("*.entitlements")):
        text = ios_ent.read_text(encoding="utf-8")
        for ent in APPLE_NETWORK_ENTITLEMENTS:
            if ent in text:
                res.fail("apple-entitlements", f"{ios_ent.relative_to(root)}: network entitlement {ent}")


def check_flatpak(root: Path, res: Result) -> None:
    candidates = [p for p in root.rglob("*") if p.is_file() and ".flatpak" not in p.parts
                  and re.search(r"\.(ya?ml|json)$", p.name)
                  and ("flatpak" in p.as_posix().lower() or p.name.count(".") >= 3)]
    for path in candidates:
        rel = path.relative_to(root).as_posix()
        if "/build/" in rel or "/target/" in rel or rel.startswith(".github/"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "finish-args" not in text:
            continue
        if re.search(r"--share=network", text):
            res.fail("flatpak", f"{rel}: grants network access (--share=network)")


def strip_rust_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def check_crypto_facade(root: Path, res: Result) -> None:
    base = root / "core/crates"
    if not base.exists():
        return
    for path in sorted(base.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if "/target/" in rel or rel.startswith(CRYPTO_FACADE):
            continue
        code = strip_rust_comments(path.read_text(encoding="utf-8"))
        for m in CRYPTO_USE.finditer(code):
            res.fail("crypto-facade", f"{rel}: '{m.group(0)}' outside the crypto facade; go through rigel_core::crypto")


def check_pinned_actions(root: Path, res: Result) -> None:
    wf_dir = root / ".github"
    for path in sorted(list(wf_dir.rglob("*.yml")) + list(wf_dir.rglob("*.yaml"))):
        for no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = re.match(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)", line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            if not SHA_PIN.match(ref):
                res.fail("pinned-actions", f"{path.relative_to(root)}:{no}: '{ref}' is not pinned to a commit SHA")


def check_spdx_headers(root: Path, res: Result) -> None:
    for base in SPDX_DIRS:
        base_path = root / base
        if not base_path.exists():
            continue
        for path in sorted(base_path.rglob("*")):
            if not path.is_file() or path.suffix not in SPDX_SUFFIXES:
                continue
            rel = path.relative_to(root).as_posix()
            if "/target/" in rel or "/build/" in rel or SPDX_SKIP.search(rel):
                continue
            head = path.read_text(encoding="utf-8", errors="replace").splitlines()[:5]
            if not any(SPDX_MARKER in line for line in head):
                res.fail("spdx-headers", f"{rel}: missing '{SPDX_MARKER}' in the first lines")


CHECKS = {
    "no-network-rust": check_no_network_rust,
    "no-network-dart": check_no_network_dart,
    "no-network-source": check_no_network_source,
    "android-manifest": check_android_manifest,
    "apple-entitlements": check_apple_entitlements,
    "flatpak": check_flatpak,
    "crypto-facade": check_crypto_facade,
    "pinned-actions": check_pinned_actions,
    "spdx-headers": check_spdx_headers,
}


def run(root: Path, selected: list[str]) -> Result:
    res = Result()
    for name in selected:
        CHECKS[name](root, res)
    return res


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("checks", nargs="*", metavar="check", help=f"one of: {', '.join(CHECKS)}")
    args = parser.parse_args(argv)
    unknown = [c for c in args.checks if c not in CHECKS]
    if unknown:
        parser.error(f"unknown check(s): {', '.join(unknown)}")
    selected = args.checks or list(CHECKS)
    res = run(args.root, selected)
    for err in res.errors:
        print(f"FAIL {err}")
    if res.errors:
        print(f"{len(res.errors)} policy violation(s).")
        return 1
    print(f"OK   {', '.join(selected)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
