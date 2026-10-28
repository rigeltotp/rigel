#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for check_policy.py: each check must catch what it claims to catch.

Run: python3 -m unittest discover -s tools/ci -p 'test_*.py'
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_policy  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
COPY = [
    "core/deny.toml",
    "core/Cargo.lock",
    "app/pubspec.lock",
    "app/lib",
    "app/android/app/src",
    "app/ios/Runner",
    "app/linux/runner",
    "tools/ci/dart-package-allowlist.txt",
    "app/android/app/src/main/AndroidManifest.xml",
    "app/macos/Runner/Release.entitlements",
    ".github",
    "core/crates",
]


class PolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        for rel in COPY:
            src, dst = REPO / rel, self.tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy(src, dst)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def errors(self, check: str) -> list[str]:
        return check_policy.run(self.tmp, [check]).errors

    def edit(self, rel: str, old: str, new: str) -> None:
        path = self.tmp / rel
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def test_repository_passes(self) -> None:
        self.assertEqual(check_policy.run(REPO, list(check_policy.CHECKS)).errors, [])

    def test_banned_crate_in_lockfile(self) -> None:
        with open(self.tmp / "core/Cargo.lock", "a", encoding="utf-8") as f:
            f.write('\n[[package]]\nname = "reqwest"\nversion = "0.12.0"\n')
        self.assertTrue(self.errors("no-network-rust"))

    def test_unlisted_crate_in_lockfile(self) -> None:
        with open(self.tmp / "core/Cargo.lock", "a", encoding="utf-8") as f:
            f.write('\n[[package]]\nname = "smol"\nversion = "2.0.0"\n')
        self.assertTrue(self.errors("no-network-rust"))

    def test_rust_std_net(self) -> None:
        lib = self.tmp / "core/crates/core/src/limits.rs"
        for code in (
            'fn f() { std::net::TcpStream::connect("203.0.113.1:443"); }',
            "use std::net::UdpSocket;",
            'fn f() { std::process::Command::new("curl"); }',
            "fn f() { libc::socket(2, 1, 0); }",
        ):
            lib.write_text(code + "\n")
            self.assertTrue(self.errors("no-network-rust-source"), code)
        lib.write_text("// std::net is banned\n")
        self.assertEqual(self.errors("no-network-rust-source"), [])

    def test_unlisted_dart_package(self) -> None:
        self.edit("app/pubspec.lock", "packages:\n", 'packages:\n  some_new_pkg:\n    dependency: "direct main"\n')
        self.assertTrue(self.errors("no-network-dart"))

    def test_dart_indirect_network(self) -> None:
        main = self.tmp / "app/lib/net.dart"
        for code in (
            "void f() { Image.network('https://x'); }",
            "void f() { Process.run('curl', []); }",
            "import 'dart:ffi';",
            "void f() { HttpOverrides.global = null; }",
        ):
            main.write_text(code + "\n")
            self.assertTrue(self.errors("no-network-source"), code)
        gen = self.tmp / "app/lib/frb_generated.dart"
        gen.write_text("import 'dart:ffi';\n")
        main.unlink()
        self.assertEqual(self.errors("no-network-source"), [])

    def test_native_network(self) -> None:
        kt = self.tmp / "app/android/app/src/main/kotlin/Net.kt"
        for rel, code in (
            ("app/android/app/src/main/kotlin/Net.kt", "val c = OkHttpClient()"),
            ("app/android/app/src/main/kotlin/Net.kt", "import java.net.URL"),
            ("app/ios/Runner/Net.swift", "let s = URLSession.shared"),
            ("app/linux/runner/net.cc", "#include <sys/socket.h>"),
        ):
            path = self.tmp / rel
            path.write_text(code + "\n")
            self.assertTrue(self.errors("no-network-native"), code)
            path.unlink()
        self.assertEqual(self.errors("no-network-native"), [])
        self.assertTrue(kt.parent.exists())

    def test_banned_dart_package(self) -> None:
        self.edit("app/pubspec.lock", "packages:\n", 'packages:\n  firebase_core:\n    dependency: "direct main"\n')
        self.assertTrue(self.errors("no-network-dart"))
        self.edit("app/pubspec.lock", "  firebase_core:\n", "  http:\n")
        self.assertTrue(self.errors("no-network-dart"))

    def test_dart_socket_use(self) -> None:
        (self.tmp / "app/lib/net.dart").write_text("import 'dart:io';\nvoid f() { HttpClient(); }\n")
        self.assertTrue(self.errors("no-network-source"))

    def test_dart_comment_is_ignored(self) -> None:
        (self.tmp / "app/lib/doc.dart").write_text("// We never use HttpClient here.\n")
        self.assertEqual(self.errors("no-network-source"), [])

    def test_internet_permission(self) -> None:
        manifest = "app/android/app/src/main/AndroidManifest.xml"
        self.edit(manifest, "    <application", '    <uses-permission android:name="android.permission.INTERNET"/>\n    <application')
        self.assertTrue(self.errors("android-manifest"))

    def test_backup_enabled(self) -> None:
        self.edit("app/android/app/src/main/AndroidManifest.xml", 'android:allowBackup="false"', 'android:allowBackup="true"')
        self.assertTrue(self.errors("android-manifest"))

    def test_exported_service(self) -> None:
        self.edit(
            "app/android/app/src/main/AndroidManifest.xml",
            "    </application>",
            '        <service android:name=".Leak" android:exported="true"/>\n    </application>',
        )
        self.assertTrue(self.errors("android-manifest"))

    def test_macos_network_entitlement(self) -> None:
        self.edit(
            "app/macos/Runner/Release.entitlements",
            "</dict>",
            "\t<key>com.apple.security.network.client</key>\n\t<true/>\n</dict>",
        )
        self.assertTrue(self.errors("apple-entitlements"))

    def test_unpinned_action(self) -> None:
        wf = self.tmp / ".github/workflows/x.yml"
        wf.write_text("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v5\n")
        self.assertTrue(self.errors("pinned-actions"))
        wf.write_text("jobs:\n  a:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + " # v5\n")
        self.assertEqual(self.errors("pinned-actions"), [])

    def test_flatpak_network(self) -> None:
        manifest = self.tmp / "packaging/flatpak/org.rigel.Rigel.yml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text("app-id: org.rigel.Rigel\nfinish-args:\n  - --socket=wayland\n")
        self.assertEqual(self.errors("flatpak"), [])
        manifest.write_text("app-id: org.rigel.Rigel\nfinish-args:\n  - --share=network\n")
        self.assertTrue(self.errors("flatpak"))

    # REUSE-IgnoreStart
    def test_crypto_outside_facade(self) -> None:
        lib = self.tmp / "core/crates/platform/src/leak.rs"
        lib.write_text("// SPDX-License-Identifier: GPL-3.0-or-later\nuse chacha20poly1305::XChaCha20Poly1305;\n")
        self.assertTrue(self.errors("crypto-facade"))
        facade = self.tmp / "core/crates/core/src/crypto/aead.rs"
        facade.parent.mkdir(parents=True)
        facade.write_text("use chacha20poly1305::XChaCha20Poly1305;\n")
        lib.unlink()
        self.assertEqual(self.errors("crypto-facade"), [])

    # REUSE-IgnoreEnd

    def test_missing_spdx_header(self) -> None:
        (self.tmp / "app/lib/nohdr.dart").write_text("void main() {}\n")
        self.assertTrue(self.errors("spdx-headers"))


if __name__ == "__main__":
    unittest.main()
