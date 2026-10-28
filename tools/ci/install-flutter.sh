#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Installs the pinned Flutter SDK on a CI runner and verifies its SHA-256.
# Uses no third-party GitHub Action (supply-chain policy, CLAUDE.md rule 17).
# To update: change FLUTTER_VERSION and all hashes from
# https://storage.googleapis.com/flutter_infra_release/releases/releases_<os>.json
set -euo pipefail

FLUTTER_VERSION="3.47.8"
BASE="https://storage.googleapis.com/flutter_infra_release/releases"

case "${RUNNER_OS:-$(uname -s)}-${RUNNER_ARCH:-$(uname -m)}" in
  Linux-X64|Linux-x86_64)
    archive="stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz"
    sha256="baf7dcc5a3dbba60fe863bf493a6cf203195621f7786eaa5a1bba02cd0d87dd2" ;;
  macOS-ARM64|Darwin-arm64)
    archive="stable/macos/flutter_macos_arm64_${FLUTTER_VERSION}-stable.zip"
    sha256="6114edc2dae3636cfefb7e4456a4510399ee856e324149b34dbacb509e329d05" ;;
  macOS-X64|Darwin-x86_64)
    archive="stable/macos/flutter_macos_${FLUTTER_VERSION}-stable.zip"
    sha256="b8a3c255a51a8c0c0943a4d5bdf9b26008c34f02febf69640c8aab413afd896f" ;;
  Windows-X64)
    archive="stable/windows/flutter_windows_${FLUTTER_VERSION}-stable.zip"
    sha256="11e19ea3409808fe3b3765ea8149640c299e58cce6eda7c9f38fc1b4a193eb6e" ;;
  *)
    echo "unsupported runner: ${RUNNER_OS:-?}-${RUNNER_ARCH:-?}" >&2; exit 1 ;;
esac

dest="${RUNNER_TEMP:-/tmp}"
file="$dest/$(basename "$archive")"
curl --proto '=https' --tlsv1.2 -sSfL "$BASE/$archive" -o "$file"

if command -v sha256sum >/dev/null; then
  actual="$(sha256sum < "$file" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 < "$file" | cut -d' ' -f1)"
fi
if [ "$actual" != "$sha256" ]; then
  echo "Flutter archive checksum mismatch: expected $sha256, got $actual" >&2
  exit 1
fi

case "$file" in
  *.tar.xz) tar -xf "$file" -C "$dest" ;;
  *.zip) unzip -q "$file" -d "$dest" ;;
esac
rm -f "$file"

git config --global --add safe.directory "$dest/flutter"
export PATH="$dest/flutter/bin:$PATH"
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$dest/flutter/bin" >> "$GITHUB_PATH"
fi
flutter --disable-analytics
dart --disable-analytics
flutter --version
