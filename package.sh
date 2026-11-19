#!/usr/bin/env bash
# Packt die Dateien aus dist/ (siehe build.sh) zu Downloads für Windows, Linux und macOS in packages/.
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${VERSION:-2.4.2}"
rm -rf packages && mkdir -p packages
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pack() { # name, dateien…
  local name="$1"; shift
  mkdir -p "$tmp/$name"
  cp "$@" README.md README.en.md INSTALL.md INSTALL.en.md LICENSE CHANGELOG.md "$tmp/$name/"
}

pack "SG9-$VERSION-linux" dist/sg9-"$VERSION"-linux-* deploy/sg9.service deploy/install-linux.sh
(cd "$tmp" && tar czf "$OLDPWD/packages/SG9-$VERSION-linux.tar.gz" "SG9-$VERSION-linux")

pack "SG9-$VERSION-windows" dist/sg9-"$VERSION"-windows-* deploy/install-windows.ps1
(cd "$tmp" && zip -qr "$OLDPWD/packages/SG9-$VERSION-windows.zip" "SG9-$VERSION-windows")

pack "SG9-$VERSION-macos" dist/sg9-"$VERSION"-darwin-* deploy/sg9.plist deploy/install-macos.sh
(cd "$tmp" && zip -qr "$OLDPWD/packages/SG9-$VERSION-macos.zip" "SG9-$VERSION-macos")

(cd packages && sha256sum SG9-* > SHA256SUMS-packages.txt)
ls -la packages
