#!/usr/bin/env bash
# Baut SG9 für Windows, Linux und macOS (Intel + ARM) in den Ordner dist/.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${VERSION:-2.4.2}"
# SG9_REPO (owner/name auf GitHub) aktiviert den Update-Hinweis in der Verwaltung
LDFLAGS="-s -w -X main.version=${VERSION} -X main.updateRepo=${SG9_REPO:-}"
mkdir -p dist
rm -f dist/*

targets=(
  "windows amd64 .exe"
  "windows arm64 .exe"
  "linux   amd64 ''"
  "linux   arm64 ''"
  "linux   arm   ''"
  "darwin  amd64 ''"
  "darwin  arm64 ''"
)

for t in "${targets[@]}"; do
  read -r os arch ext <<<"$t"
  ext="${ext//\'/}"
  out="dist/sg9-${VERSION}-${os}-${arch}${ext}"
  echo "→ ${out}"
  GOOS="$os" GOARCH="$arch" GOARM=7 CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags "$LDFLAGS" -o "$out" .
done

(cd dist && sha256sum sg9-* > SHA256SUMS.txt)
echo "Fertig. Dateien in dist/"
