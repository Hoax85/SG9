#!/usr/bin/env bash
# SG9 unter macOS als Hintergrunddienst (launchd) installieren, aktualisieren oder entfernen.
#
#   sudo ./install-macos.sh                  installieren oder auf diese Version aktualisieren
#   sudo ./install-macos.sh --uninstall      Dienst und Programm entfernen, Daten bleiben
#   sudo ./install-macos.sh --uninstall --purge   zusätzlich alle Daten löschen
#
# Programm:  /usr/local/sg9/sg9
# Daten:     /usr/local/sg9/sg9-data
# Dienst:    /Library/LaunchDaemons/sg9.server.plist (startet beim Hochfahren, ohne Anmeldung)
set -euo pipefail

TARGET=/usr/local/sg9
PLIST=/Library/LaunchDaemons/sg9.server.plist
HERE="$(cd "$(dirname "$0")" && pwd)"

die() { echo "Fehler: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "bitte mit sudo ausführen: sudo $0 $*"

UNINSTALL=0 PURGE=0
for a in "$@"; do
  case "$a" in
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) die "unbekannte Option $a" ;;
  esac
done

stop() { launchctl bootout system "$PLIST" 2>/dev/null || true; }

if [ "$UNINSTALL" = 1 ]; then
  stop
  rm -f "$PLIST" "$TARGET/sg9" "$TARGET/sg9-stderr.log"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$TARGET"
    echo "SG9 vollständig entfernt, inklusive aller Daten."
  else
    echo "SG9 entfernt. Deine Daten liegen weiterhin in $TARGET/sg9-data"
    echo "Ganz löschen: sudo $0 --uninstall --purge"
  fi
  exit 0
fi

case "$(uname -m)" in
  arm64) ARCH=arm64 ;;
  x86_64) ARCH=amd64 ;;
  *) die "unbekannte Prozessorarchitektur $(uname -m)" ;;
esac
BIN=$(ls "$HERE"/sg9-*-darwin-"$ARCH" "$HERE"/sg9-darwin-"$ARCH" 2>/dev/null | head -n1 || true)
[ -n "$BIN" ] || die "Programmdatei für $ARCH nicht gefunden (sg9-…-darwin-$ARCH im selben Ordner wie dieses Skript)"
SRC="$HERE/sg9.plist"
[ -f "$SRC" ] || SRC="$HERE/../deploy/sg9.plist"
[ -f "$SRC" ] || die "sg9.plist nicht gefunden"

UPDATE=0
[ -f "$TARGET/sg9" ] && UPDATE=1
stop
mkdir -p "$TARGET/sg9-data"
install -m 755 "$BIN" "$TARGET/sg9"
# Aus dem Internet geladene Programme blockiert macOS sonst ("nicht verifizierter Entwickler")
xattr -d com.apple.quarantine "$TARGET/sg9" 2>/dev/null || true
install -m 644 "$SRC" "$PLIST"
launchctl bootstrap system "$PLIST"
sleep 1

if launchctl print system/sg9.server >/dev/null 2>&1; then
  if [ "$UPDATE" = 1 ]; then
    echo "SG9 aktualisiert auf $("$TARGET/sg9" -version) und neu gestartet."
  else
    echo "SG9 läuft als Dienst und startet ab jetzt mit dem Mac."
    echo "Verwaltung: http://localhost:8021  (beim ersten Öffnen Passwort festlegen)"
  fi
  echo "Protokoll: $TARGET/sg9-data/sg9.log"
  echo "Fragt macOS, ob sg9 eingehende Verbindungen annehmen darf: \"Erlauben\" wählen."
else
  echo "Der Dienst ist nicht gestartet. Siehe $TARGET/sg9-stderr.log"
  exit 1
fi
