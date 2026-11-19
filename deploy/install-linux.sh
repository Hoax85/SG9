#!/usr/bin/env bash
# SG9 unter Linux als Dienst (systemd) installieren, aktualisieren oder entfernen.
#
#   sudo ./install-linux.sh                  installieren oder auf diese Version aktualisieren
#   sudo ./install-linux.sh --uninstall      Dienst und Programm entfernen, Daten bleiben
#   sudo ./install-linux.sh --uninstall --purge   zusätzlich alle Daten und den Benutzer sg9 löschen
#
# Programm:  /opt/sg9/sg9
# Daten:     /opt/sg9/sg9-data   (Einstellungen, Benutzer, Schlüssel, Protokoll)
# Dienst:    sg9.service, läuft als eigener Benutzer "sg9" ohne Anmelderechte
set -euo pipefail

TARGET=/opt/sg9
UNIT=/etc/systemd/system/sg9.service
HERE="$(cd "$(dirname "$0")" && pwd)"

die() { echo "Fehler: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "bitte mit sudo ausführen: sudo $0 $*"
command -v systemctl >/dev/null || die "kein systemd gefunden. SG9 läuft trotzdem: einfach das Programm starten."

UNINSTALL=0 PURGE=0
for a in "$@"; do
  case "$a" in
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) die "unbekannte Option $a" ;;
  esac
done

if [ "$UNINSTALL" = 1 ]; then
  systemctl disable --now sg9 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload
  rm -f "$TARGET/sg9"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$TARGET"
    id sg9 >/dev/null 2>&1 && userdel sg9 || true
    echo "SG9 vollständig entfernt, inklusive aller Daten."
  else
    echo "SG9 entfernt. Deine Daten liegen weiterhin in $TARGET/sg9-data"
    echo "Ganz löschen: sudo $0 --uninstall --purge"
  fi
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv6l|arm*) ARCH=arm ;;
  *) die "unbekannte Prozessorarchitektur $(uname -m)" ;;
esac
BIN=$(ls "$HERE"/sg9-*-linux-"$ARCH" "$HERE"/sg9-linux-"$ARCH" 2>/dev/null | head -n1 || true)
[ -n "$BIN" ] || die "Programmdatei für $ARCH nicht gefunden (sg9-…-linux-$ARCH im selben Ordner wie dieses Skript)"
SERVICE="$HERE/sg9.service"
[ -f "$SERVICE" ] || SERVICE="$HERE/../deploy/sg9.service"
[ -f "$SERVICE" ] || die "sg9.service nicht gefunden"

if ! id sg9 >/dev/null 2>&1; then
  useradd --system --home-dir "$TARGET" --shell "$(command -v nologin || echo /bin/false)" sg9
fi
UPDATE=0
[ -f "$TARGET/sg9" ] && UPDATE=1
systemctl stop sg9 2>/dev/null || true
install -d -o sg9 -g sg9 "$TARGET" "$TARGET/sg9-data"
install -m 755 "$BIN" "$TARGET/sg9"
install -m 644 "$SERVICE" "$UNIT"
systemctl daemon-reload
systemctl enable --now sg9
sleep 1

if systemctl is-active --quiet sg9; then
  if [ "$UPDATE" = 1 ]; then
    echo "SG9 aktualisiert auf $("$TARGET/sg9" -version) und neu gestartet."
  else
    echo "SG9 läuft als Dienst und startet ab jetzt mit dem Rechner."
    echo "Verwaltung: http://localhost:8021  (beim ersten Öffnen Passwort festlegen)"
  fi
  echo "Status: systemctl status sg9   Protokoll: journalctl -u sg9 -f"
  echo
  echo "Ordner teilen, die nicht in $TARGET liegen: dem Benutzer sg9 Leserechte geben,"
  echo "z. B. sudo setfacl -R -m u:sg9:rx /pfad/zum/ordner"
  if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    echo "Firewall (firewalld) aktiv: Ports freigeben mit z. B."
    echo "  sudo firewall-cmd --permanent --add-port={2121,2222,8080}/tcp --add-port=50000-50100/tcp && sudo firewall-cmd --reload"
  elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q active; then
    echo "Firewall (ufw) aktiv: Ports freigeben mit z. B."
    echo "  sudo ufw allow 2121,2222,8080/tcp && sudo ufw allow 50000:50100/tcp"
  fi
else
  echo "Der Dienst ist nicht gestartet. Ursache anzeigen: journalctl -u sg9 -n 30"
  exit 1
fi
