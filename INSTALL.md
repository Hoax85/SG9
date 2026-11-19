# SG9 installieren und deinstallieren

*[English version](INSTALL.en.md)*

Die Downloads findest du unter **Releases** auf <https://github.com/Hoax85/sg9/releases>:

| System | Datei | Darin |
|---|---|---|
| Windows 10/11 | `SG9-<version>-windows.zip` | Programm für Intel/AMD (`amd64`) und ARM (`arm64`), Installationsskript |
| Linux | `SG9-<version>-linux.tar.gz` | Programm für PC (`amd64`), ARM 64 Bit (`arm64`, z. B. Raspberry Pi 4/5) und ARM 32 Bit (`arm`, ältere Raspberry Pi), Installationsskript |
| macOS | `SG9-<version>-macos.zip` | Programm für Apple Silicon (`arm64`) und Intel (`amd64`), Installationsskript |
| Docker / Unraid | `ghcr.io/hoax85/sg9` | Image für amd64, arm64, armv7 |

Es gibt zwei Arten, SG9 zu betreiben:

- **Einfach starten (portabel):** Programm doppelklicken bzw. im Terminal starten. Läuft, solange das Fenster offen ist. Gut zum Ausprobieren.
- **Als Dienst:** SG9 startet mit dem Rechner, auch ohne Anmeldung, und läuft im Hintergrund. Gut für den Dauerbetrieb.

Nach dem ersten Start: **<http://localhost:8021>** öffnen und das Passwort für die Verwaltung festlegen.

---

## Windows

### Einfach starten
1. ZIP entpacken, z. B. nach `C:\SG9`.
2. `sg9-<version>-windows-amd64.exe` doppelklicken (auf ARM-Geräten wie Surface Pro X die `arm64`-Datei).
3. Meldet Windows „Der Computer wurde durch Windows geschützt“: **Weitere Informationen → Trotzdem ausführen**.
4. Fragt die Windows-Firewall nach: **Zugriff zulassen**.

Die Daten liegen im Ordner `sg9-data` neben der Programmdatei.

### Als Dienst installieren
1. ZIP entpacken.
2. Startmenü → „PowerShell“ mit rechter Maustaste → **Als Administrator ausführen**.
3. In den entpackten Ordner wechseln und das Skript starten:
   ```powershell
   cd C:\Users\DEINNAME\Downloads\SG9-<version>-windows
   powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Exe .\sg9-<version>-windows-amd64.exe
   ```

Das Skript kopiert SG9 nach `C:\Program Files\SG9`, richtet den Dienst „SG9 Datei-Server“ ein (sichtbar unter `services.msc`) und gibt das Programm in der Firewall frei.
Daten: `C:\Program Files\SG9\sg9-data`.

### Aktualisieren
Neue Version herunterladen und denselben Befehl wie bei der Installation mit der neuen Datei ausführen. Einstellungen und Benutzer bleiben erhalten.

### Deinstallieren
```powershell
powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Uninstall          # Daten bleiben
powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Uninstall -Purge   # alles löschen
```
Portabel gestartet: Programm beenden und den Ordner löschen.

---

## Linux

Funktioniert auf allen gängigen Distributionen (Debian, Ubuntu, Fedora, Arch, CachyOS, Raspberry Pi OS …).

### Einfach starten
```bash
tar xzf SG9-<version>-linux.tar.gz
cd SG9-<version>-linux
./sg9-<version>-linux-amd64        # Raspberry Pi: …-linux-arm64 bzw. …-linux-arm
```

### Als Dienst installieren (systemd)
```bash
tar xzf SG9-<version>-linux.tar.gz
cd SG9-<version>-linux
sudo ./install-linux.sh
```
Das Skript erkennt den Prozessor selbst, legt den Systembenutzer `sg9` an, installiert nach `/opt/sg9` und startet den Dienst `sg9`.

- Daten: `/opt/sg9/sg9-data`
- Status: `systemctl status sg9`
- Protokoll: `journalctl -u sg9 -f`
- Andere Ordner teilen (z. B. `/srv/daten`): dem Benutzer `sg9` Rechte geben,
  `sudo setfacl -R -m u:sg9:rwx /srv/daten` (nur lesen: `rx`)

### Firewall
Ist eine Firewall aktiv, die Ports freigeben (Standardports, anpassen falls geändert):
```bash
# firewalld (Fedora, CachyOS mit firewalld …)
sudo firewall-cmd --permanent --add-port={2121,2222,8080}/tcp --add-port=50000-50100/tcp && sudo firewall-cmd --reload
# ufw (Ubuntu …)
sudo ufw allow 2121,2222,8080/tcp && sudo ufw allow 50000:50100/tcp
```

### Aktualisieren
Neue Version herunterladen, entpacken und wieder `sudo ./install-linux.sh` ausführen. Einstellungen bleiben erhalten.

### Deinstallieren
```bash
sudo ./install-linux.sh --uninstall           # Daten bleiben in /opt/sg9/sg9-data
sudo ./install-linux.sh --uninstall --purge   # alles löschen, inkl. Benutzer sg9
```

---

## macOS

### Einfach starten
1. ZIP entpacken.
2. Terminal öffnen, `cd ` tippen, den entpackten Ordner ins Fenster ziehen, Enter.
3. Starten (Apple Silicon M1–M4: `arm64`, ältere Intel-Macs: `amd64`):
   ```bash
   xattr -d com.apple.quarantine sg9-*-darwin-* 2>/dev/null
   ./sg9-<version>-darwin-arm64
   ```
Der `xattr`-Befehl ist nötig, weil SG9 nicht bei Apple signiert ist. Sonst meldet macOS „kann nicht geöffnet werden, da der Entwickler nicht verifiziert werden kann“.

### Als Dienst installieren (launchd)
```bash
cd ~/Downloads/SG9-<version>-macos
sudo ./install-macos.sh
```
Installiert nach `/usr/local/sg9` und startet SG9 bei jedem Hochfahren, auch ohne Anmeldung.
Fragt macOS, ob `sg9` eingehende Verbindungen annehmen darf: **Erlauben**.

- Daten: `/usr/local/sg9/sg9-data`
- Protokoll: `/usr/local/sg9/sg9-data/sg9.log`

### Aktualisieren
Neue Version entpacken und wieder `sudo ./install-macos.sh` ausführen.

### Deinstallieren
```bash
sudo ./install-macos.sh --uninstall           # Daten bleiben
sudo ./install-macos.sh --uninstall --purge   # alles löschen
```

---

## Docker

```bash
docker run -d --name sg9 --network host --restart unless-stopped \
  -v /pfad/zu/sg9-data:/data -v /pfad/zu/dateien:/shares \
  ghcr.io/hoax85/sg9:latest
```
Oder mit der mitgelieferten `docker-compose.yml`: `docker compose up -d`.

- `--network host` ist empfohlen, damit FTP und alle eingestellten Ports ohne weitere Angaben funktionieren.
- Beim ersten Start ist die Verwaltung unter `http://<server>:8021` erreichbar (Passwort festlegen geht nur aus dem eigenen Netz).
- Der Container läuft als Benutzer 99:100. Die Ordner müssen für diesen Benutzer beschreibbar sein: `sudo chown -R 99:100 /pfad/zu/sg9-data`.

**Aktualisieren:** `docker pull ghcr.io/hoax85/sg9:latest`, dann den Container neu erstellen (`docker compose up -d`). Die Daten liegen im Ordner und bleiben erhalten.

**Deinstallieren:** `docker rm -f sg9 && docker rmi ghcr.io/hoax85/sg9`, danach bei Bedarf den Datenordner löschen.

---

## Unraid

### Installieren
1. Die Vorlage `deploy/unraid/sg9.xml` aus dem Quellcode auf den USB-Stick kopieren nach
   `/boot/config/plugins/dockerMan/templates-user/my-SG9.xml`
   (z. B. über die Freigabe `flash`: `\\tower\flash\config\plugins\dockerMan\templates-user\`).
2. **Docker → Container hinzufügen**, bei Vorlage **SG9** wählen.
3. Pfade prüfen: `/data` → `/mnt/user/appdata/sg9`, `/shares` → der Share, den SG9 teilen soll, z. B. `/mnt/user/`.
4. **Anwenden**. Danach auf das SG9-Symbol → **WebUI** und das Passwort festlegen.

### Aktualisieren
Docker → beim Container **Update** bzw. „Nach Updates suchen“, oder Container bearbeiten → **Anwenden**.

### Deinstallieren
Docker → SG9 → **Entfernen** (Haken bei „Image entfernen“). Die Daten in `/mnt/user/appdata/sg9` löschst du bei Bedarf von Hand.

---

## Vor einer Deinstallation oder einem Umzug

In der Verwaltung unter **Einstellungen → Sicherung und Umzug** eine Sicherung herunterladen. Sie enthält Einstellungen, Benutzer, Links und Schlüssel. Auf dem neuen System stellst du sie mit **Sicherung wiederherstellen** wieder her. Die geteilten Dateien selbst sind nicht in der Sicherung, sie bleiben, wo sie sind.

## Probleme

- **Verwaltung nicht erreichbar:** Läuft SG9? Unter Linux `systemctl status sg9`, unter Windows `services.msc`. Ist der Port 8021 von einem anderen Programm belegt, steht das im Protokoll.
- **Passwort vergessen:** Dienst stoppen, `sg9 -data <datenordner> -reset-admin` ausführen, Dienst starten, neues Passwort festlegen.
- **Von anderen Geräten nicht erreichbar:** Firewall prüfen (siehe oben). Die Verwaltung ist absichtlich nur auf dem eigenen Rechner erreichbar, umstellbar unter Einstellungen → Dienste und Ports.
