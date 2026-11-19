# Änderungen

## 2.4.2

- Behoben: Die Durchsatz-Grafik auf der Übersicht blieb seit 2.4.0 leer (Namenskonflikt mit der Übersetzungsfunktion). Ein Test verhindert das künftig.
- Englisch/Französisch/Italienisch: „Herunterladen“ im Dateimanager, Richtung der Übertragung in der Sitzungsliste und die Spalte „Konto“ werden jetzt richtig übersetzt.

## 2.4.1

- Installationsskripte für Linux (`install-linux.sh`) und macOS (`install-macos.sh`): installieren, aktualisieren, entfernen (`--uninstall`, `--purge`).
- Windows-Skript: `-Purge` löscht auch alle Daten.
- Installationsanleitung für alle Systeme auf Deutsch (`INSTALL.md`) und Englisch (`INSTALL.en.md`), in jedem Download enthalten.

## 2.4.0

- **Sprachen:** Deutsch, English, Français, Italiano. Umschalter neben Hell/Dunkel, Freigabe-Seiten folgen der Sprache des Besuchers. Auch Fehlermeldungen, Protokoll und Benachrichtigungen sind übersetzt.
- **Links:** QR-Code zu jedem Link, Galerie mit Blättern für Bilder, Vorschau für PDF, Video und Musik.
- **Briefkasten:** Absender kann Name und Nachricht angeben, Dateien landen im Unterordner pro Absender, die Benachrichtigung nennt den Namen.
- **Länderfilter:** Links oder alle Dienste nur aus gewählten Ländern (DB-IP Lite oder GeoLite2, MMDB-Format).
- **Benachrichtigungen** per ntfy, E-Mail und Home Assistant, in der gewählten Sprache.
- **Zwei-Faktor-Anmeldung** für die Verwaltung mit Wiederherstellungscodes.
- **Sicherung und Wiederherstellung** als ZIP, tägliche automatische Sicherung (7 Stück).
- **Prüfprotokoll** aller Änderungen in der Verwaltung.
- **Update-Hinweis** über GitHub-Releases (abschaltbar).
- **Windows-Dienst:** `sg9.exe -install-service` bzw. `install-windows.ps1`.
- **Docker/Unraid:** schlankes Image ab `scratch`, Gesundheitscheck, Unraid-Vorlage, Images für amd64, arm64, armv7.
- Automatische Tests inklusive Ende-zu-Ende-Test für FTP, SFTP, WebDAV, Verwaltung und Links.
- Vorschau-Sicherheit: HTML- und SVG-Dateien werden nie im Browser angezeigt, sondern nur heruntergeladen.

## 2.3.1

- Freigabe-Links für beliebige Ordner und Dateien auf dem Server.
- Let's Encrypt eingebaut, Links von ausserhalb erreichbar.
- Übersicht zeigt nur eingeschaltete Dienste.

## 2.3.0

- Einrichtung im Browser statt Passwort auf der Konsole, Anmeldung bleibt 30 Tage, auf dem eigenen Rechner ohne Passwort.
- Eigener Port für jeden Dienst, live umstellbar.

## 2.0.0

- SFTP, WebDAV, Dateimanager im Browser, Freigabe-Links, Hell/Dunkel.

## 1.0.0

- FTP/FTPS-Server im Stil von G6: Benutzer, Gruppen, virtuelle Ordner, Rechte, Limits, Ratio, Verwaltung im Browser.
