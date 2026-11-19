# SG9 Server

*[Deutsche Version](README.md)*

A file server in the spirit of the classic G6 FTP Server: users, groups, virtual folders,
speed limits, ratios and a web-based administration. Plus the modern ways to reach your files:
SFTP, WebDAV as a network drive, a file manager in the browser and share links.

One single file per operating system, no installation, no dependencies.
Runs on **Windows**, **Linux** (including Raspberry Pi) and **macOS** (Intel and Apple Silicon).
The interface speaks English, German, French and Italian.

## Quick start

Installing as a service, updating and uninstalling on Windows, Linux, macOS, Docker and Unraid:
**[INSTALL.en.md](INSTALL.en.md)**

```bash
./sg9          # Linux / macOS
sg9.exe        # Windows
```

On first start SG9 creates the folder `sg9-data/` next to the program.

1. Open the administration: <http://localhost:8021>
2. Choose your own password the first time
3. Create a user under **Users**
4. Connect however you like:

| Method | Address | Program |
|---|---|---|
| FTP / FTPS | `server:2121` | FileZilla, WinSCP, Cyberduck |
| SFTP | `server:2222` | FileZilla, WinSCP, `sftp`, Cyberduck |
| Browser | `http://server:8080` | any browser |
| Network drive (WebDAV) | `http://server:8080/dav` | Windows Explorer, macOS Finder, Linux file managers |
| Share link | `http://server:8080/s/…` | any browser, no account needed |

Every service has its own port, adjustable under **Settings → Services and ports**, applied
immediately without a restart.

## Features

**Like G6:** users and groups with inheritance (`%u` = username), virtual folders including
network drives, per-folder permissions, speed limits per user, group and server, ratio with
starting credit, quotas, connection limits, hidden files and blocked upload types, welcome
messages and `.message` files, IP filters and automatic bans, account expiry, anonymous access,
online/offline switch, live sessions and live log.

**New:**
- **SFTP** with password or SSH key (no shell access, by design)
- **WebDAV** to mount SG9 as a drive in Explorer or Finder
- **Files in the browser** with drag & drop upload, folders as ZIP, preview of images, PDF, video and audio
- **Share links** for any file or folder on the server or in a user account, with optional password, expiry and download limit, plus a **QR code**
- **Drop boxes** where others upload files to you, with their name and a message, sorted into a folder per sender
- **Let's Encrypt** built in: real HTTPS for links from outside, no reverse proxy needed
- **Country filter** for links or all services (free DB-IP Lite or GeoLite2 database)
- **Events**: run a script or call a webhook on upload, download, sign-in, failed attempt, …
- **Notifications** via ntfy (push to your phone), email or Home Assistant
- **Two-factor sign-in** for the administration, with recovery codes
- **Backup and restore** of the whole configuration, daily automatic backups
- **Audit log** of every change in the administration
- **Update hint** when a new release is on GitHub (can be turned off, downloads nothing)
- Light, dark or system theme; usable on a phone

## Docker and Unraid

```bash
docker pull ghcr.io/<github-name>/sg9:latest   # amd64, arm64, armv7
docker compose up -d                           # with the included docker-compose.yml
```

Host networking is recommended so FTP passive mode and every port you configure just work.
`/data` holds settings and keys, `/shares` the folders SG9 may share. The image is about 14 MB,
runs as user 99:100 and has a built-in health check. An Unraid template is in `deploy/unraid/sg9.xml`.

## Running as a service

- **Windows:** `install-windows.ps1` (as administrator) installs SG9 as a real Windows service and
  opens the firewall for it. Or directly: `sg9.exe -install-service`, remove with `-uninstall-service`.
- **Linux:** `sudo ./install-linux.sh` (systemd), remove with `--uninstall`
- **macOS:** `sudo ./install-macos.sh` (launchd), remove with `--uninstall`

Full instructions: **[INSTALL.en.md](INSTALL.en.md)**

Forgot the admin password? Run `sg9 -reset-admin` and choose a new one on the next visit.

## Building

Go 1.24 or newer, all dependencies are vendored:

```bash
./build.sh        # all platforms → dist/
./package.sh      # downloads → packages/
go test ./...     # tests, including an end-to-end test of all services
```

Pushing a tag like `v2.4.0` runs `.github/workflows/release.yml`: tests, builds, creates a GitHub
release with the downloads and pushes the Docker image to `ghcr.io`.

## Translating

All texts live in `internal/ui/i18n/sg9.tsv`: one line per text, columns German, English,
French, Italian. `{}` marks a variable part. To add a language, append a column and add its code
to `Languages` in `internal/ui/i18n.go`.

## License

© 2026 Peter and the SG9 contributors. SG9 is licensed under the **GNU Affero General Public License v3.0** (see `LICENSE`).
