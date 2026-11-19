# Installing and uninstalling SG9

*[Deutsche Version](INSTALL.md)*

Downloads are under **Releases** at <https://github.com/Hoax85/sg9/releases>:

| System | File | Contents |
|---|---|---|
| Windows 10/11 | `SG9-<version>-windows.zip` | program for Intel/AMD (`amd64`) and ARM (`arm64`), install script |
| Linux | `SG9-<version>-linux.tar.gz` | program for PC (`amd64`), 64-bit ARM (`arm64`, e.g. Raspberry Pi 4/5) and 32-bit ARM (`arm`, older Raspberry Pi), install script |
| macOS | `SG9-<version>-macos.zip` | program for Apple Silicon (`arm64`) and Intel (`amd64`), install script |
| Docker / Unraid | `ghcr.io/hoax85/sg9` | image for amd64, arm64, armv7 |

There are two ways to run SG9:

- **Just start it (portable):** double-click the program or start it in a terminal. It runs as long as the window is open. Good for trying it out.
- **As a service:** SG9 starts with the computer, even without anyone signing in, and runs in the background. Good for permanent use.

After the first start, open **<http://localhost:8021>** and choose the administration password.
To switch the interface to English, use the language selector next to the light/dark switch.

---

## Windows

### Just start it
1. Extract the ZIP, e.g. to `C:\SG9`.
2. Double-click `sg9-<version>-windows-amd64.exe` (on ARM devices such as the Surface Pro X use the `arm64` file).
3. If Windows says “Windows protected your PC”: **More info → Run anyway**.
4. If the Windows firewall asks: **Allow access**.

Data is stored in the `sg9-data` folder next to the program.

### Install as a service
1. Extract the ZIP.
2. Start menu → right-click “PowerShell” → **Run as administrator**.
3. Change into the extracted folder and run the script:
   ```powershell
   cd C:\Users\YOURNAME\Downloads\SG9-<version>-windows
   powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Exe .\sg9-<version>-windows-amd64.exe
   ```

The script copies SG9 to `C:\Program Files\SG9`, creates the service “SG9 Datei-Server” (visible in `services.msc`) and allows the program through the firewall.
Data: `C:\Program Files\SG9\sg9-data`.

### Update
Download the new version and run the same install command with the new file. Settings and users are kept.

### Uninstall
```powershell
powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Uninstall          # keeps data
powershell -ExecutionPolicy Bypass -File install-windows.ps1 -Uninstall -Purge   # deletes everything
```
Portable use: stop the program and delete the folder.

---

## Linux

Works on all common distributions (Debian, Ubuntu, Fedora, Arch, Raspberry Pi OS, …).

### Just start it
```bash
tar xzf SG9-<version>-linux.tar.gz
cd SG9-<version>-linux
./sg9-<version>-linux-amd64        # Raspberry Pi: …-linux-arm64 or …-linux-arm
```

### Install as a service (systemd)
```bash
tar xzf SG9-<version>-linux.tar.gz
cd SG9-<version>-linux
sudo ./install-linux.sh
```
The script detects the processor, creates the system user `sg9`, installs to `/opt/sg9` and starts the `sg9` service.

- Data: `/opt/sg9/sg9-data`
- Status: `systemctl status sg9`
- Log: `journalctl -u sg9 -f`
- To share other folders (e.g. `/srv/data`), give the `sg9` user access:
  `sudo setfacl -R -m u:sg9:rwx /srv/data` (read only: `rx`)

### Firewall
If a firewall is active, open the ports (default ports, adjust if you changed them):
```bash
# firewalld (Fedora, …)
sudo firewall-cmd --permanent --add-port={2121,2222,8080}/tcp --add-port=50000-50100/tcp && sudo firewall-cmd --reload
# ufw (Ubuntu, …)
sudo ufw allow 2121,2222,8080/tcp && sudo ufw allow 50000:50100/tcp
```

### Update
Download and extract the new version, then run `sudo ./install-linux.sh` again. Settings are kept.

### Uninstall
```bash
sudo ./install-linux.sh --uninstall           # keeps data in /opt/sg9/sg9-data
sudo ./install-linux.sh --uninstall --purge   # deletes everything, including the sg9 user
```

---

## macOS

### Just start it
1. Extract the ZIP.
2. Open Terminal, type `cd `, drag the extracted folder into the window, press Enter.
3. Start it (Apple Silicon M1–M4: `arm64`, older Intel Macs: `amd64`):
   ```bash
   xattr -d com.apple.quarantine sg9-*-darwin-* 2>/dev/null
   ./sg9-<version>-darwin-arm64
   ```
The `xattr` command is needed because SG9 is not signed with Apple. Otherwise macOS reports that it “cannot be opened because the developer cannot be verified”.

### Install as a service (launchd)
```bash
cd ~/Downloads/SG9-<version>-macos
sudo ./install-macos.sh
```
Installs to `/usr/local/sg9` and starts SG9 at every boot, even without anyone signing in.
If macOS asks whether `sg9` may accept incoming connections: **Allow**.

- Data: `/usr/local/sg9/sg9-data`
- Log: `/usr/local/sg9/sg9-data/sg9.log`

### Update
Extract the new version and run `sudo ./install-macos.sh` again.

### Uninstall
```bash
sudo ./install-macos.sh --uninstall           # keeps data
sudo ./install-macos.sh --uninstall --purge   # deletes everything
```

---

## Docker

```bash
docker run -d --name sg9 --network host --restart unless-stopped \
  -v /path/to/sg9-data:/data -v /path/to/files:/shares \
  ghcr.io/hoax85/sg9:latest
```
Or with the included `docker-compose.yml`: `docker compose up -d`.

- `--network host` is recommended so FTP and every configured port work without extra mappings.
- On first start the administration is at `http://<server>:8021` (setting the password only works from your own network).
- The container runs as user 99:100. The folders must be writable for that user: `sudo chown -R 99:100 /path/to/sg9-data`.

**Update:** `docker pull ghcr.io/hoax85/sg9:latest`, then recreate the container (`docker compose up -d`). Data stays in the folder.

**Uninstall:** `docker rm -f sg9 && docker rmi ghcr.io/hoax85/sg9`, then delete the data folder if you like.

---

## Unraid

### Install
1. Copy the template `deploy/unraid/sg9.xml` from the source code to the USB flash drive as
   `/boot/config/plugins/dockerMan/templates-user/my-SG9.xml`
   (e.g. via the `flash` share: `\\tower\flash\config\plugins\dockerMan\templates-user\`).
2. **Docker → Add Container**, choose the template **SG9**.
3. Check the paths: `/data` → `/mnt/user/appdata/sg9`, `/shares` → the share SG9 should serve, e.g. `/mnt/user/`.
4. **Apply**. Then click the SG9 icon → **WebUI** and choose the password.

### Update
Docker → **Update** on the container (or “Check for updates”), or edit the container → **Apply**.

### Uninstall
Docker → SG9 → **Remove** (tick “also remove image”). Delete the data in `/mnt/user/appdata/sg9` by hand if you like.

---

## Before uninstalling or moving

In the administration, under **Settings → Backup and migration**, download a backup. It contains settings, users, links and keys. On the new system, use **Restore backup**. The shared files themselves are not part of the backup; they stay where they are.

## Troubleshooting

- **Administration not reachable:** Is SG9 running? On Linux `systemctl status sg9`, on Windows `services.msc`. If port 8021 is used by another program, the log says so.
- **Forgot the password:** stop the service, run `sg9 -data <data folder> -reset-admin`, start the service, choose a new password.
- **Not reachable from other devices:** check the firewall (see above). The administration is deliberately reachable only from the computer itself; change this under Settings → Services and ports.
