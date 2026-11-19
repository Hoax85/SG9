// SG9 – Datei-Server mit FTP/FTPS, SFTP, WebDAV, Browser-Zugang und Freigabe-Links.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	_ "time/tzdata" // Zeitzonen auch in schlanken Containern ohne Systemdateien

	"sg9/internal/admin"
	"sg9/internal/core"
	"sg9/internal/ftp"
	"sg9/internal/sftpd"
	"sg9/internal/ui"
	"sg9/internal/web"
)

var version = "2.4.2"

// updateRepo: GitHub-Projekt für den Update-Hinweis (owner/name).
// Release-Builds setzen es mit -ldflags "-X main.updateRepo=…".
var updateRepo = ""

func defaultDataDir() string {
	if d := os.Getenv("SG9_DATA"); d != "" {
		return d
	}
	exe, err := os.Executable()
	if err != nil {
		return "sg9-data"
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Join(filepath.Dir(exe), "sg9-data")
}

func main() {
	dataDir := flag.String("data", defaultDataDir(), "Ordner für Konfiguration, Logs und Schlüssel")
	setPw := flag.String("set-admin-password", "", "Admin-Passwort setzen und beenden")
	resetAdmin := flag.Bool("reset-admin", false, "Admin-Passwort löschen: beim nächsten Öffnen der Verwaltung neu festlegen")
	addUser := flag.String("add-user", "", "Benutzer anlegen: name:passwort (Gruppe Standard)")
	quiet := flag.Bool("quiet", false, "keine Log-Ausgabe auf der Konsole")
	showVersion := flag.Bool("version", false, "Version anzeigen")
	healthcheck := flag.Bool("healthcheck", false, "prüfen, ob die Verwaltung antwortet (für Docker), Rückgabewert 0 = ok")
	installSvc := flag.Bool("install-service", false, "als Windows-Dienst einrichten (startet mit Windows, auch ohne Anmeldung)")
	uninstallSvc := flag.Bool("uninstall-service", false, "Windows-Dienst entfernen")
	flag.Parse()
	admin.Version = version
	admin.UpdateRepo = updateRepo
	core.Translator = ui.Translate

	if *installSvc || *uninstallSvc {
		abs, _ := filepath.Abs(*dataDir)
		if err := manageService(*installSvc, abs); err != nil {
			fmt.Fprintln(os.Stderr, "Fehler:", err)
			os.Exit(1)
		}
		return
	}

	if *showVersion {
		fmt.Println("SG9 Server", version)
		return
	}
	abs, _ := filepath.Abs(*dataDir)
	store, created, err := core.OpenStore(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		os.Exit(1)
	}
	if *healthcheck {
		os.Exit(runHealthcheck(store.Settings()))
	}

	if *setPw != "" {
		if len(*setPw) < 8 {
			fmt.Fprintln(os.Stderr, "Das Passwort braucht mindestens 8 Zeichen.")
			os.Exit(1)
		}
		must(store.Update(func(c *core.Config) error { c.Settings.Admin.PasswordHash = core.HashPassword(*setPw); return nil }))
		fmt.Println("Admin-Passwort gesetzt.")
		return
	}
	if *resetAdmin {
		must(store.Update(func(c *core.Config) error {
			c.Settings.Admin.PasswordHash, c.Settings.Admin.TOTPSecret, c.Settings.Admin.RecoveryHashes = "", "", nil
			return nil
		}))
		_ = os.Remove(filepath.Join(abs, "sg9-admin-sessions.json"))
		fmt.Println("Admin-Passwort und Zwei-Faktor-Anmeldung gelöscht. Beim nächsten Öffnen der Verwaltung legst du ein neues Passwort fest.")
		return
	}
	if *addUser != "" {
		name, pw, ok := splitOnce(*addUser, ':')
		if !ok || pw == "" {
			fmt.Fprintln(os.Stderr, "Format: -add-user name:passwort")
			os.Exit(1)
		}
		must(store.Update(func(c *core.Config) error {
			if c.FindUser(name) != nil {
				return fmt.Errorf("Benutzer %s existiert bereits", name)
			}
			grp := ""
			if c.FindGroup("Standard") != nil {
				grp = "Standard"
			}
			c.Users = append(c.Users, core.User{Name: name, PasswordHash: core.HashPassword(pw), Enabled: true, Group: grp})
			return nil
		}))
		fmt.Println("Benutzer", name, "angelegt.")
		return
	}

	if isService() {
		runService(func(stop <-chan struct{}) { serve(store, abs, created, true, stop) })
		return
	}
	stop := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		close(stop)
	}()
	serve(store, abs, created, *quiet, stop)
}

// serve startet alle Dienste und läuft, bis stop geschlossen wird.
func serve(store *core.Store, abs string, created, quiet bool, stop <-chan struct{}) {
	st := store.Settings()
	log := core.NewLogger(st.LogFile, quiet)
	log.Info("SG9 %s startet, Datenordner: %s", version, abs)
	if created {
		log.Info("Neue Konfiguration angelegt: %s", filepath.Join(abs, "sg9.json"))
	}
	hub := core.NewHub(store, log, core.NewStats(), core.NewBanList())
	ftpSrv := ftp.New(hub)
	sftpSrv := sftpd.New(hub)
	webSrv := web.New(hub)
	store.OnSave(hub.Reload)
	store.OnSave(ftpSrv.Reload)
	store.OnSave(sftpSrv.Reload)
	store.OnSave(webSrv.Reload)
	var adm *admin.Admin
	store.OnSave(func() {
		if adm != nil {
			adm.Reload()
		}
	})

	started := 0
	for name, start := range map[string]func() error{"FTP": ftpSrv.Start, "SFTP": sftpSrv.Start, "Web": webSrv.Start} {
		if err := start(); err != nil {
			log.Error("%s: %v", name, err)
		} else {
			started++
		}
	}
	store.AutoBackup(log, 7)
	adm = admin.New(hub, admin.Services{FTP: ftpSrv, SFTP: sftpSrv, Web: webSrv})
	if err := adm.Start(); err != nil {
		log.Error("%v", err)
		os.Exit(1)
	}
	adm.StartUpdateCheck()
	if store.Settings().Admin.PasswordHash == "" && !quiet {
		_, port, _ := core.SplitAddr(store.Settings().Admin.ListenAddr)
		fmt.Printf("\n  SG9 einrichten: http://localhost:%d im Browser öffnen und ein Passwort festlegen.\n\n", port)
	}
	if started == 0 {
		log.Warn("Kein Dienst konnte starten. Ports im Web-Admin unter Einstellungen prüfen.")
	}

	<-stop
	log.Info("SG9 wird beendet")
	ftpSrv.Stop()
	sftpSrv.Stop()
	webSrv.Stop()
	hub.SaveCounters()
}

// runHealthcheck fragt die Verwaltung lokal ab (Docker HEALTHCHECK braucht kein curl).
func runHealthcheck(st core.Settings) int {
	_, port, err := core.SplitAddr(st.Admin.ListenAddr)
	if err != nil {
		return 1
	}
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if st.Admin.UseTLS {
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // nur localhost
	}
	resp, err := client.Get(fmt.Sprintf("%s://127.0.0.1:%d/api/state", scheme, port))
	if err != nil {
		fmt.Fprintln(os.Stderr, "nicht erreichbar:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return 1
	}
	return 0
}

func splitOnce(s string, sep byte) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		os.Exit(1)
	}
}
