// Package core enthält Konfiguration, Benutzer, Gruppen und gemeinsame Dienste von SG9.
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Protokolle, die SG9 anbietet.
const (
	ProtoFTP    = "ftp"
	ProtoSFTP   = "sftp"
	ProtoWebDAV = "webdav"
	ProtoWeb    = "web"
	ProtoShare  = "share"
)

// AllProtocols in Anzeige-Reihenfolge.
var AllProtocols = []string{ProtoFTP, ProtoSFTP, ProtoWebDAV, ProtoWeb}

// Permissions beschreibt, was in einem Verzeichnis erlaubt ist.
type Permissions struct {
	List   bool `json:"list"`   // Verzeichnisinhalt anzeigen
	Read   bool `json:"read"`   // Dateien herunterladen
	Write  bool `json:"write"`  // neue Dateien hochladen / überschreiben
	Append bool `json:"append"` // anhängen und Upload fortsetzen
	Delete bool `json:"delete"` // Dateien löschen
	Rename bool `json:"rename"` // umbenennen / verschieben
	MkDir  bool `json:"mkdir"`  // Ordner anlegen
	RmDir  bool `json:"rmdir"`  // Ordner löschen
}

// Mount ist ein virtueller Ordner: ein echter Pfad, der unter VirtualPath erscheint.
type Mount struct {
	VirtualPath string      `json:"virtualPath"`
	RealPath    string      `json:"realPath"`
	Perms       Permissions `json:"perms"`
}

// Group bündelt Vorgaben, die Benutzer erben.
type Group struct {
	Name           string      `json:"name"`
	Comment        string      `json:"comment"`
	Home           string      `json:"home"` // %u wird durch den Benutzernamen ersetzt
	HomePerms      Permissions `json:"homePerms"`
	Mounts         []Mount     `json:"mounts"`
	DownloadKBps   int         `json:"downloadKBps"`
	UploadKBps     int         `json:"uploadKBps"`
	MaxConnections int         `json:"maxConnections"`
	QuotaMB        int64       `json:"quotaMB"`
	Ratio          int         `json:"ratio"`         // 0 = aus, N = pro hochgeladenem Byte N Bytes Download
	RatioCreditMB  int64       `json:"ratioCreditMB"` // Startguthaben
	IPAllow        []string    `json:"ipAllow"`
	IPDeny         []string    `json:"ipDeny"`
	ForceTLS       bool        `json:"forceTLS"`
	Protocols      []string    `json:"protocols"` // leer = alle
	AllowShares    bool        `json:"allowShares"`
	Welcome        string      `json:"welcome"`
	HideFiles      []string    `json:"hideFiles"`
	DenyUpload     []string    `json:"denyUpload"`
}

// User ist ein Konto. Leere bzw. 0-Werte werden von der Gruppe geerbt.
type User struct {
	Name           string       `json:"name"`
	PasswordHash   string       `json:"passwordHash,omitempty"`
	Enabled        bool         `json:"enabled"`
	Group          string       `json:"group"`
	Comment        string       `json:"comment"`
	Home           string       `json:"home"`
	HomePerms      *Permissions `json:"homePerms"` // nil = von Gruppe erben
	Mounts         []Mount      `json:"mounts"`
	DownloadKBps   int          `json:"downloadKBps"`
	UploadKBps     int          `json:"uploadKBps"`
	MaxConnections int          `json:"maxConnections"`
	QuotaMB        int64        `json:"quotaMB"`
	Ratio          int          `json:"ratio"`
	RatioCreditMB  int64        `json:"ratioCreditMB"`
	IPAllow        []string     `json:"ipAllow"`
	IPDeny         []string     `json:"ipDeny"`
	ForceTLS       bool         `json:"forceTLS"`
	ExpiresAt      string       `json:"expiresAt"` // YYYY-MM-DD, leer = nie
	Protocols      []string     `json:"protocols"` // leer = wie Gruppe
	AllowShares    *bool        `json:"allowShares"`
	Welcome        string       `json:"welcome"`
	HideFiles      []string     `json:"hideFiles"`
	DenyUpload     []string     `json:"denyUpload"`
	SSHKeys        []string     `json:"sshKeys"` // authorized_keys-Zeilen für SFTP
}

// TLSSettings steuert FTPS.
type TLSSettings struct {
	Mode         string `json:"mode"`         // off | optional | required
	ImplicitAddr string `json:"implicitAddr"` // z. B. ":990", leer = aus
	CertFile     string `json:"certFile"`     // leer = selbst signiert erzeugen
	KeyFile      string `json:"keyFile"`
}

// AntiHammer sperrt IPs nach zu vielen Fehlversuchen.
type AntiHammer struct {
	Enabled     bool `json:"enabled"`
	MaxAttempts int  `json:"maxAttempts"`
	WindowSec   int  `json:"windowSec"`
	BanSec      int  `json:"banSec"`
}

// AdminSettings betrifft die Web-Oberfläche.
type AdminSettings struct {
	ListenAddr   string `json:"listenAddr"`
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash,omitempty"`
	UseTLS       bool   `json:"useTLS"`
	LocalNoLogin bool   `json:"localNoLogin"` // auf dem eigenen Rechner ohne Passwort
	// Zwei-Faktor-Anmeldung
	TOTPSecret     string   `json:"totpSecret,omitempty"`
	TOTPLastUsed   int64    `json:"totpLastUsed,omitempty"`
	RecoveryHashes []string `json:"recoveryHashes,omitempty"`
}

// ACMESettings: echtes HTTPS-Zertifikat von Let's Encrypt.
type ACMESettings struct {
	Enabled bool   `json:"enabled"`
	Domain  string `json:"domain"` // z. B. dateien.example.ch
	Email   string `json:"email"`  // optional, für Warnungen von Let's Encrypt
}

// SFTPSettings für den SSH/SFTP-Dienst.
type SFTPSettings struct {
	Enabled    bool   `json:"enabled"`
	ListenAddr string `json:"listenAddr"`
}

// WebSettings für WebDAV, Browser-Client und Freigabe-Links.
// Jeder der drei Dienste kann einen eigenen Port haben; leer = gleicher Port wie der Browser.
type WebSettings struct {
	Enabled    bool         `json:"enabled"`
	ListenAddr string       `json:"listenAddr"` // Browser-Zugang
	DavAddr    string       `json:"davAddr"`    // WebDAV, leer = wie ListenAddr
	ShareAddr  string       `json:"shareAddr"`  // Freigabe-Links, leer = wie ListenAddr
	UseTLS     bool         `json:"useTLS"`
	PublicURL  string       `json:"publicURL"` // Basis für Freigabe-Links, z. B. https://files.example.ch
	WebDAV     bool         `json:"webdav"`
	WebClient  bool         `json:"webClient"`
	Shares     bool         `json:"shares"`
	ACME       ACMESettings `json:"acme"`
	Geo        GeoSettings  `json:"geo"`
}

// EffectiveDav liefert die Adresse des WebDAV-Dienstes.
func (w WebSettings) EffectiveDav() string {
	if strings.TrimSpace(w.DavAddr) != "" {
		return w.DavAddr
	}
	return w.ListenAddr
}

// EffectiveShare liefert die Adresse der Freigabe-Links.
func (w WebSettings) EffectiveShare() string {
	if strings.TrimSpace(w.ShareAddr) != "" {
		return w.ShareAddr
	}
	return w.ListenAddr
}

// Settings sind die globalen Servereinstellungen.
type Settings struct {
	ServerName         string        `json:"serverName"`
	ListenAddr         string        `json:"listenAddr"`
	FTPEnabled         bool          `json:"ftpEnabled"`
	Online             bool          `json:"online"`
	Banner             string        `json:"banner"`
	PassivePortMin     int           `json:"passivePortMin"`
	PassivePortMax     int           `json:"passivePortMax"`
	PublicIP           string        `json:"publicIP"`
	MaxConnections     int           `json:"maxConnections"`
	MaxConnPerIP       int           `json:"maxConnPerIP"`
	IdleTimeoutSec     int           `json:"idleTimeoutSec"`
	LoginTimeoutSec    int           `json:"loginTimeoutSec"`
	GlobalDownloadKBps int           `json:"globalDownloadKBps"`
	GlobalUploadKBps   int           `json:"globalUploadKBps"`
	AllowFXP           bool          `json:"allowFXP"`
	FollowSymlinks     bool          `json:"followSymlinks"`
	DirMessages        bool          `json:"dirMessages"` // .message beim Ordnerwechsel anzeigen
	HideFiles          []string      `json:"hideFiles"`
	DenyUpload         []string      `json:"denyUpload"`
	IPAllow            []string      `json:"ipAllow"`
	IPDeny             []string      `json:"ipDeny"`
	TLS                TLSSettings   `json:"tls"`
	SFTP               SFTPSettings  `json:"sftp"`
	Web                WebSettings   `json:"web"`
	AntiHammer         AntiHammer    `json:"antiHammer"`
	Admin              AdminSettings `json:"admin"`
	LogFile            string        `json:"logFile"`
}

// Event löst bei einem Ereignis ein Skript oder einen Webhook aus.
type Event struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	On      []string `json:"on"`     // upload, download, delete, mkdir, rename, login, logout, loginfail, share
	Action  string   `json:"action"` // command | webhook
	Target  string   `json:"target"` // Befehl oder URL
	Filter  string   `json:"filter"` // Pfadmuster, z. B. *.pdf (leer = alle)
	Users   []string `json:"users"`  // leer = alle
	Comment string   `json:"comment"`
}

// Share ist ein öffentlicher Freigabe-Link.
type Share struct {
	ID           string    `json:"id"`
	Owner        string    `json:"owner"`
	Path         string    `json:"path"`               // virtueller Pfad im Konto des Besitzers bzw. im Server-Ordner
	RealPath     string    `json:"realPath,omitempty"` // Freigabe direkt eines Server-Ordners (nur Verwaltung)
	Comment      string    `json:"comment"`
	Created      time.Time `json:"created"`
	ExpiresAt    string    `json:"expiresAt"` // YYYY-MM-DD, leer = nie
	PasswordHash string    `json:"passwordHash,omitempty"`
	MaxDownloads int       `json:"maxDownloads"` // 0 = unbegrenzt
	Downloads    int       `json:"downloads"`
	Upload       bool      `json:"upload"` // Briefkasten: nur hochladen
	Disabled     bool      `json:"disabled"`
}

// Expired meldet, ob ein Link abgelaufen oder aufgebraucht ist.
func (s *Share) Expired(now time.Time) bool {
	if s.Disabled || (s.MaxDownloads > 0 && s.Downloads >= s.MaxDownloads) {
		return true
	}
	if s.ExpiresAt == "" {
		return false
	}
	t, err := time.ParseInLocation("2006-01-02", s.ExpiresAt, time.Local)
	return err == nil && now.After(t.Add(24*time.Hour))
}

// Config ist die gesamte gespeicherte Konfiguration.
type Config struct {
	Settings Settings `json:"settings"`
	Groups   []Group  `json:"groups"`
	Users    []User   `json:"users"`
	Events   []Event  `json:"events"`
	Notify   Notify   `json:"notify"`
	Shares   []Share  `json:"shares"`
}

// Store hält die Konfiguration im Speicher und schreibt sie atomar auf Platte.
type Store struct {
	mu      sync.RWMutex
	path    string
	DataDir string
	cfg     Config
	onSave  []func()
}

// DefaultConfig liefert sinnvolle Startwerte.
func DefaultConfig(dataDir string) Config {
	return Config{
		Settings: Settings{
			ServerName:      "SG9 Server",
			ListenAddr:      ":2121",
			FTPEnabled:      true,
			Online:          true,
			Banner:          "Willkommen auf %s",
			PassivePortMin:  50000,
			PassivePortMax:  50100,
			MaxConnections:  100,
			MaxConnPerIP:    10,
			IdleTimeoutSec:  300,
			LoginTimeoutSec: 60,
			DirMessages:     true,
			TLS:             TLSSettings{Mode: "optional"},
			SFTP:            SFTPSettings{Enabled: true, ListenAddr: ":2222"},
			Web:             WebSettings{Enabled: true, ListenAddr: ":8080", WebDAV: true, WebClient: true, Shares: true},
			AntiHammer:      AntiHammer{Enabled: true, MaxAttempts: 5, WindowSec: 60, BanSec: 900},
			Admin:           AdminSettings{ListenAddr: "127.0.0.1:8021", Username: "admin"},
			LogFile:         filepath.Join(dataDir, "sg9.log"),
		},
		Groups: []Group{{
			Name:        "Standard",
			Comment:     "Vorgabegruppe: jeder Benutzer bekommt einen eigenen Ordner",
			Home:        filepath.Join(dataDir, "ftproot", "%u"),
			HomePerms:   Permissions{List: true, Read: true, Write: true, Append: true, Delete: true, Rename: true, MkDir: true, RmDir: true},
			AllowShares: true,
		}},
	}
}

// OpenStore lädt die Konfiguration oder legt eine neue an.
func OpenStore(dataDir string) (*Store, bool, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, false, err
	}
	s := &Store{path: filepath.Join(dataDir, "sg9.json"), DataDir: dataDir}
	b, err := os.ReadFile(s.path)
	created := false
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.cfg = DefaultConfig(dataDir)
		s.cfg.Notify.On = append([]string(nil), DefaultNotifyOn...)
		// Im Container muss die Verwaltung von aussen erreichbar sein.
		if a := strings.TrimSpace(os.Getenv("SG9_ADMIN_LISTEN")); a != "" {
			s.cfg.Settings.Admin.ListenAddr = a
		}
		if n := strings.TrimSpace(os.Getenv("SG9_SERVER_NAME")); n != "" {
			s.cfg.Settings.ServerName = n
		}
		created = true
		if err := s.saveLocked(); err != nil {
			return nil, false, err
		}
	case err != nil:
		return nil, false, err
	default:
		cfg := DefaultConfig(dataDir)
		// Ältere Konfigurationen kennen die neuen Abschnitte nicht: Vorgaben behalten.
		if err := json.Unmarshal(b, &cfg); err != nil {
			return nil, false, fmt.Errorf("%s ist kein gültiges JSON: %w", s.path, err)
		}
		if !strings.Contains(string(b), `"ftpEnabled"`) {
			cfg.Settings.FTPEnabled = true
		}
		if cfg.Notify.On == nil {
			cfg.Notify.On = append([]string(nil), DefaultNotifyOn...)
		}
		s.cfg = cfg
	}
	return s, created, nil
}

// OnSave registriert eine Funktion, die nach jeder Änderung läuft.
func (s *Store) OnSave(f func()) { s.mu.Lock(); s.onSave = append(s.onSave, f); s.mu.Unlock() }

func (s *Store) saveLocked() error {
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) copyLocked() Config {
	var c Config
	b, _ := json.Marshal(s.cfg)
	_ = json.Unmarshal(b, &c)
	return c
}

// Snapshot liefert eine tiefe Kopie der Konfiguration.
func (s *Store) Snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.copyLocked()
}

// Settings liefert eine Kopie der globalen Einstellungen.
func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.cfg.Settings
	st.HideFiles = append([]string(nil), st.HideFiles...)
	st.DenyUpload = append([]string(nil), st.DenyUpload...)
	st.IPAllow = append([]string(nil), st.IPAllow...)
	st.IPDeny = append([]string(nil), st.IPDeny...)
	return st
}

// Update ändert die Konfiguration atomar und speichert sie.
func (s *Store) Update(fn func(c *Config) error) error {
	return s.update(fn, true)
}

// UpdateQuiet speichert ohne Reload-Hooks (z. B. Download-Zähler von Freigaben).
func (s *Store) UpdateQuiet(fn func(c *Config) error) error {
	return s.update(fn, false)
}

func (s *Store) update(fn func(c *Config) error, hooks bool) error {
	s.mu.Lock()
	work := s.copyLocked()
	if err := fn(&work); err != nil {
		s.mu.Unlock()
		return err
	}
	if err := validate(&work); err != nil {
		s.mu.Unlock()
		return err
	}
	old := s.cfg
	s.cfg = work
	if err := s.saveLocked(); err != nil {
		s.cfg = old
		s.mu.Unlock()
		return err
	}
	var hs []func()
	if hooks {
		hs = append(hs, s.onSave...)
	}
	s.mu.Unlock()
	for _, h := range hs {
		h()
	}
	return nil
}

func validName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if !(r == '-' || r == '_' || r == '.' || r == '@' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

func validate(c *Config) error {
	st := &c.Settings
	if st.PassivePortMin < 1024 || st.PassivePortMax > 65535 || st.PassivePortMin > st.PassivePortMax {
		return errors.New("Passiv-Portbereich ungültig (1024–65535, Min ≤ Max)")
	}
	switch st.TLS.Mode {
	case "off", "optional", "required":
	default:
		return errors.New("TLS-Modus muss off, optional oder required sein")
	}
	if st.ListenAddr == "" {
		return errors.New("FTP-Adresse fehlt")
	}
	if st.SFTP.Enabled && st.SFTP.ListenAddr == "" {
		return errors.New("SFTP-Adresse fehlt")
	}
	if st.Web.Enabled && st.Web.ListenAddr == "" {
		return errors.New("Port für den Browser-Zugang fehlt")
	}
	for _, a := range []*string{&st.ListenAddr, &st.TLS.ImplicitAddr, &st.SFTP.ListenAddr, &st.Web.ListenAddr, &st.Web.DavAddr, &st.Web.ShareAddr, &st.Admin.ListenAddr} {
		if *a = strings.TrimSpace(*a); *a != "" {
			*a = NormAddr(*a)
		}
	}
	if NormAddr(st.Web.DavAddr) == NormAddr(st.Web.ListenAddr) {
		st.Web.DavAddr = ""
	}
	if NormAddr(st.Web.ShareAddr) == NormAddr(st.Web.ListenAddr) {
		st.Web.ShareAddr = ""
	}
	st.Web.ACME.Domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(st.Web.ACME.Domain), "https://"), "http://"), "/")))
	if st.Web.ACME.Enabled {
		d := st.Web.ACME.Domain
		if d == "" || !strings.Contains(d, ".") || strings.ContainsAny(d, " /:*") || net.ParseIP(d) != nil {
			return errors.New("Let's Encrypt braucht einen Domainnamen wie dateien.example.ch (keine IP-Adresse)")
		}
		st.Web.UseTLS = true
	}
	if err := CheckPorts(*st); err != nil {
		return err
	}
	if err := validatePatterns(st.HideFiles, st.DenyUpload); err != nil {
		return err
	}
	groups := map[string]bool{}
	for i := range c.Groups {
		g := &c.Groups[i]
		if !validName(g.Name) {
			return fmt.Errorf("Gruppenname %q ungültig (erlaubt: Buchstaben, Ziffern, - _ . @)", g.Name)
		}
		if groups[strings.ToLower(g.Name)] {
			return fmt.Errorf("Gruppe %q doppelt", g.Name)
		}
		groups[strings.ToLower(g.Name)] = true
		if err := validateMounts(g.Mounts); err != nil {
			return fmt.Errorf("Gruppe %s: %w", g.Name, err)
		}
		if err := validatePatterns(g.HideFiles, g.DenyUpload); err != nil {
			return fmt.Errorf("Gruppe %s: %w", g.Name, err)
		}
	}
	users := map[string]bool{}
	for i := range c.Users {
		u := &c.Users[i]
		if !validName(u.Name) {
			return fmt.Errorf("Benutzername %q ungültig (erlaubt: Buchstaben, Ziffern, - _ . @)", u.Name)
		}
		if users[strings.ToLower(u.Name)] {
			return fmt.Errorf("Benutzer %q doppelt", u.Name)
		}
		users[strings.ToLower(u.Name)] = true
		if u.Group != "" && !groups[strings.ToLower(u.Group)] {
			return fmt.Errorf("Benutzer %s: Gruppe %q existiert nicht", u.Name, u.Group)
		}
		if err := validateMounts(u.Mounts); err != nil {
			return fmt.Errorf("Benutzer %s: %w", u.Name, err)
		}
		if err := validatePatterns(u.HideFiles, u.DenyUpload); err != nil {
			return fmt.Errorf("Benutzer %s: %w", u.Name, err)
		}
	}
	for i := range c.Events {
		e := &c.Events[i]
		if e.Action != "command" && e.Action != "webhook" {
			return errors.New("Ereignis: Aktion muss command oder webhook sein")
		}
		if strings.TrimSpace(e.Target) == "" {
			return errors.New("Ereignis: Ziel (Befehl oder URL) fehlt")
		}
		if e.Action == "webhook" && !(strings.HasPrefix(e.Target, "http://") || strings.HasPrefix(e.Target, "https://")) {
			return errors.New("Webhook-URL muss mit http:// oder https:// beginnen")
		}
		if e.Filter != "" {
			if _, err := path.Match(e.Filter, "x"); err != nil {
				return fmt.Errorf("Ereignis: Filter %q ungültig", e.Filter)
			}
		}
	}
	for i := range c.Shares {
		sh := &c.Shares[i]
		if sh.ID == "" {
			return errors.New("Freigabe ohne ID")
		}
		sh.Path = CleanVirtual(sh.Path)
	}
	sort.Slice(c.Users, func(i, j int) bool { return strings.ToLower(c.Users[i].Name) < strings.ToLower(c.Users[j].Name) })
	sort.Slice(c.Groups, func(i, j int) bool { return strings.ToLower(c.Groups[i].Name) < strings.ToLower(c.Groups[j].Name) })
	return nil
}

func validatePatterns(lists ...[]string) error {
	for _, l := range lists {
		for _, p := range l {
			if _, err := path.Match(strings.ToLower(p), "x"); err != nil {
				return fmt.Errorf("Dateimuster %q ungültig", p)
			}
		}
	}
	return nil
}

func validateMounts(ms []Mount) error {
	seen := map[string]bool{}
	for i := range ms {
		vp := CleanVirtual(ms[i].VirtualPath)
		if vp == "/" {
			return errors.New("virtueller Ordner darf nicht / sein (dafür ist der Home-Ordner da)")
		}
		if ms[i].RealPath == "" {
			return fmt.Errorf("virtueller Ordner %s hat keinen echten Pfad", vp)
		}
		if seen[vp] {
			return fmt.Errorf("virtueller Ordner %s doppelt", vp)
		}
		seen[vp] = true
		ms[i].VirtualPath = vp
	}
	return nil
}

// FindUser sucht einen Benutzer (Groß-/Kleinschreibung egal).
func (c *Config) FindUser(name string) *User {
	for i := range c.Users {
		if strings.EqualFold(c.Users[i].Name, name) {
			return &c.Users[i]
		}
	}
	return nil
}

// FindGroup sucht eine Gruppe.
func (c *Config) FindGroup(name string) *Group {
	for i := range c.Groups {
		if strings.EqualFold(c.Groups[i].Name, name) {
			return &c.Groups[i]
		}
	}
	return nil
}

// FindShare sucht einen Freigabe-Link.
func (c *Config) FindShare(id string) *Share {
	for i := range c.Shares {
		if c.Shares[i].ID == id {
			return &c.Shares[i]
		}
	}
	return nil
}
