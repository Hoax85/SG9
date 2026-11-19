// Package admin stellt die Web-Oberfläche und REST-API zur Verwaltung von SG9 bereit.
package admin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sg9/internal/core"
	"sg9/internal/ui"
	"sg9/internal/web"
)

// Version wird beim Build gesetzt.
var Version = "2.3.1"

// Services sind die Protokoll-Dienste, deren Status der Admin anzeigt.
type Services struct {
	FTP  interface{ Listening() []string }
	SFTP interface {
		Listening() []string
		Fingerprint() string
		ReloadHostKey()
	}
	Web *web.Server
}

// Admin ist der Web-Admin-Server.
type Admin struct {
	Hub *core.Hub
	Svc Services

	loginBans   *core.BanList
	mu          sync.Mutex
	tokens      map[string]time.Time // Hash der Anmeldung -> gültig bis
	tokensDirty bool
	pending     *pending2FA

	smu     sync.Mutex
	handler http.Handler
	cur     *http.Server
	curLn   net.Listener
	curKey  string
}

// New erstellt den Admin-Server.
func New(h *core.Hub, svc Services) *Admin {
	a := &Admin{Hub: h, Svc: svc, loginBans: core.NewBanList(), tokens: map[string]time.Time{}}
	a.loadTokens()
	go a.tokenSaver()
	return a
}

func (a *Admin) store() *core.Store { return a.Hub.Store }

// Start startet den HTTP(S)-Server.
func (a *Admin) Start() error {
	a.handler = a.routes()
	a.smu.Lock()
	defer a.smu.Unlock()
	st := a.store().Settings()
	return a.listenLocked(st)
}

func adminKey(st core.Settings) string {
	return fmt.Sprint(core.NormAddr(st.Admin.ListenAddr), st.Admin.UseTLS, st.TLS.CertFile, st.TLS.KeyFile)
}

// listenLocked öffnet den Port der Verwaltung und ersetzt einen bisherigen.
func (a *Admin) listenLocked(st core.Settings) error {
	ln, err := net.Listen("tcp", st.Admin.ListenAddr)
	if err != nil {
		return fmt.Errorf("Port der Verwaltung %s nicht verfügbar: %w", st.Admin.ListenAddr, err)
	}
	scheme := "http"
	if st.Admin.UseTLS {
		if _, err := core.LoadOrCreateCert(a.store().DataDir, st.TLS, st.ServerName); err != nil {
			ln.Close()
			return err
		}
		ln = tls.NewListener(ln, a.Hub.Certs.TLSConfig())
		scheme = "https"
	}
	srv := &http.Server{Handler: securityHeaders(a.handler), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.Hub.Log.Error("Verwaltung: %v", err)
		}
	}()
	if old := a.cur; old != nil {
		// Die laufende Anfrage (Einstellungen speichern) noch zu Ende beantworten lassen.
		go func() { time.Sleep(2 * time.Second); old.Close() }()
	}
	a.cur, a.curLn, a.curKey = srv, ln, adminKey(st)
	a.Hub.Log.Info("Verwaltung auf %s://%s", scheme, displayAddr(ln.Addr().String()))
	return nil
}

// Reload wechselt den Port der Verwaltung ohne Neustart von SG9.
func (a *Admin) Reload() {
	st := a.store().Settings()
	a.smu.Lock()
	defer a.smu.Unlock()
	if a.handler == nil || adminKey(st) == a.curKey {
		return
	}
	if err := a.listenLocked(st); err != nil {
		a.Hub.Log.Error("%v – die Verwaltung bleibt auf dem bisherigen Port", err)
	}
}

// Listening meldet die Adresse der Verwaltung.
func (a *Admin) Listening() []string {
	a.smu.Lock()
	defer a.smu.Unlock()
	if a.curLn == nil {
		return []string{}
	}
	return []string{a.curLn.Addr().String()}
}

func (a *Admin) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", ui.Handler())
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { ui.ServePage(w, "admin.html") })
	mux.HandleFunc("GET /api/state", a.state)
	mux.HandleFunc("POST /api/setup", a.setup)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.auth(a.logout))
	mux.HandleFunc("GET /api/status", a.auth(a.status))
	mux.HandleFunc("GET /api/sessions", a.auth(a.sessions))
	mux.HandleFunc("POST /api/sessions/{id}/kick", a.auth(a.kick))
	mux.HandleFunc("GET /api/users", a.auth(a.listUsers))
	mux.HandleFunc("PUT /api/users", a.auth(a.saveUser))
	mux.HandleFunc("DELETE /api/users/{name}", a.auth(a.deleteUser))
	mux.HandleFunc("POST /api/users/{name}/reset-counters", a.auth(a.resetCounters))
	mux.HandleFunc("GET /api/users/{name}/ls", a.auth(a.userList))
	mux.HandleFunc("GET /api/groups", a.auth(a.listGroups))
	mux.HandleFunc("PUT /api/groups", a.auth(a.saveGroup))
	mux.HandleFunc("DELETE /api/groups/{name}", a.auth(a.deleteGroup))
	mux.HandleFunc("GET /api/settings", a.auth(a.getSettings))
	mux.HandleFunc("PUT /api/settings", a.auth(a.putSettings))
	mux.HandleFunc("POST /api/server/online", a.auth(a.setOnline))
	mux.HandleFunc("GET /api/logs", a.auth(a.logs))
	mux.HandleFunc("GET /api/bans", a.auth(a.listBans))
	mux.HandleFunc("DELETE /api/bans/{ip}", a.auth(a.unban))
	mux.HandleFunc("GET /api/browse", a.auth(a.browse))
	mux.HandleFunc("GET /api/backup", a.auth(a.backupDownload))
	mux.HandleFunc("GET /api/backups", a.auth(a.backupList))
	mux.HandleFunc("GET /api/backups/{name}", a.auth(a.backupGet))
	mux.HandleFunc("POST /api/restore", a.auth(a.restore))
	mux.HandleFunc("GET /api/audit", a.auth(a.auditLog))
	mux.HandleFunc("GET /api/qr", a.auth(func(w http.ResponseWriter, r *http.Request) { core.ServeQR(w, r) }))
	mux.HandleFunc("GET /api/2fa", a.auth(a.twofaStatus))
	mux.HandleFunc("POST /api/2fa/begin", a.auth(a.twofaBegin))
	mux.HandleFunc("POST /api/2fa/enable", a.auth(a.twofaEnable))
	mux.HandleFunc("POST /api/2fa/disable", a.auth(a.twofaDisable))
	mux.HandleFunc("GET /api/notify", a.auth(a.getNotify))
	mux.HandleFunc("PUT /api/notify", a.auth(a.putNotify))
	mux.HandleFunc("POST /api/notify/test", a.auth(a.testNotify))
	mux.HandleFunc("GET /api/cert", a.auth(a.certStatus))
	mux.HandleFunc("GET /api/geo", a.auth(a.geoStatus))
	mux.HandleFunc("POST /api/cert/request", a.auth(a.certRequest))
	mux.HandleFunc("POST /api/admin/password", a.auth(a.changePassword))
	mux.HandleFunc("GET /api/shares", a.auth(a.listShares))
	mux.HandleFunc("POST /api/shares", a.auth(a.createShare))
	mux.HandleFunc("PATCH /api/shares/{id}", a.auth(a.patchShare))
	mux.HandleFunc("DELETE /api/shares/{id}", a.auth(a.deleteShare))
	mux.HandleFunc("GET /api/events", a.auth(a.listEvents))
	mux.HandleFunc("PUT /api/events", a.auth(a.saveEvents))
	mux.HandleFunc("POST /api/events/test", a.auth(a.testEvent))
	return mux
}

func displayAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
		h.ServeHTTP(w, r)
	})
}

// ---------- Hilfen ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func ok(w http.ResponseWriter) { writeJSON(w, 200, map[string]string{"ok": "1"}) }

func readJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	return json.NewDecoder(r.Body).Decode(v)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *Admin) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Current, New string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	if len(in.New) < 8 {
		fail(w, 400, "Das neue Passwort braucht mindestens 8 Zeichen")
		return
	}
	if !core.CheckPassword(a.store().Settings().Admin.PasswordHash, in.Current) {
		fail(w, 400, "Das aktuelle Passwort stimmt nicht")
		return
	}
	h := core.HashPassword(in.New)
	if err := a.store().Update(func(c *core.Config) error { c.Settings.Admin.PasswordHash = h; return nil }); err != nil {
		fail(w, 500, err.Error())
		return
	}
	_ = os.Remove(filepath.Join(a.store().DataDir, "ERSTES-ADMIN-PASSWORT.txt"))
	a.logoutAll()
	a.issueSession(w)
	a.Hub.Log.Info("Admin-Passwort geändert, andere Geräte wurden abgemeldet")
	ok(w)
}

// ---------- Status ----------

type serviceOut struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Enabled   bool     `json:"enabled"`
	Listening []string `json:"listening"`
	Sessions  int      `json:"sessions"`
	Note      string   `json:"note,omitempty"`
}

func (a *Admin) status(w http.ResponseWriter, r *http.Request) {
	cfg := a.store().Snapshot()
	st := cfg.Settings
	sess := a.Hub.Sessions()
	count := map[string]int{}
	active := 0
	for _, s := range sess {
		count[s.Protocol]++
		if s.Transfer != nil {
			active++
		}
	}
	ftpL := a.Svc.FTP.Listening()
	var plain, implicit []string
	for _, l := range ftpL {
		_, port, _ := net.SplitHostPort(l)
		_, ip, _ := net.SplitHostPort(st.TLS.ImplicitAddr)
		if st.TLS.ImplicitAddr != "" && port == ip {
			implicit = append(implicit, l)
		} else {
			plain = append(plain, l)
		}
	}
	tlsNote := map[string]string{"off": "ohne Verschlüsselung", "optional": "TLS optional", "required": "TLS erzwungen"}[st.TLS.Mode]
	webNote := map[bool]string{true: "HTTPS", false: "HTTP"}[st.Web.UseTLS]
	services := []serviceOut{
		{ID: "ftp", Name: "FTP", Enabled: st.FTPEnabled, Listening: nonNil(plain), Sessions: count["ftp"] + count["ftps"], Note: tlsNote},
		{ID: "ftps", Name: "FTPS implizit", Enabled: st.FTPEnabled && st.TLS.ImplicitAddr != "", Listening: nonNil(implicit), Sessions: -1, Note: "sofort verschlüsselt"},
		{ID: "sftp", Name: "SFTP", Enabled: st.SFTP.Enabled, Listening: a.Svc.SFTP.Listening(), Sessions: count["sftp"], Note: a.Svc.SFTP.Fingerprint()},
		{ID: "web", Name: "Browser", Enabled: st.Web.Enabled && st.Web.WebClient, Listening: a.Svc.Web.ListeningFor("web"), Sessions: count["web"], Note: webNote},
		{ID: "dav", Name: "WebDAV", Enabled: st.Web.Enabled && st.Web.WebDAV, Listening: a.Svc.Web.ListeningFor("dav"), Sessions: count["webdav"], Note: webNote + ", Pfad /dav"},
		{ID: "share", Name: "Freigabe-Links", Enabled: st.Web.Enabled && st.Web.Shares, Listening: a.Svc.Web.ListeningFor("share"), Sessions: count["share"], Note: webNote},
		{ID: "admin", Name: "Verwaltung", Enabled: true, Listening: a.Listening(), Sessions: -1, Note: map[bool]string{true: "HTTPS", false: "HTTP"}[st.Admin.UseTLS]},
	}
	activeShares := 0
	for _, s := range cfg.Shares {
		if !s.Expired(time.Now()) {
			activeShares++
		}
	}
	stats := a.Hub.Stats
	writeJSON(w, 200, map[string]any{
		"serverName":   st.ServerName,
		"version":      Version,
		"platform":     runtime.GOOS + "/" + runtime.GOARCH,
		"online":       st.Online,
		"services":     services,
		"webScheme":    map[bool]string{true: "https", false: "http"}[st.Web.UseTLS],
		"started":      stats.Started,
		"uptimeSec":    int64(time.Since(stats.Started).Seconds()),
		"sessions":     len(sess),
		"transfers":    active,
		"users":        len(cfg.Users),
		"groups":       len(cfg.Groups),
		"shares":       activeShares,
		"events":       len(cfg.Events),
		"bytesDown":    stats.BytesDown.Load(),
		"bytesUp":      stats.BytesUp.Load(),
		"filesDown":    stats.FilesDown.Load(),
		"filesUp":      stats.FilesUp.Load(),
		"connections":  stats.Connections.Load(),
		"logins":       stats.Logins.Load(),
		"failedLogins": stats.FailedLogins.Load(),
		"bans":         len(a.Hub.Bans.List()),
		"history":      stats.History(),
		"dataDir":      a.store().DataDir,
	})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (a *Admin) sessions(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, a.Hub.Sessions()) }

func (a *Admin) kick(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if !a.Hub.Kick(id) {
		fail(w, 404, "Sitzung nicht gefunden")
		return
	}
	ok(w)
}

// ---------- Benutzer ----------

type userOut struct {
	core.User
	HasPassword bool              `json:"hasPassword"`
	Online      int               `json:"online"`
	Counters    core.UserCounters `json:"counters"`
	RatioLeft   int64             `json:"ratioLeft"`
}

func (a *Admin) listUsers(w http.ResponseWriter, r *http.Request) {
	cfg := a.store().Snapshot()
	online := map[string]int{}
	for _, s := range a.Hub.Sessions() {
		online[strings.ToLower(s.User)]++
	}
	out := []userOut{}
	for _, u := range cfg.Users {
		acct := cfg.Resolve(&u)
		has := u.PasswordHash != ""
		u.PasswordHash = ""
		if u.Mounts == nil {
			u.Mounts = []core.Mount{}
		}
		out = append(out, userOut{User: u, HasPassword: has, Online: online[strings.ToLower(u.Name)],
			Counters: a.Hub.Counters(u.Name), RatioLeft: a.Hub.RatioLeft(acct)})
	}
	writeJSON(w, 200, out)
}

func (a *Admin) saveUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		core.User
		Password     string `json:"password"`
		OriginalName string `json:"originalName"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage: "+err.Error())
		return
	}
	u := in.User
	u.Name = strings.TrimSpace(u.Name)
	auditDetail(r, u.Name)
	err := a.store().Update(func(c *core.Config) error {
		var existing *core.User
		if in.OriginalName != "" {
			existing = c.FindUser(in.OriginalName)
			if existing == nil {
				return fmt.Errorf("Benutzer %s existiert nicht mehr", in.OriginalName)
			}
			if !strings.EqualFold(in.OriginalName, u.Name) && c.FindUser(u.Name) != nil {
				return fmt.Errorf("Benutzer %s existiert bereits", u.Name)
			}
		} else if c.FindUser(u.Name) != nil {
			return fmt.Errorf("Benutzer %s existiert bereits", u.Name)
		}
		if in.Password != "" {
			u.PasswordHash = core.HashPassword(in.Password)
		} else if existing != nil {
			u.PasswordHash = existing.PasswordHash
		}
		if u.PasswordHash == "" && !strings.EqualFold(u.Name, "anonymous") && len(u.SSHKeys) == 0 {
			return errors.New("Bitte ein Passwort vergeben (oder einen SSH-Schlüssel hinterlegen)")
		}
		if existing != nil {
			if !strings.EqualFold(existing.Name, u.Name) {
				for i := range c.Shares {
					if strings.EqualFold(c.Shares[i].Owner, existing.Name) {
						c.Shares[i].Owner = u.Name
					}
				}
			}
			*existing = u
		} else {
			c.Users = append(c.Users, u)
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if !u.Enabled {
		a.Hub.KickUser(u.Name)
	}
	a.Hub.Log.Info("Benutzer %s gespeichert", u.Name)
	ok(w)
}

func (a *Admin) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := a.store().Update(func(c *core.Config) error {
		for i := range c.Users {
			if strings.EqualFold(c.Users[i].Name, name) {
				c.Users = append(c.Users[:i], c.Users[i+1:]...)
				kept := c.Shares[:0]
				for _, s := range c.Shares {
					if !strings.EqualFold(s.Owner, name) {
						kept = append(kept, s)
					}
				}
				c.Shares = kept
				return nil
			}
		}
		return errors.New("Benutzer nicht gefunden")
	})
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	a.Hub.KickUser(name)
	a.Hub.Log.Info("Benutzer %s gelöscht (samt seinen Freigabe-Links)", name)
	ok(w)
}

func (a *Admin) resetCounters(w http.ResponseWriter, r *http.Request) {
	a.Hub.ResetCounters(r.PathValue("name"))
	a.Hub.Log.Info("Zähler von %s zurückgesetzt", r.PathValue("name"))
	ok(w)
}

// userList zeigt, was ein Benutzer sieht (für die Auswahl beim Anlegen von Links).
func (a *Admin) userList(w http.ResponseWriter, r *http.Request) {
	cfg := a.store().Snapshot()
	u := cfg.FindUser(r.PathValue("name"))
	if u == nil {
		fail(w, 404, "Benutzer nicht gefunden")
		return
	}
	acct := cfg.Resolve(u)
	if err := acct.EnsureHome(); err != nil {
		fail(w, 500, "Home-Ordner kann nicht angelegt werden: "+err.Error())
		return
	}
	fs := core.NewFS(acct, cfg.Settings.FollowSymlinks)
	t, e, err := fs.StatPath(r.URL.Query().Get("path"))
	if err != nil || !e.IsDir {
		fail(w, 404, "Ordner nicht gefunden")
		return
	}
	type item struct {
		Name string `json:"name"`
		Dir  bool   `json:"dir"`
		Size int64  `json:"size"`
	}
	out := []item{}
	if entries, err := fs.List(t); err == nil {
		for _, c := range entries {
			out = append(out, item{c.Name, c.IsDir, c.Size})
		}
	}
	writeJSON(w, 200, map[string]any{"path": t.Virtual, "entries": out})
}

// ---------- Gruppen ----------

func (a *Admin) listGroups(w http.ResponseWriter, r *http.Request) {
	cfg := a.store().Snapshot()
	type groupOut struct {
		core.Group
		Members int `json:"members"`
	}
	out := []groupOut{}
	for _, g := range cfg.Groups {
		n := 0
		for _, u := range cfg.Users {
			if strings.EqualFold(u.Group, g.Name) {
				n++
			}
		}
		if g.Mounts == nil {
			g.Mounts = []core.Mount{}
		}
		out = append(out, groupOut{Group: g, Members: n})
	}
	writeJSON(w, 200, out)
}

func (a *Admin) saveGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		core.Group
		OriginalName string `json:"originalName"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage: "+err.Error())
		return
	}
	g := in.Group
	g.Name = strings.TrimSpace(g.Name)
	auditDetail(r, g.Name)
	err := a.store().Update(func(c *core.Config) error {
		if in.OriginalName == "" {
			if c.FindGroup(g.Name) != nil {
				return fmt.Errorf("Gruppe %s existiert bereits", g.Name)
			}
			c.Groups = append(c.Groups, g)
			return nil
		}
		ex := c.FindGroup(in.OriginalName)
		if ex == nil {
			return fmt.Errorf("Gruppe %s existiert nicht mehr", in.OriginalName)
		}
		if !strings.EqualFold(in.OriginalName, g.Name) {
			for i := range c.Users {
				if strings.EqualFold(c.Users[i].Group, in.OriginalName) {
					c.Users[i].Group = g.Name
				}
			}
		}
		*ex = g
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.Hub.Log.Info("Gruppe %s gespeichert", g.Name)
	ok(w)
}

func (a *Admin) deleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := a.store().Update(func(c *core.Config) error {
		for _, u := range c.Users {
			if strings.EqualFold(u.Group, name) {
				return fmt.Errorf("Die Gruppe wird noch von %s verwendet", u.Name)
			}
		}
		for i := range c.Groups {
			if strings.EqualFold(c.Groups[i].Name, name) {
				c.Groups = append(c.Groups[:i], c.Groups[i+1:]...)
				return nil
			}
		}
		return errors.New("Gruppe nicht gefunden")
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ok(w)
}

// ---------- Einstellungen ----------

func (a *Admin) getSettings(w http.ResponseWriter, r *http.Request) {
	st := a.store().Settings()
	st.Admin.PasswordHash, st.Admin.TOTPSecret, st.Admin.RecoveryHashes = "", "", nil
	writeJSON(w, 200, map[string]any{"settings": st, "sftpFingerprint": a.Svc.SFTP.Fingerprint()})
}

func (a *Admin) putSettings(w http.ResponseWriter, r *http.Request) {
	var in core.Settings
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage: "+err.Error())
		return
	}
	old := a.store().Settings()
	defer func() { auditDetail(r, diffKeys(old, a.store().Settings())) }()
	if in.Admin.ListenAddr == "" {
		in.Admin.ListenAddr = old.Admin.ListenAddr
	}
	// Ports vorab prüfen, damit eine Fehleingabe keinen Dienst lahmlegt.
	if err := core.CheckPorts(normalized(in)); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := checkFreePorts(old, normalized(in)); err != nil {
		fail(w, 400, err.Error())
		return
	}
	err := a.store().Update(func(c *core.Config) error {
		in.Admin.PasswordHash = c.Settings.Admin.PasswordHash
		in.Admin.TOTPSecret, in.Admin.TOTPLastUsed, in.Admin.RecoveryHashes = c.Settings.Admin.TOTPSecret, c.Settings.Admin.TOTPLastUsed, c.Settings.Admin.RecoveryHashes
		if in.Admin.Username == "" {
			in.Admin.Username = c.Settings.Admin.Username
		}
		c.Settings = in
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.Hub.Log.Info("Einstellungen gespeichert")
	nw := a.store().Settings()
	out := map[string]any{"ok": "1"}
	if adminKey(old) != adminKey(nw) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		nh, port, _ := core.SplitAddr(nw.Admin.ListenAddr)
		if nh != "" && nh != "127.0.0.1" && nh != "::1" {
			host = nh
		}
		scheme := map[bool]string{true: "https", false: "http"}[nw.Admin.UseTLS]
		out["adminURL"] = fmt.Sprintf("%s://%s/#settings", scheme, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	writeJSON(w, 200, out)
}

// normalized wendet die Adress-Normalisierung an, ohne zu speichern.
func normalized(st core.Settings) core.Settings {
	for _, p := range []*string{&st.ListenAddr, &st.TLS.ImplicitAddr, &st.SFTP.ListenAddr, &st.Web.ListenAddr, &st.Web.DavAddr, &st.Web.ShareAddr, &st.Admin.ListenAddr} {
		if *p = strings.TrimSpace(*p); *p != "" {
			*p = core.NormAddr(*p)
		}
	}
	return st
}

// checkFreePorts prüft neue Ports, bevor sie übernommen werden.
func checkFreePorts(old, nw core.Settings) error {
	inUse := map[int]bool{}
	for _, l := range core.ActiveListeners(old) {
		if _, p, err := core.SplitAddr(l.Addr); err == nil {
			inUse[p] = true
		}
	}
	tried := map[string]bool{}
	for _, l := range core.ActiveListeners(nw) {
		addr := core.NormAddr(l.Addr)
		_, port, err := core.SplitAddr(addr)
		if err != nil || inUse[port] || tried[addr] {
			continue // gehört schon SG9 oder wurde schon geprüft
		}
		tried[addr] = true
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			msg := fmt.Sprintf("%s: Port %d ist nicht verfügbar", l.Name, port)
			switch {
			case errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission denied"):
				msg += ". Ports unter 1024 brauchen unter Linux und macOS besondere Rechte (siehe deploy/sg9.service) oder einen Port ab 1024."
			case strings.Contains(err.Error(), "address already in use") || strings.Contains(err.Error(), "Only one usage"):
				msg += ", ein anderes Programm benutzt ihn bereits."
			case strings.Contains(err.Error(), "assign requested address"):
				msg += ": Diese IP-Adresse gehört nicht zu diesem Rechner."
			default:
				msg += ": " + err.Error()
			}
			return errors.New(msg)
		}
		ln.Close()
	}
	return nil
}

func (a *Admin) setOnline(w http.ResponseWriter, r *http.Request) {
	var in struct{ Online bool }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	if err := a.store().Update(func(c *core.Config) error { c.Settings.Online = in.Online; return nil }); err != nil {
		fail(w, 500, err.Error())
		return
	}
	if in.Online {
		a.Hub.Log.Info("Server ist jetzt online")
	} else {
		a.Hub.Log.Warn("Server ist jetzt offline: neue Verbindungen werden abgewiesen")
	}
	ok(w)
}

// ---------- Freigabe-Links ----------

func (a *Admin) baseURL(r *http.Request) string { return a.Svc.Web.PublicBase(r, "share") }

func (a *Admin) listShares(w http.ResponseWriter, r *http.Request) {
	cfg := a.store().Snapshot()
	base := a.baseURL(r)
	out := []any{}
	for i := len(cfg.Shares) - 1; i >= 0; i-- {
		out = append(out, web.ShareView(cfg.Shares[i], base))
	}
	writeJSON(w, 200, out)
}

func (a *Admin) createShare(w http.ResponseWriter, r *http.Request) {
	var in core.ShareRequest
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	if in.ServerPath != "" {
		auditDetail(r, in.ServerPath)
	} else {
		auditDetail(r, in.Owner+": "+in.Path)
	}
	sh, err := a.Hub.CreateShare(in, true)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, web.ShareView(sh, a.baseURL(r)))
}

func (a *Admin) patchShare(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Disabled       *bool   `json:"disabled"`
		ResetDownloads bool    `json:"resetDownloads"`
		ExpiresAt      *string `json:"expiresAt"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	err := a.store().Update(func(c *core.Config) error {
		s := c.FindShare(r.PathValue("id"))
		if s == nil {
			return errors.New("Freigabe nicht gefunden")
		}
		if in.Disabled != nil {
			s.Disabled = *in.Disabled
		}
		if in.ResetDownloads {
			s.Downloads = 0
		}
		if in.ExpiresAt != nil {
			if *in.ExpiresAt != "" {
				if _, err := time.Parse("2006-01-02", *in.ExpiresAt); err != nil {
					return errors.New("Ablaufdatum ungültig")
				}
			}
			s.ExpiresAt = *in.ExpiresAt
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ok(w)
}

func (a *Admin) deleteShare(w http.ResponseWriter, r *http.Request) {
	if err := a.Hub.DeleteShare(r.PathValue("id"), ""); err != nil {
		fail(w, 404, err.Error())
		return
	}
	a.Hub.Log.Info("Freigabe-Link %s gelöscht", r.PathValue("id"))
	ok(w)
}

// ---------- Ereignisse ----------

func (a *Admin) listEvents(w http.ResponseWriter, r *http.Request) {
	cfg := a.store().Snapshot()
	ev := cfg.Events
	if ev == nil {
		ev = []core.Event{}
	}
	writeJSON(w, 200, map[string]any{"events": ev, "names": core.EventNames, "os": runtime.GOOS})
}

func (a *Admin) saveEvents(w http.ResponseWriter, r *http.Request) {
	var in []core.Event
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage: "+err.Error())
		return
	}
	for i := range in {
		if in[i].ID == "" {
			in[i].ID = core.NewShareID()
		}
	}
	if err := a.store().Update(func(c *core.Config) error { c.Events = in; return nil }); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.Hub.Log.Info("Ereignisse gespeichert (%d)", len(in))
	ok(w)
}

func (a *Admin) testEvent(w http.ResponseWriter, r *http.Request) {
	var e core.Event
	if err := readJSON(r, &e); err != nil || strings.TrimSpace(e.Target) == "" {
		fail(w, 400, "Ziel fehlt")
		return
	}
	go a.Hub.TestEvent(e)
	a.Hub.Log.Info("Test-Ereignis ausgelöst: %s %s", e.Action, e.Target)
	ok(w)
}

// ---------- Logs & Sperren ----------

func (a *Admin) logs(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	writeJSON(w, 200, a.Hub.Log.Since(since, 500))
}

func (a *Admin) listBans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.Hub.Bans.List())
}

func (a *Admin) unban(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	a.Hub.Bans.Unban(ip)
	a.Hub.Log.Info("Sperre für %s aufgehoben", ip)
	ok(w)
}

// ---------- Benachrichtigungen ----------

type notifyOut struct {
	core.Notify
	HasEmailPassword bool     `json:"hasEmailPassword"`
	HasNtfyToken     bool     `json:"hasNtfyToken"`
	Kinds            []string `json:"kinds"`
}

func (a *Admin) getNotify(w http.ResponseWriter, r *http.Request) {
	n := a.store().Snapshot().Notify
	out := notifyOut{Notify: n, HasEmailPassword: n.Email.Password != "", HasNtfyToken: n.Ntfy.Token != "", Kinds: core.NotifyKinds}
	out.Email.Password, out.Ntfy.Token = "", ""
	if out.On == nil {
		out.On = []string{}
	}
	writeJSON(w, 200, out)
}

// mergeSecrets übernimmt gespeicherte Passwörter, wenn das Feld leer gelassen wurde.
func (a *Admin) mergeSecrets(in core.Notify) core.Notify {
	old := a.store().Snapshot().Notify
	if in.Email.Password == "" {
		in.Email.Password = old.Email.Password
	}
	if in.Ntfy.Token == "" {
		in.Ntfy.Token = old.Ntfy.Token
	}
	if in.On == nil {
		in.On = []string{}
	}
	return in
}

func (a *Admin) putNotify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		core.Notify
		ClearEmailPassword bool `json:"clearEmailPassword"`
		ClearNtfyToken     bool `json:"clearNtfyToken"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	n := a.mergeSecrets(in.Notify)
	if in.ClearEmailPassword {
		n.Email.Password = ""
	}
	if in.ClearNtfyToken {
		n.Ntfy.Token = ""
	}
	if err := a.store().Update(func(c *core.Config) error { c.Notify = n; return nil }); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.Hub.Log.Info("Benachrichtigungen gespeichert")
	ok(w)
}

func (a *Admin) testNotify(w http.ResponseWriter, r *http.Request) {
	var in core.Notify
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	in = a.mergeSecrets(in)
	if !in.Ntfy.Enabled && !in.Email.Enabled && !in.HA.Enabled {
		fail(w, 400, "Schalte zuerst mindestens einen Weg ein")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	writeJSON(w, 200, a.Hub.TestNotify(ctx, in))
}

// ---------- Sicherung ----------

func (a *Admin) backupDownload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="sg9-sicherung-`+time.Now().Format("2006-01-02")+`.zip"`)
	if err := a.store().WriteBackup(w); err != nil {
		a.Hub.Log.Error("Sicherung: %v", err)
		return
	}
	a.store().Audit(clientIP(r), "Sicherung heruntergeladen", "")
}

func (a *Admin) backupList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.store().ListBackups())
}

func (a *Admin) backupGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !(strings.HasPrefix(name, "sg9-") || strings.HasPrefix(name, "vor-wiederherstellung-")) || !strings.HasSuffix(name, ".zip") ||
		strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		fail(w, 404, "Nicht gefunden")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeFile(w, r, filepath.Join(a.store().DataDir, "backups", name))
}

func (a *Admin) restore(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 200<<20))
	if err != nil {
		fail(w, 400, "Die Datei ist zu gross oder unvollständig")
		return
	}
	// Vorher den jetzigen Stand sichern, damit nichts verloren geht.
	safety := filepath.Join(a.store().DataDir, "backups", "vor-wiederherstellung-"+time.Now().Format("2006-01-02-150405")+".zip")
	_ = os.MkdirAll(filepath.Dir(safety), 0o750)
	if f, err := os.Create(safety); err == nil {
		_ = a.store().WriteBackup(f)
		f.Close()
	}
	if err := a.store().RestoreBackup(data); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.Hub.Certs.Reset()
	a.Svc.SFTP.ReloadHostKey()
	a.Svc.Web.ReloadSecret()
	a.Hub.Log.Info("Sicherung wiederhergestellt (der vorherige Stand liegt in %s)", safety)
	writeJSON(w, 200, map[string]any{"ok": "1", "safety": filepath.Base(safety)})
}

func (a *Admin) auditLog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.store().AuditLog(500))
}

// ---------- Let's Encrypt ----------

func (a *Admin) certStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.Hub.Certs.Status())
}

func (a *Admin) certRequest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	if err := a.Hub.Certs.Request(ctx); err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, a.Hub.Certs.Status())
}

// ---------- Ordnerauswahl ----------

type fileOut struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

func (a *Admin) browse(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	type out struct {
		Path   string    `json:"path"`
		Parent string    `json:"parent"`
		Dirs   []string  `json:"dirs"`
		Files  []fileOut `json:"files"`
		Sep    string    `json:"sep"`
		Home   string    `json:"home"`
	}
	res := out{Dirs: []string{}, Files: []fileOut{}, Sep: string(filepath.Separator)}
	if h, err := os.UserHomeDir(); err == nil && h != "/" {
		res.Home = h
	}
	// Im Container liegen die freigegebenen Ordner unter /shares.
	if fi, err := os.Stat("/shares"); err == nil && fi.IsDir() && os.Getenv("SG9_DATA") != "" {
		res.Home = "/shares"
	}
	withFiles := r.URL.Query().Get("files") == "1"
	if p == "" {
		if runtime.GOOS == "windows" {
			for c := 'A'; c <= 'Z'; c++ {
				d := string(c) + `:\`
				if _, err := os.Stat(d); err == nil {
					res.Dirs = append(res.Dirs, d)
				}
			}
			writeJSON(w, 200, res)
			return
		}
		p = "/"
	}
	p = filepath.Clean(p)
	des, err := os.ReadDir(p)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			fail(w, 403, "SG9 darf diesen Ordner nicht lesen. Läuft SG9 als Dienst (Benutzer sg9), fehlen ihm die Rechte dafür.")
		} else {
			fail(w, 400, "Ordner nicht lesbar: "+err.Error())
		}
		return
	}
	res.Path = p
	if parent := filepath.Dir(p); parent != p {
		res.Parent = parent
	}
	for _, d := range des {
		if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			if fi, err := os.Stat(filepath.Join(p, d.Name())); err == nil && fi.IsDir() {
				res.Dirs = append(res.Dirs, d.Name())
				continue
			}
		}
		if withFiles && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				res.Files = append(res.Files, fileOut{Name: d.Name(), Size: fi.Size()})
			}
		}
	}
	sort.Slice(res.Files, func(i, j int) bool { return strings.ToLower(res.Files[i].Name) < strings.ToLower(res.Files[j].Name) })
	sort.Slice(res.Dirs, func(i, j int) bool { return strings.ToLower(res.Dirs[i]) < strings.ToLower(res.Dirs[j]) })
	writeJSON(w, 200, res)
}

// geoStatus: Zustand des Länderfilters, mit ?ip= eine Adresse nachschlagen.
func (a *Admin) geoStatus(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("ip"))
	if q == "" {
		writeJSON(w, 200, a.Hub.Geo.Status())
		return
	}
	ip := net.ParseIP(q)
	if ip == nil {
		fail(w, 400, "Das ist keine IP-Adresse.")
		return
	}
	cc, err := a.Hub.Geo.Country(ip)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	ok, _ := a.Hub.Geo.Allowed(ip, true)
	writeJSON(w, 200, map[string]any{"ip": ip.String(), "country": cc, "allowed": ok})
}
