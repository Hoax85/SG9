// Package web stellt WebDAV, den Browser-Client und Freigabe-Links bereit.
package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/webdav"

	"sg9/internal/core"
	"sg9/internal/ui"
)

// Server ist der Web-Dienst. Browser, WebDAV und Freigabe-Links können
// sich einen Port teilen oder jeweils einen eigenen haben.
type Server struct {
	Hub *core.Hub

	mu        sync.Mutex
	listeners []*webListener
	listenKey string
	secret    []byte

	smu      sync.Mutex
	sessions map[string]*httpSession // Schlüssel: dav|user|ip, web|token, share|id|ip
	blocked  map[string]time.Time    // nach Kick kurz sperren
	cache    map[string]cacheEntry   // Basic-Auth-Cache (PBKDF2 ist teuer)
	locks    map[string]webdav.LockSystem
}

// webListener ist ein Port mit den Funktionen, die darauf laufen.
type webListener struct {
	addr     string
	features map[string]bool // web, dav, share
	ln       net.Listener
	srv      *http.Server
}

type cacheEntry struct {
	acct core.Account
	exp  time.Time
}

// New erstellt den Web-Dienst.
func New(h *core.Hub) *Server {
	s := &Server{Hub: h, sessions: map[string]*httpSession{}, blocked: map[string]time.Time{},
		cache: map[string]cacheEntry{}, locks: map[string]webdav.LockSystem{}}
	s.secret = loadSecret(h.Store.DataDir)
	go s.janitor()
	return s
}

func loadSecret(dir string) []byte {
	p := filepath.Join(dir, "sg9-secret")
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		return b
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	_ = os.WriteFile(p, b, 0o600)
	return b
}

func (s *Server) settings() core.WebSettings { return s.Hub.Store.Settings().Web }

// Listening meldet alle Web-Adressen.
func (s *Server) Listening() []string { return s.ListeningFor("") }

// ListeningFor meldet die Adressen, auf denen eine Funktion (web, dav, share) läuft.
func (s *Server) ListeningFor(feature string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for _, l := range s.listeners {
		if feature == "" || l.features[feature] {
			out = append(out, l.ln.Addr().String())
		}
	}
	return out
}

// Start öffnet die Listener.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked()
}

func (s *Server) key(st core.Settings) string {
	w := st.Web
	return fmt.Sprint(w.Enabled, w.ListenAddr, w.EffectiveDav(), w.EffectiveShare(), w.WebClient, w.WebDAV, w.Shares, w.UseTLS, st.TLS.CertFile, st.TLS.KeyFile)
}

// plan ordnet die eingeschalteten Funktionen ihren Adressen zu.
func plan(w core.WebSettings) ([]string, map[string]map[string]bool) {
	var order []string
	m := map[string]map[string]bool{}
	add := func(addr, f string) {
		k := core.NormAddr(addr)
		if m[k] == nil {
			m[k] = map[string]bool{}
			order = append(order, k)
		}
		m[k][f] = true
	}
	if !w.Enabled {
		return nil, m
	}
	if w.WebClient {
		add(w.ListenAddr, "web")
	}
	if w.WebDAV {
		add(w.EffectiveDav(), "dav")
	}
	if w.Shares {
		add(w.EffectiveShare(), "share")
	}
	return order, m
}

var featureNames = map[string]string{"web": "Browser", "dav": "WebDAV", "share": "Freigabe-Links"}

func (s *Server) startLocked() error {
	st := s.Hub.Store.Settings()
	s.listenKey = s.key(st)
	order, feats := plan(st.Web)
	if len(order) == 0 {
		return nil
	}
	var tlsConf *tls.Config
	scheme := "http"
	if st.Web.UseTLS {
		if _, err := core.LoadOrCreateCert(s.Hub.Store.DataDir, st.TLS, st.ServerName); err != nil {
			return err
		}
		tlsConf = s.Hub.Certs.TLSConfig()
		scheme = "https"
	}
	var errs []string
	for _, addr := range order {
		f := feats[addr]
		var names []string
		for _, k := range []string{"web", "dav", "share"} {
			if f[k] {
				names = append(names, featureNames[k])
			}
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: Port %s nicht verfügbar: %v", strings.Join(names, ", "), addr, err))
			continue
		}
		if tlsConf != nil {
			ln = tls.NewListener(ln, tlsConf)
		}
		wl := &webListener{addr: addr, features: f, ln: ln}
		wl.srv = &http.Server{Handler: s.routes(f), ReadHeaderTimeout: 20 * time.Second, IdleTimeout: 2 * time.Minute}
		go func(wl *webListener) {
			if err := wl.srv.Serve(wl.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.Hub.Log.Error("Web-Dienst %s: %v", wl.addr, err)
			}
		}(wl)
		s.listeners = append(s.listeners, wl)
		s.Hub.Log.Info("%s auf %s://%s", strings.Join(names, ", "), scheme, ln.Addr())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (s *Server) stopLocked() {
	for _, l := range s.listeners {
		l.srv.Close()
	}
	s.listeners = nil
}

// Stop beendet den Dienst.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

// Reload startet bei geänderten Einstellungen neu.
func (s *Server) Reload() {
	st := s.Hub.Store.Settings()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key(st) == s.listenKey {
		return
	}
	s.stopLocked()
	if err := s.startLocked(); err != nil {
		s.Hub.Log.Error("Web-Neustart: %v", err)
	}
}

// PublicBase liefert die Basisadresse eines Web-Dienstes (feature: web, dav, share),
// wie sie ein Besucher von r aus erreicht.
func (s *Server) PublicBase(r *http.Request, feature string) string {
	w := s.settings()
	if feature == "share" && strings.TrimSpace(w.PublicURL) != "" {
		return strings.TrimRight(strings.TrimSpace(w.PublicURL), "/")
	}
	if feature == "share" && w.ACME.Enabled && w.ACME.Domain != "" {
		return "https://" + w.ACME.Domain
	}
	addr := w.ListenAddr
	switch feature {
	case "dav":
		addr = w.EffectiveDav()
	case "share":
		addr = w.EffectiveShare()
	}
	_, port, _ := core.SplitAddr(addr)
	host := "localhost"
	if r != nil {
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		} else if r.Host != "" {
			host = r.Host
		}
	}
	scheme := "http"
	if w.UseTLS {
		scheme = "https"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return scheme + "://" + host
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

func (s *Server) routes(f map[string]bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", ui.Handler())
	if f["dav"] {
		mux.HandleFunc("/dav/", s.serveDAV)
		mux.HandleFunc("/dav", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/dav/", http.StatusMovedPermanently)
				return
			}
			s.serveDAV(w, r)
		})
		// Windows fragt beim Verbinden oft OPTIONS auf / an.
		mux.HandleFunc("OPTIONS /{$}", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("DAV", "1, 2")
			w.Header().Set("MS-Author-Via", "DAV")
			w.Header().Set("Allow", "OPTIONS, GET, HEAD, PROPFIND")
			w.WriteHeader(http.StatusOK)
		})
	}
	if f["web"] {
		s.clientRoutes(mux)
	} else {
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			switch {
			case f["dav"]:
				fmt.Fprintln(w, "SG9 WebDAV. Als Netzlaufwerk verbinden mit der Adresse dieses Servers und /dav am Ende.")
			default:
				fmt.Fprintln(w, "SG9")
			}
		})
	}
	if f["share"] {
		s.shareRoutes(mux)
	}
	return headers(mux)
}

func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if !strings.HasPrefix(r.URL.Path, "/dav") {
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:")
		}
		h.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	return net.IPv4zero
}

func (s *Server) sign(parts ...string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// ---------- WebDAV ----------

func (s *Server) serveDAV(w http.ResponseWriter, r *http.Request) {
	if !s.settings().WebDAV {
		http.Error(w, "WebDAV ist deaktiviert", http.StatusNotFound)
		return
	}
	ip := clientIP(r)
	if err := s.Hub.Admit(ip); err != nil && !s.hasSession("dav", ip) {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	user, pw, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="SG9", charset="UTF-8"`)
		http.Error(w, "Anmeldung erforderlich", http.StatusUnauthorized)
		return
	}
	acct, err := s.basicLogin(core.ProtoWebDAV, user, pw, ip, r.TLS != nil)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="SG9", charset="UTF-8"`)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	sess, err := s.session("dav|"+strings.ToLower(acct.Name)+"|"+ip.String(), core.ProtoWebDAV, acct, ip, r.TLS != nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	ctx, done := sess.begin(r.Context(), r.Method+" "+strings.TrimPrefix(r.URL.Path, "/dav"))
	defer done()
	h := &webdav.Handler{
		Prefix:     "/dav",
		FileSystem: &davFS{fs: sess.fs, sess: sess, srv: s, acct: acct},
		LockSystem: s.lockSystem(acct.Name),
	}
	h.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) lockSystem(user string) webdav.LockSystem {
	s.smu.Lock()
	defer s.smu.Unlock()
	k := strings.ToLower(user)
	if s.locks[k] == nil {
		s.locks[k] = webdav.NewMemLS()
	}
	return s.locks[k]
}

// basicLogin prüft Zugangsdaten mit kurzem Cache (PBKDF2 pro Anfrage wäre zu langsam).
func (s *Server) basicLogin(proto, user, pw string, ip net.IP, secure bool) (core.Account, error) {
	ck := s.sign("auth", proto, strings.ToLower(user), pw, ip.String())
	s.smu.Lock()
	if until, ok := s.blocked[proto+"|"+strings.ToLower(user)+"|"+ip.String()]; ok && time.Now().Before(until) {
		s.smu.Unlock()
		return core.Account{}, errors.New("Sitzung wurde vom Administrator getrennt")
	}
	if e, ok := s.cache[ck]; ok && time.Now().Before(e.exp) {
		s.smu.Unlock()
		return e.acct, nil
	}
	s.smu.Unlock()
	acct, err := s.Hub.Login(core.LoginRequest{Name: user, Password: pw, IP: ip, Protocol: proto, Secure: secure})
	if err != nil {
		return acct, err
	}
	s.smu.Lock()
	s.cache[ck] = cacheEntry{acct: acct, exp: time.Now().Add(2 * time.Minute)}
	s.smu.Unlock()
	return acct, nil
}

// ---------- Sitzungen ----------

func (s *Server) hasSession(prefix string, ip net.IP) bool {
	s.smu.Lock()
	defer s.smu.Unlock()
	for k := range s.sessions {
		if strings.HasPrefix(k, prefix+"|") && strings.HasSuffix(k, "|"+ip.String()) {
			return true
		}
	}
	return false
}

// session liefert oder erzeugt die Sitzung zu einem Schlüssel.
func (s *Server) session(key, proto string, acct core.Account, ip net.IP, secure bool) (*httpSession, error) {
	s.smu.Lock()
	sess := s.sessions[key]
	if sess == nil {
		_, _, perUser := s.Hub.Count("", acct.Name)
		if acct.MaxConnections > 0 && perUser >= acct.MaxConnections && acct.Name != "" {
			s.smu.Unlock()
			return nil, errors.New("Maximale Anzahl Verbindungen für dieses Konto erreicht")
		}
		sess = newHTTPSession(s, key, proto, acct, ip.String(), secure)
		s.sessions[key] = sess
		s.smu.Unlock()
		sess.log("info", "%s verbunden", sess.protoLabel())
		if acct.Name != "" {
			s.Hub.Fire(core.EventData{Event: "login", User: acct.Name, IP: ip.String(), Protocol: proto})
		}
		return sess, nil
	}
	s.smu.Unlock()
	sess.ensureRegistered()
	return sess, nil
}

func (s *Server) dropSession(key string) {
	s.smu.Lock()
	sess := s.sessions[key]
	delete(s.sessions, key)
	s.smu.Unlock()
	if sess != nil {
		sess.unregister()
	}
}

// janitor räumt untätige Sitzungen und abgelaufene Cache-Einträge auf.
func (s *Server) janitor() {
	for range time.Tick(30 * time.Second) {
		now := time.Now()
		var idle []*httpSession
		s.smu.Lock()
		for k, e := range s.cache {
			if now.After(e.exp) {
				delete(s.cache, k)
			}
		}
		for k, t := range s.blocked {
			if now.After(t) {
				delete(s.blocked, k)
			}
		}
		for k, sess := range s.sessions {
			last, active := sess.activity()
			if active {
				continue
			}
			if strings.HasPrefix(k, "web|") {
				if now.Sub(last) > 12*time.Hour {
					delete(s.sessions, k)
					idle = append(idle, sess)
				} else if now.Sub(last) > 5*time.Minute {
					sess.unregister() // Anmeldung bleibt gültig, taucht aber nicht mehr als aktiv auf
				}
				continue
			}
			if now.Sub(last) > 5*time.Minute {
				delete(s.sessions, k)
				idle = append(idle, sess)
			}
		}
		s.smu.Unlock()
		for _, sess := range idle {
			sess.unregister()
			sess.log("info", "%s-Sitzung beendet (untätig)", sess.protoLabel())
			if sess.user != "" {
				s.Hub.Fire(core.EventData{Event: "logout", User: sess.user, IP: sess.ip, Protocol: sess.proto})
			}
		}
	}
}

type httpSession struct {
	srv       *Server
	key       string
	id        int64
	proto     string
	ip        string
	user      string
	acct      core.Account
	fs        *core.FS
	secure    bool
	connected time.Time
	downLim   *core.Limiter
	upLim     *core.Limiter
	shareID   string

	mu         sync.Mutex
	registered bool
	lastActive time.Time
	lastCmd    string
	xfers      map[*core.Xfer]bool
	cancels    map[int64]context.CancelFunc
	reqSeq     int64
	active     atomic.Int32
}

func newHTTPSession(s *Server, key, proto string, acct core.Account, ip string, secure bool) *httpSession {
	now := time.Now()
	h := &httpSession{srv: s, key: key, proto: proto, ip: ip, user: acct.Name, acct: acct, secure: secure,
		connected: now, lastActive: now, xfers: map[*core.Xfer]bool{}, cancels: map[int64]context.CancelFunc{},
		downLim: core.NewLimiter(acct.DownloadKBps), upLim: core.NewLimiter(acct.UploadKBps)}
	if acct.Home != "" || len(acct.Mounts) > 0 {
		h.fs = core.NewFS(acct, s.Hub.Store.Settings().FollowSymlinks)
	}
	h.ensureRegistered()
	s.Hub.Stats.Connections.Add(1)
	return h
}

func (h *httpSession) ensureRegistered() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.registered {
		h.id = h.srv.Hub.NextID()
		h.srv.Hub.Register(h.id, h)
		h.registered = true
	}
}

func (h *httpSession) unregister() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.registered {
		h.srv.Hub.Unregister(h.id)
		h.registered = false
	}
}

func (h *httpSession) activity() (time.Time, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastActive, h.active.Load() > 0 || len(h.xfers) > 0
}

func (h *httpSession) protoLabel() string {
	switch h.proto {
	case core.ProtoWebDAV:
		return "WebDAV"
	case core.ProtoShare:
		return "Freigabe"
	}
	return "Web"
}

// begin verfolgt eine laufende Anfrage, damit Kick sie abbrechen kann.
func (h *httpSession) begin(parent context.Context, cmd string) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	h.mu.Lock()
	h.reqSeq++
	id := h.reqSeq
	h.cancels[id] = cancel
	h.lastCmd = cmd
	h.lastActive = time.Now()
	h.mu.Unlock()
	h.active.Add(1)
	h.ensureRegistered()
	return ctx, func() {
		h.active.Add(-1)
		h.mu.Lock()
		delete(h.cancels, id)
		h.lastActive = time.Now()
		h.mu.Unlock()
		cancel()
	}
}

// Info für den Admin.
func (h *httpSession) Info() core.SessionInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	user := h.user
	if h.proto == core.ProtoShare {
		user = "Link " + h.shareID
	}
	in := core.SessionInfo{ID: h.id, Protocol: h.proto, IP: h.ip, User: user, Connected: h.connected,
		LastCommand: h.lastCmd, LastActive: h.lastActive, TLS: h.secure}
	for x := range h.xfers {
		in.Transfer = x.Info()
		break
	}
	return in
}

// Kick bricht laufende Anfragen ab und meldet die Sitzung ab.
func (h *httpSession) Kick() {
	h.mu.Lock()
	for _, c := range h.cancels {
		c()
	}
	h.mu.Unlock()
	s := h.srv
	s.smu.Lock()
	s.blocked[h.proto+"|"+strings.ToLower(h.user)+"|"+h.ip] = time.Now().Add(30 * time.Second)
	for k, e := range s.cache {
		if strings.EqualFold(e.acct.Name, h.user) {
			delete(s.cache, k)
		}
	}
	s.smu.Unlock()
	s.dropSession(h.key)
}

func (h *httpSession) log(level, f string, a ...any) {
	h.mu.Lock()
	id := h.id
	h.mu.Unlock()
	user := h.user
	if h.proto == core.ProtoShare {
		user = "Link:" + h.shareID
	}
	h.srv.Hub.Log.Add(level, id, h.ip, user, f, a...)
}

func (h *httpSession) event(name string, t core.Target, n int64, extra string) {
	if h.proto == core.ProtoShare {
		extra = strings.TrimSpace(name + " " + h.shareID + " " + extra)
		name = "share"
	}
	h.srv.Hub.Fire(core.EventData{Event: name, User: h.acct.Name, IP: h.ip, Protocol: h.proto, Path: t.Virtual, RealPath: t.Real, Bytes: n, Extra: extra})
}

func (h *httpSession) addXfer(x *core.Xfer) { h.mu.Lock(); h.xfers[x] = true; h.mu.Unlock() }
func (h *httpSession) delXfer(x *core.Xfer) { h.mu.Lock(); delete(h.xfers, x); h.mu.Unlock() }

func (h *httpSession) downMeter(a core.Account, x *core.Xfer) *core.Meter {
	return &core.Meter{Hub: h.srv.Hub, User: a.Name, Lims: []*core.Limiter{h.downLim, h.srv.Hub.GlobalDown}, Xfer: x, Ratio: h.srv.Hub.RatioLeft(a)}
}

func (h *httpSession) upMeter(a core.Account, x *core.Xfer, q *atomic.Int64, limit int64) *core.Meter {
	return &core.Meter{Hub: h.srv.Hub, User: a.Name, Upload: true, Lims: []*core.Limiter{h.upLim, h.srv.Hub.GlobalUp}, Xfer: x, Quota: q, Limit: limit, Ratio: -1}
}
