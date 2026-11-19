package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SessionInfo ist der öffentliche Zustand einer Sitzung (für den Admin).
type SessionInfo struct {
	ID          int64     `json:"id"`
	Protocol    string    `json:"protocol"`
	IP          string    `json:"ip"`
	User        string    `json:"user"`
	Connected   time.Time `json:"connected"`
	LastCommand string    `json:"lastCommand"`
	LastActive  time.Time `json:"lastActive"`
	Cwd         string    `json:"cwd"`
	TLS         bool      `json:"tls"`
	Transfer    *XferInfo `json:"transfer,omitempty"`
}

// XferInfo beschreibt eine laufende Übertragung.
type XferInfo struct {
	Direction string  `json:"direction"` // down | up | list
	File      string  `json:"file"`
	Bytes     int64   `json:"bytes"`
	Size      int64   `json:"size"`
	Speed     float64 `json:"speed"`
}

// Session ist eine Verbindung eines beliebigen Protokolls.
type Session interface {
	Info() SessionInfo
	Kick()
}

// Xfer verfolgt eine laufende Übertragung (für die Live-Anzeige).
type Xfer struct {
	Direction string
	File      string
	Size      int64
	Started   time.Time
	Bytes     atomic.Int64
}

// Info liefert den Anzeigezustand.
func (x *Xfer) Info() *XferInfo {
	if x == nil {
		return nil
	}
	b := x.Bytes.Load()
	el := time.Since(x.Started).Seconds()
	sp := 0.0
	if el > 0.2 {
		sp = float64(b) / el
	}
	return &XferInfo{Direction: x.Direction, File: x.File, Bytes: b, Size: x.Size, Speed: sp}
}

// UserCounters sind dauerhaft gespeicherte Zähler pro Benutzer (für Ratio und Statistik).
type UserCounters struct {
	BytesUp   int64     `json:"bytesUp"`
	BytesDown int64     `json:"bytesDown"`
	FilesUp   int64     `json:"filesUp"`
	FilesDown int64     `json:"filesDown"`
	Logins    int64     `json:"logins"`
	LastLogin time.Time `json:"lastLogin"`
	LastIP    string    `json:"lastIP"`
}

// Hub verbindet alle Protokolle: Anmeldung, Sitzungen, Zähler, Kontingente, Ereignisse.
type Hub struct {
	Store *Store
	Log   *Logger
	Stats *Stats
	Bans  *BanList
	Certs *Certs

	GlobalDown *Limiter
	GlobalUp   *Limiter

	mu       sync.Mutex
	sessions map[int64]Session
	nextID   int64

	cmu      sync.Mutex
	counters map[string]*UserCounters
	dirty    bool

	qmu    sync.Mutex
	quotas map[string]*atomic.Int64
}

// NewHub erstellt den Hub und lädt die Benutzerzähler.
func NewHub(store *Store, log *Logger, stats *Stats, bans *BanList) *Hub {
	st := store.Settings()
	h := &Hub{Store: store, Log: log, Stats: stats, Bans: bans, Certs: NewCerts(store, log),
		GlobalDown: NewLimiter(st.GlobalDownloadKBps), GlobalUp: NewLimiter(st.GlobalUploadKBps),
		sessions: map[int64]Session{}, counters: map[string]*UserCounters{}, quotas: map[string]*atomic.Int64{}}
	if b, err := os.ReadFile(h.countersPath()); err == nil {
		_ = json.Unmarshal(b, &h.counters)
	}
	go func() {
		for range time.Tick(30 * time.Second) {
			h.SaveCounters()
		}
	}()
	return h
}

// Reload übernimmt globale Limits.
func (h *Hub) Reload() {
	st := h.Store.Settings()
	h.GlobalDown.SetKBps(st.GlobalDownloadKBps)
	h.GlobalUp.SetKBps(st.GlobalUploadKBps)
	h.Log.SetFile(st.LogFile)
}

// ---------- Sitzungen ----------

// NextID vergibt eine Sitzungsnummer.
func (h *Hub) NextID() int64 { h.mu.Lock(); defer h.mu.Unlock(); h.nextID++; return h.nextID }

// Register trägt eine Sitzung ein.
func (h *Hub) Register(id int64, s Session) { h.mu.Lock(); h.sessions[id] = s; h.mu.Unlock() }

// Unregister entfernt eine Sitzung.
func (h *Hub) Unregister(id int64) { h.mu.Lock(); delete(h.sessions, id); h.mu.Unlock() }

func (h *Hub) list() []Session {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Session, 0, len(h.sessions))
	for _, s := range h.sessions {
		out = append(out, s)
	}
	return out
}

// Sessions liefert alle Sitzungen aller Protokolle.
func (h *Hub) Sessions() []SessionInfo {
	out := []SessionInfo{}
	for _, s := range h.list() {
		out = append(out, s.Info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Kick trennt eine Sitzung.
func (h *Hub) Kick(id int64) bool {
	h.mu.Lock()
	s := h.sessions[id]
	h.mu.Unlock()
	if s == nil {
		return false
	}
	in := s.Info()
	h.Log.Add("warn", in.ID, in.IP, in.User, "Vom Administrator getrennt")
	s.Kick()
	return true
}

// KickUser trennt alle Sitzungen eines Benutzers.
func (h *Hub) KickUser(name string) int {
	n := 0
	for _, s := range h.list() {
		if strings.EqualFold(s.Info().User, name) {
			s.Kick()
			n++
		}
	}
	return n
}

// Count zählt Sitzungen gesamt, einer IP und eines Benutzers.
func (h *Hub) Count(ip, user string) (total, perIP, perUser int) {
	for _, s := range h.list() {
		in := s.Info()
		total++
		if in.IP == ip {
			perIP++
		}
		if user != "" && strings.EqualFold(in.User, user) {
			perUser++
		}
	}
	return
}

// Admit prüft vor dem Verbindungsaufbau: online, Sperre, IP-Filter, Verbindungslimits.
func (h *Hub) Admit(ip net.IP) error {
	st := h.Store.Settings()
	s := ip.String()
	switch {
	case !st.Online:
		return errors.New("Server ist offline.")
	case h.Bans.Banned(s):
		return errors.New("Zu viele Fehlversuche, IP vorübergehend gesperrt.")
	case !IPAllowed(st.IPAllow, st.IPDeny, ip):
		h.Log.Warn("Verbindung von %s durch IP-Filter abgelehnt", s)
		return errors.New("Zugriff von dieser IP nicht erlaubt.")
	}
	total, perIP, _ := h.Count(s, "")
	if st.MaxConnections > 0 && total >= st.MaxConnections {
		return errors.New("Maximale Anzahl Verbindungen erreicht.")
	}
	if st.MaxConnPerIP > 0 && perIP >= st.MaxConnPerIP {
		return errors.New("Zu viele Verbindungen von deiner IP.")
	}
	return nil
}

// ---------- Anmeldung ----------

// LoginError unterscheidet zwischen Fehlversuch (zählt für Anti-Hammer) und Ablehnung.
type LoginError struct {
	Msg    string
	Failed bool // falsches Passwort/unbekannt: zählt als Fehlversuch
	Banned bool // IP wurde gerade gesperrt
}

func (e *LoginError) Error() string { return e.Msg }

// LoginRequest beschreibt einen Anmeldeversuch.
type LoginRequest struct {
	Name     string
	Password string
	// CheckKey prüft alternativ zum Passwort (z. B. SSH-Schlüssel). Liefert true bei Erfolg.
	CheckKey func(u *User) bool
	IP       net.IP
	Protocol string
	Secure   bool // Verbindung verschlüsselt
	Session  int64
	// CountsSession: bei true wird das Verbindungslimit pro Benutzer geprüft
	CountsSession bool
}

// Login prüft Zugangsdaten und alle Kontoregeln und liefert das effektive Konto.
func (h *Hub) Login(r LoginRequest) (Account, error) {
	ipStr := r.IP.String()
	fail := func(reason, shown string) (Account, error) {
		h.Stats.FailedLogins.Add(1)
		h.Log.Add("warn", r.Session, ipStr, "", "%s-Anmeldung als %q fehlgeschlagen: %s", strings.ToUpper(r.Protocol), r.Name, reason)
		h.Fire(EventData{Event: "loginfail", User: r.Name, IP: ipStr, Protocol: r.Protocol, Extra: reason})
		banned := h.Bans.Fail(ipStr, h.Store.Settings().AntiHammer)
		if banned {
			h.Log.Warn("IP %s wegen zu vieler Fehlversuche gesperrt", ipStr)
		}
		return Account{}, &LoginError{Msg: shown, Failed: true, Banned: banned}
	}
	deny := func(reason string) (Account, error) {
		h.Log.Add("warn", r.Session, ipStr, r.Name, "%s-Anmeldung abgelehnt: %s", strings.ToUpper(r.Protocol), reason)
		return Account{}, &LoginError{Msg: reason}
	}
	cfg := h.Store.Snapshot()
	name := r.Name
	if strings.EqualFold(name, "ftp") {
		name = "anonymous"
	}
	u := cfg.FindUser(name)
	switch {
	case u == nil:
		return fail("unbekannter Benutzer", "Anmeldung fehlgeschlagen.")
	case !u.Enabled:
		return fail("Konto deaktiviert", "Anmeldung fehlgeschlagen.")
	case u.Expired(time.Now()):
		return fail("Konto abgelaufen", "Konto abgelaufen.")
	}
	anon := strings.EqualFold(u.Name, "anonymous")
	ok := anon
	if !ok && r.CheckKey != nil {
		ok = r.CheckKey(u)
	}
	if !ok && r.Password != "" {
		ok = CheckPassword(u.PasswordHash, r.Password)
	}
	if !ok {
		return fail("falsches Passwort", "Anmeldung fehlgeschlagen.")
	}
	a := cfg.Resolve(u)
	if !a.AllowsProtocol(r.Protocol) {
		return deny(fmt.Sprintf("%s ist für dieses Konto nicht freigeschaltet.", strings.ToUpper(r.Protocol)))
	}
	if !IPAllowed(a.IPAllow, a.IPDeny, r.IP) {
		return fail("IP für dieses Konto nicht erlaubt", "Anmeldung von dieser IP nicht erlaubt.")
	}
	if a.ForceTLS && !r.Secure {
		return deny("Dieses Konto verlangt eine verschlüsselte Verbindung.")
	}
	if r.CountsSession && a.MaxConnections > 0 {
		if _, _, perUser := h.Count("", u.Name); perUser >= a.MaxConnections {
			return deny("Maximale Anzahl Verbindungen für dieses Konto erreicht.")
		}
	}
	if a.Home == "" && len(a.Mounts) == 0 {
		return deny("Für dieses Konto ist kein Ordner eingerichtet.")
	}
	if a.Home != "" {
		if err := os.MkdirAll(a.Home, 0o750); err != nil {
			h.Log.Error("Home-Ordner %s: %v", a.Home, err)
			return deny("Home-Ordner nicht verfügbar.")
		}
	}
	h.Bans.Success(ipStr)
	h.Stats.Logins.Add(1)
	h.cmu.Lock()
	c := h.counterLocked(u.Name)
	c.Logins++
	c.LastLogin = time.Now()
	c.LastIP = ipStr
	h.dirty = true
	h.cmu.Unlock()
	return a, nil
}

// ---------- Zähler, Ratio, Kontingent ----------

func (h *Hub) countersPath() string { return filepath.Join(h.Store.DataDir, "sg9-userstats.json") }

func (h *Hub) counterLocked(user string) *UserCounters {
	k := strings.ToLower(user)
	c := h.counters[k]
	if c == nil {
		c = &UserCounters{}
		h.counters[k] = c
	}
	return c
}

// SaveCounters schreibt die Benutzerzähler, falls geändert.
func (h *Hub) SaveCounters() {
	h.cmu.Lock()
	if !h.dirty {
		h.cmu.Unlock()
		return
	}
	b, _ := json.MarshalIndent(h.counters, "", "  ")
	h.dirty = false
	h.cmu.Unlock()
	tmp := h.countersPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, h.countersPath())
	}
}

// Counters liefert eine Kopie der Zähler eines Benutzers.
func (h *Hub) Counters(user string) UserCounters {
	h.cmu.Lock()
	defer h.cmu.Unlock()
	if c := h.counters[strings.ToLower(user)]; c != nil {
		return *c
	}
	return UserCounters{}
}

// ResetCounters setzt die Zähler eines Benutzers zurück (z. B. Ratio neu beginnen).
func (h *Hub) ResetCounters(user string) {
	h.cmu.Lock()
	delete(h.counters, strings.ToLower(user))
	h.dirty = true
	h.cmu.Unlock()
}

// AddBytes verbucht übertragene Bytes (global, Live-Grafik, Benutzer).
func (h *Hub) AddBytes(user string, upload bool, n int64) {
	if upload {
		h.Stats.BytesUp.Add(n)
	} else {
		h.Stats.BytesDown.Add(n)
	}
	if user == "" {
		return
	}
	h.cmu.Lock()
	c := h.counterLocked(user)
	if upload {
		c.BytesUp += n
	} else {
		c.BytesDown += n
	}
	h.dirty = true
	h.cmu.Unlock()
}

// AddFile verbucht eine abgeschlossene Datei.
func (h *Hub) AddFile(user string, upload bool) {
	if upload {
		h.Stats.FilesUp.Add(1)
	} else {
		h.Stats.FilesDown.Add(1)
	}
	if user == "" {
		return
	}
	h.cmu.Lock()
	c := h.counterLocked(user)
	if upload {
		c.FilesUp++
	} else {
		c.FilesDown++
	}
	h.dirty = true
	h.cmu.Unlock()
}

// RatioLeft liefert das verbleibende Download-Guthaben in Bytes (-1 = unbegrenzt).
func (h *Hub) RatioLeft(a Account) int64 {
	if a.Ratio <= 0 {
		return -1
	}
	c := h.Counters(a.Name)
	left := c.BytesUp*int64(a.Ratio) + a.RatioCreditMB*1024*1024 - c.BytesDown
	if left < 0 {
		return 0
	}
	return left
}

// Quota liefert den Belegungszähler eines Kontos (nil = kein Kontingent).
func (h *Hub) Quota(a Account, freshLogin bool) *atomic.Int64 {
	if a.QuotaMB <= 0 || a.Home == "" {
		return nil
	}
	h.qmu.Lock()
	defer h.qmu.Unlock()
	k := strings.ToLower(a.Name)
	q := h.quotas[k]
	if q == nil {
		q = &atomic.Int64{}
		q.Store(DirSize(a.Home))
		h.quotas[k] = q
	} else if freshLogin {
		if _, _, n := h.Count("", a.Name); n == 0 {
			q.Store(DirSize(a.Home))
		}
	}
	return q
}

// ---------- Gebremstes Kopieren ----------

// Meter zählt und bremst einen Datenstrom einer Sitzung.
type Meter struct {
	Hub    *Hub
	User   string
	Upload bool
	Lims   []*Limiter
	Xfer   *Xfer
	Quota  *atomic.Int64
	Limit  int64 // Kontingent in Bytes (0 = keins)
	Ratio  int64 // verbleibendes Download-Guthaben (-1 = unbegrenzt)
}

// ErrQuota bzw. ErrRatio brechen eine Übertragung ab.
var (
	ErrQuota = errors.New("Speicherplatz-Kontingent überschritten")
	ErrRatio = errors.New("Download-Guthaben (Ratio) aufgebraucht, bitte zuerst etwas hochladen")
)

// Before prüft und bremst vor dem Übertragen von n Bytes.
func (m *Meter) Before(n int) error {
	if m == nil {
		return nil
	}
	if m.Upload && m.Quota != nil && m.Limit > 0 && m.Quota.Load()+int64(n) > m.Limit {
		return ErrQuota
	}
	if !m.Upload && m.Ratio >= 0 {
		if m.Ratio < int64(n) {
			return ErrRatio
		}
		m.Ratio -= int64(n)
	}
	for _, l := range m.Lims {
		l.Wait(n)
	}
	return nil
}

// After verbucht n übertragene Bytes.
func (m *Meter) After(n int) {
	if m == nil || n <= 0 {
		return
	}
	if m.Xfer != nil {
		m.Xfer.Bytes.Add(int64(n))
	}
	if m.Upload && m.Quota != nil {
		m.Quota.Add(int64(n))
	}
	m.Hub.AddBytes(m.User, m.Upload, int64(n))
}

// Copy kopiert von src nach dst mit Bremse, Zählung und Prüfungen.
func (m *Meter) Copy(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			if err := m.Before(nr); err != nil {
				return total, err
			}
			nw, werr := dst.Write(buf[:nr])
			total += int64(nw)
			m.After(nw)
			if werr != nil {
				return total, werr
			}
			if nw < nr {
				return total, io.ErrShortWrite
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

// ---------- Ereignisse ----------

// EventData beschreibt ein Ereignis für Skripte und Webhooks.
type EventData struct {
	Event    string    `json:"event"`
	Time     time.Time `json:"time"`
	User     string    `json:"user"`
	IP       string    `json:"ip"`
	Protocol string    `json:"protocol"`
	Path     string    `json:"path,omitempty"`
	RealPath string    `json:"realPath,omitempty"`
	Bytes    int64     `json:"bytes,omitempty"`
	Extra    string    `json:"extra,omitempty"`
}

// EventNames für die Oberfläche.
var EventNames = []string{"upload", "download", "delete", "mkdir", "rmdir", "rename", "login", "logout", "loginfail", "share"}

// Fire löst passende Ereignisse im Hintergrund aus.
func (h *Hub) Fire(d EventData) {
	if d.Time.IsZero() {
		d.Time = time.Now()
	}
	cfg := h.Store.Snapshot()
	for _, e := range cfg.Events {
		if !e.Enabled || !containsFold(e.On, d.Event) {
			continue
		}
		if len(e.Users) > 0 && !containsFold(e.Users, d.User) {
			continue
		}
		if e.Filter != "" {
			if ok, _ := path.Match(strings.ToLower(e.Filter), strings.ToLower(path.Base(d.Path))); !ok {
				continue
			}
		}
		go h.runEvent(e, d)
	}
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func (h *Hub) runEvent(e Event, d EventData) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	switch e.Action {
	case "webhook":
		b, _ := json.Marshal(d)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Target, bytes.NewReader(b))
		if err != nil {
			h.Log.Error("Webhook %s: %v", e.Target, err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SG9")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			h.Log.Error("Webhook %s: %v", e.Target, err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			h.Log.Warn("Webhook %s antwortete %d", e.Target, resp.StatusCode)
		}
	case "command":
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(ctx, "cmd", "/C", e.Target)
		} else {
			cmd = exec.CommandContext(ctx, "/bin/sh", "-c", e.Target)
		}
		cmd.Env = append(os.Environ(),
			"SG9_EVENT="+d.Event, "SG9_USER="+d.User, "SG9_IP="+d.IP, "SG9_PROTOCOL="+d.Protocol,
			"SG9_PATH="+d.Path, "SG9_REAL_PATH="+d.RealPath, fmt.Sprintf("SG9_BYTES=%d", d.Bytes), "SG9_EXTRA="+d.Extra)
		out, err := cmd.CombinedOutput()
		if err != nil {
			h.Log.Error("Ereignis-Befehl (%s) fehlgeschlagen: %v %s", d.Event, err, strings.TrimSpace(string(out)))
		}
	}
}

// TestEvent führt ein Ereignis sofort mit Beispieldaten aus.
func (h *Hub) TestEvent(e Event) {
	h.runEvent(e, EventData{Event: "test", Time: time.Now(), User: "test", IP: "127.0.0.1", Protocol: "test", Path: "/beispiel.txt"})
}
