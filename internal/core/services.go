package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- IP-Filter ----------

// IPMatches prüft, ob ip auf eine Regel passt.
// Regeln: einzelne IP, CIDR (10.0.0.0/8) oder Platzhalter (192.168.1.*).
func IPMatches(rules []string, ip net.IP) bool {
	s := ip.String()
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if r == "*" {
			return true
		}
		if strings.Contains(r, "/") {
			if _, n, err := net.ParseCIDR(r); err == nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if strings.Contains(r, "*") {
			if wildcardMatch(r, s) {
				return true
			}
			continue
		}
		if rip := net.ParseIP(r); rip != nil && rip.Equal(ip) {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern, s string) bool {
	pp := strings.Split(pattern, ".")
	sp := strings.Split(s, ".")
	if len(pp) != len(sp) {
		return false
	}
	for i := range pp {
		if pp[i] != "*" && pp[i] != sp[i] {
			return false
		}
	}
	return true
}

// IPAllowed: Sperrliste gewinnt, eine nicht leere Erlaubt-Liste ist ein Whitelist.
func IPAllowed(allow, deny []string, ip net.IP) bool {
	if IPMatches(deny, ip) {
		return false
	}
	nonEmpty := false
	for _, a := range allow {
		if strings.TrimSpace(a) != "" {
			nonEmpty = true
		}
	}
	return !nonEmpty || IPMatches(allow, ip)
}

// ---------- Bandbreite ----------

// Limiter ist ein Token-Bucket in Bytes pro Sekunde. 0 = unbegrenzt.
type Limiter struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
}

// NewLimiter erstellt einen Limiter mit kbps KiB/s.
func NewLimiter(kbps int) *Limiter { l := &Limiter{}; l.SetKBps(kbps); return l }

// SetKBps ändert das Limit zur Laufzeit.
func (l *Limiter) SetKBps(kbps int) {
	l.mu.Lock()
	l.rate = float64(kbps) * 1024
	if l.tokens > l.rate {
		l.tokens = l.rate
	}
	l.mu.Unlock()
}

// Wait blockiert, bis n Bytes übertragen werden dürfen.
func (l *Limiter) Wait(n int) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.rate <= 0 {
		l.mu.Unlock()
		return
	}
	now := time.Now()
	if l.last.IsZero() {
		l.last = now
		l.tokens = l.rate / 4
	}
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	l.last = now
	if l.tokens > l.rate {
		l.tokens = l.rate
	}
	l.tokens -= float64(n)
	var wait time.Duration
	if l.tokens < 0 {
		wait = time.Duration(-l.tokens / l.rate * float64(time.Second))
	}
	l.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

// ---------- Protokoll ----------

// LogEntry ist eine Zeile im Server-Log.
type LogEntry struct {
	ID      int64     `json:"id"`
	Time    time.Time `json:"time"`
	Level   string    `json:"level"` // info | warn | error | xfer
	Session int64     `json:"session,omitempty"`
	IP      string    `json:"ip,omitempty"`
	User    string    `json:"user,omitempty"`
	Msg     string    `json:"msg"`
}

// Logger schreibt in eine Datei, auf die Konsole und in einen Ringpuffer.
type Logger struct {
	mu    sync.Mutex
	buf   []LogEntry
	next  int64
	file  *os.File
	path  string
	quiet bool
}

const logRing = 2000

// NewLogger öffnet die Logdatei (leer = keine Datei).
func NewLogger(path string, quiet bool) *Logger {
	l := &Logger{quiet: quiet}
	l.SetFile(path)
	return l
}

// SetFile wechselt die Logdatei.
func (l *Logger) SetFile(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if path == l.path && l.file != nil {
		return
	}
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
	l.path = path
	if path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err == nil {
		l.file = f
	} else {
		fmt.Fprintf(os.Stderr, "Logdatei %s nicht beschreibbar: %v\n", path, err)
	}
}

// Add schreibt einen Eintrag.
func (l *Logger) Add(level string, sess int64, ip, user, format string, args ...any) {
	e := LogEntry{Time: time.Now(), Level: level, Session: sess, IP: ip, User: user, Msg: fmt.Sprintf(format, args...)}
	l.mu.Lock()
	l.next++
	e.ID = l.next
	if len(l.buf) >= logRing {
		copy(l.buf, l.buf[1:])
		l.buf = l.buf[:len(l.buf)-1]
	}
	l.buf = append(l.buf, e)
	line := formatLog(e)
	if l.file != nil {
		_, _ = l.file.WriteString(line)
	}
	l.mu.Unlock()
	if !l.quiet {
		fmt.Print(line)
	}
}

func formatLog(e LogEntry) string {
	who := ""
	if e.Session > 0 {
		who = fmt.Sprintf(" [#%d %s %s]", e.Session, e.IP, e.User)
	}
	return fmt.Sprintf("%s %-5s%s %s\n", e.Time.Format("2006-01-02 15:04:05"), strings.ToUpper(e.Level), who, e.Msg)
}

// Info, Warn, Error ohne Sitzungsbezug.
func (l *Logger) Info(f string, a ...any)  { l.Add("info", 0, "", "", f, a...) }
func (l *Logger) Warn(f string, a ...any)  { l.Add("warn", 0, "", "", f, a...) }
func (l *Logger) Error(f string, a ...any) { l.Add("error", 0, "", "", f, a...) }

// Since liefert alle Einträge mit ID > id (max. limit).
func (l *Logger) Since(id int64, limit int) []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []LogEntry{}
	for _, e := range l.buf {
		if e.ID > id {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// ---------- Statistik ----------

// Stats zählt Verkehr und Ereignisse seit dem Start.
type Stats struct {
	Started      time.Time
	BytesDown    atomic.Int64 // Server -> Client
	BytesUp      atomic.Int64 // Client -> Server
	FilesDown    atomic.Int64
	FilesUp      atomic.Int64
	Connections  atomic.Int64
	Logins       atomic.Int64
	FailedLogins atomic.Int64

	mu       sync.Mutex
	history  []RatePoint
	lastDown int64
	lastUp   int64
}

// RatePoint ist eine Sekunde Durchsatz.
type RatePoint struct {
	T    int64 `json:"t"`
	Down int64 `json:"down"`
	Up   int64 `json:"up"`
}

// NewStats startet den Sekundentakt für die Live-Grafik.
func NewStats() *Stats {
	s := &Stats{Started: time.Now()}
	go func() {
		t := time.NewTicker(time.Second)
		for now := range t.C {
			d, u := s.BytesDown.Load(), s.BytesUp.Load()
			s.mu.Lock()
			s.history = append(s.history, RatePoint{T: now.Unix(), Down: d - s.lastDown, Up: u - s.lastUp})
			if len(s.history) > 120 {
				s.history = s.history[len(s.history)-120:]
			}
			s.lastDown, s.lastUp = d, u
			s.mu.Unlock()
		}
	}()
	return s
}

// History liefert die letzten zwei Minuten.
func (s *Stats) History() []RatePoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]RatePoint{}, s.history...)
}

// ---------- Anti-Hammer ----------

// BanList merkt sich Fehlversuche und Sperren pro IP.
type BanList struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	bans     map[string]time.Time
}

// Ban beschreibt eine aktive Sperre.
type Ban struct {
	IP    string    `json:"ip"`
	Until time.Time `json:"until"`
}

// NewBanList erstellt eine leere Liste.
func NewBanList() *BanList {
	return &BanList{failures: map[string][]time.Time{}, bans: map[string]time.Time{}}
}

// Banned meldet, ob eine IP gerade gesperrt ist.
func (b *BanList) Banned(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.bans[ip]
	if ok && time.Now().After(until) {
		delete(b.bans, ip)
		return false
	}
	return ok
}

// Fail verbucht einen Fehlversuch; liefert true, wenn die IP jetzt gesperrt wurde.
func (b *BanList) Fail(ip string, ah AntiHammer) bool {
	if !ah.Enabled || ah.MaxAttempts <= 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	win := time.Duration(ah.WindowSec) * time.Second
	list := b.failures[ip][:0]
	for _, t := range b.failures[ip] {
		if now.Sub(t) < win {
			list = append(list, t)
		}
	}
	list = append(list, now)
	b.failures[ip] = list
	if len(list) >= ah.MaxAttempts {
		b.bans[ip] = now.Add(time.Duration(ah.BanSec) * time.Second)
		delete(b.failures, ip)
		return true
	}
	return false
}

// Success setzt den Zähler einer IP zurück.
func (b *BanList) Success(ip string) { b.mu.Lock(); delete(b.failures, ip); b.mu.Unlock() }

// List liefert alle aktiven Sperren.
func (b *BanList) List() []Ban {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []Ban{}
	now := time.Now()
	for ip, until := range b.bans {
		if now.Before(until) {
			out = append(out, Ban{IP: ip, Until: until})
		}
	}
	return out
}

// Unban hebt eine Sperre auf.
func (b *BanList) Unban(ip string) { b.mu.Lock(); delete(b.bans, ip); b.mu.Unlock() }

// ---------- TLS ----------

// LoadOrCreateCert lädt das konfigurierte Zertifikat oder erzeugt ein selbst signiertes.
func LoadOrCreateCert(dataDir string, t TLSSettings, name string) (tls.Certificate, error) {
	if t.CertFile != "" && t.KeyFile != "" {
		return tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	}
	certPath := filepath.Join(dataDir, "sg9-cert.pem")
	keyPath := filepath.Join(dataDir, "sg9-key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{name}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}
