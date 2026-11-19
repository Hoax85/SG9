package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sg9/internal/core"
)

// Wie lange eine Anmeldung gilt. Jede Nutzung verlängert sie.
const sessionTTL = 30 * 24 * time.Hour

// ---------- Herkunft einer Anfrage ----------

// hostOK schützt vor DNS-Rebinding: Der Browser muss uns unter einem Namen
// aufrufen, der eindeutig ein lokaler Rechner ist, nicht unter einer fremden Domain.
func hostOK(r *http.Request) bool {
	h, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		h = r.Host
	}
	h = strings.Trim(strings.ToLower(h), "[]")
	if h == "localhost" || net.ParseIP(h) != nil {
		return true
	}
	if !strings.Contains(h, ".") {
		return true // Rechnername im eigenen Netz, z. B. "raspberrypi"
	}
	for _, suf := range []string{".local", ".lan", ".home", ".internal", ".fritz.box", ".home.arpa"} {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

func remoteIPOf(r *http.Request) net.IP {
	return net.ParseIP(clientIP(r))
}

// isThisComputer: Anfrage kommt vom Rechner, auf dem SG9 läuft.
func isThisComputer(r *http.Request) bool {
	ip := remoteIPOf(r)
	return ip != nil && ip.IsLoopback() && hostOK(r)
}

// isHomeNetwork: Anfrage aus dem eigenen Netz (für die Ersteinrichtung ohne Bildschirm, z. B. Raspberry Pi).
func isHomeNetwork(r *http.Request) bool {
	ip := remoteIPOf(r)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) && hostOK(r)
}

// ---------- Sitzungen (überstehen einen Neustart) ----------

func tokenKey(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func (a *Admin) tokensPath() string {
	return filepath.Join(a.store().DataDir, "sg9-admin-sessions.json")
}

func (a *Admin) loadTokens() {
	b, err := os.ReadFile(a.tokensPath())
	if err != nil {
		return
	}
	var m map[string]time.Time
	if json.Unmarshal(b, &m) != nil {
		return
	}
	now := time.Now()
	a.mu.Lock()
	for k, exp := range m {
		if exp.After(now) {
			a.tokens[k] = exp
		}
	}
	a.mu.Unlock()
}

// saveTokensLocked schreibt nur Hashes der Anmeldungen, nie die Anmeldungen selbst.
func (a *Admin) saveTokensLocked() {
	b, _ := json.Marshal(a.tokens)
	tmp := a.tokensPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, a.tokensPath())
	}
	a.tokensDirty = false
}

// tokenSaver speichert verlängerte Anmeldungen ab und zu.
func (a *Admin) tokenSaver() {
	for range time.Tick(5 * time.Minute) {
		a.mu.Lock()
		now := time.Now()
		for k, exp := range a.tokens {
			if now.After(exp) {
				delete(a.tokens, k)
				a.tokensDirty = true
			}
		}
		if a.tokensDirty {
			a.saveTokensLocked()
		}
		a.mu.Unlock()
	}
}

func (a *Admin) issueSession(w http.ResponseWriter) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	a.mu.Lock()
	a.tokens[tokenKey(tok)] = time.Now().Add(sessionTTL)
	a.saveTokensLocked()
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sg9_admin", Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: a.store().Settings().Admin.UseTLS, MaxAge: int(sessionTTL.Seconds())})
}

// validSession prüft das Cookie und verlängert die Anmeldung.
func (a *Admin) validSession(r *http.Request) bool {
	c, err := r.Cookie("sg9_admin")
	if err != nil {
		return false
	}
	k := tokenKey(c.Value)
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.tokens[k]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(a.tokens, k)
		a.tokensDirty = true
		return false
	}
	if time.Until(exp) < sessionTTL-time.Hour {
		a.tokens[k] = time.Now().Add(sessionTTL)
		a.tokensDirty = true
	}
	return true
}

// autoLogin: Auf dem eigenen Rechner ohne Passwort, falls eingeschaltet.
func (a *Admin) autoLogin(r *http.Request) bool {
	st := a.store().Settings().Admin
	return st.LocalNoLogin && st.PasswordHash != "" && isThisComputer(r)
}

func (a *Admin) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Header.Get("X-SG9") != "1" {
			fail(w, http.StatusForbidden, "CSRF-Schutz: Header fehlt")
			return
		}
		if a.validSession(r) || a.autoLogin(r) {
			next(w, r)
			return
		}
		fail(w, http.StatusUnauthorized, "Nicht angemeldet")
	}
}

// ---------- Endpunkte ----------

// state sagt der Oberfläche, was sie zeigen soll: Einrichtung, Anmeldung oder direkt los.
func (a *Admin) state(w http.ResponseWriter, r *http.Request) {
	st := a.store().Settings()
	needsSetup := st.Admin.PasswordHash == ""
	writeJSON(w, 200, map[string]any{
		"needsSetup": needsSetup,
		"canSetup":   needsSetup && isHomeNetwork(r),
		"loggedIn":   !needsSetup && (a.validSession(r) || a.autoLogin(r)),
		"auto":       !needsSetup && !a.validSession(r) && a.autoLogin(r),
		"local":      isThisComputer(r),
		"username":   st.Admin.Username,
		"serverName": st.ServerName,
	})
}

// setup legt beim ersten Start das Passwort fest.
func (a *Admin) setup(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-SG9") != "1" {
		fail(w, http.StatusForbidden, "CSRF-Schutz: Header fehlt")
		return
	}
	if !isHomeNetwork(r) {
		fail(w, 403, "Die Einrichtung geht nur vom Server selbst oder aus dem eigenen Netz.")
		return
	}
	var in struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		LocalNoLogin bool   `json:"localNoLogin"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	if len(in.Password) < 8 {
		fail(w, 400, "Das Passwort braucht mindestens 8 Zeichen")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	h := core.HashPassword(in.Password)
	done := false
	err := a.store().Update(func(c *core.Config) error {
		if c.Settings.Admin.PasswordHash != "" {
			return nil // jemand war schneller
		}
		c.Settings.Admin.PasswordHash = h
		if in.Username != "" {
			c.Settings.Admin.Username = in.Username
		}
		c.Settings.Admin.LocalNoLogin = in.LocalNoLogin
		done = true
		return nil
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if !done {
		fail(w, 409, "SG9 ist schon eingerichtet. Bitte anmelden.")
		return
	}
	_ = os.Remove(filepath.Join(a.store().DataDir, "ERSTES-ADMIN-PASSWORT.txt"))
	a.issueSession(w)
	a.Hub.Log.Info("Verwaltung eingerichtet von %s", clientIP(r))
	ok(w)
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if a.loginBans.Banned(ip) {
		fail(w, http.StatusTooManyRequests, "Zu viele Fehlversuche, bitte in 10 Minuten erneut versuchen.")
		return
	}
	var in struct{ Username, Password string }
	if err := readJSON(r, &in); err != nil {
		fail(w, http.StatusBadRequest, "Ungültige Anfrage")
		return
	}
	st := a.store().Settings()
	if st.Admin.PasswordHash == "" {
		fail(w, 409, "SG9 ist noch nicht eingerichtet.")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(in.Username), st.Admin.Username) || !core.CheckPassword(st.Admin.PasswordHash, in.Password) {
		time.Sleep(700 * time.Millisecond)
		if a.loginBans.Fail(ip, core.AntiHammer{Enabled: true, MaxAttempts: 8, WindowSec: 300, BanSec: 600}) {
			a.Hub.Log.Warn("Verwaltung: IP %s gesperrt", ip)
		}
		a.Hub.Log.Warn("Anmeldung an der Verwaltung fehlgeschlagen von %s", ip)
		fail(w, http.StatusUnauthorized, "Benutzername oder Passwort falsch")
		return
	}
	a.issueSession(w)
	a.Hub.Log.Info("Verwaltung: angemeldet von %s", ip)
	ok(w)
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sg9_admin"); err == nil {
		a.mu.Lock()
		delete(a.tokens, tokenKey(c.Value))
		a.saveTokensLocked()
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sg9_admin", Value: "", Path: "/", MaxAge: -1})
	ok(w)
}

// logoutAll beendet alle Anmeldungen, z. B. nach einem Passwortwechsel.
func (a *Admin) logoutAll() {
	a.mu.Lock()
	a.tokens = map[string]time.Time{}
	a.saveTokensLocked()
	a.mu.Unlock()
}
