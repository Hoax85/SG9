package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
			if r.Method == http.MethodGet {
				next(w, r)
				return
			}
			// Änderungen ins Prüfprotokoll
			rec := &statusRecorder{ResponseWriter: w, status: 200}
			detail := new(string)
			r = r.WithContext(context.WithValue(r.Context(), auditKey{}, detail))
			next(rec, r)
			if label, ok := auditLabels[r.Pattern]; ok && rec.status < 400 {
				d := *detail
				for _, k := range []string{"name", "id", "ip"} {
					if v := r.PathValue(k); v != "" && d == "" {
						d = v
					}
				}
				a.store().Audit(clientIP(r), label, d)
			}
			return
		}
		fail(w, http.StatusUnauthorized, "Nicht angemeldet")
	}
}

// ---------- Prüfprotokoll ----------

type auditKey struct{}

// auditDetail ergänzt den Eintrag im Prüfprotokoll um eine Angabe (z. B. den Benutzernamen).
func auditDetail(r *http.Request, d string) {
	if p, ok := r.Context().Value(auditKey{}).(*string); ok && d != "" {
		*p = d
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }

var auditLabels = map[string]string{
	"POST /api/sessions/{id}/kick":          "Sitzung getrennt",
	"PUT /api/users":                        "Benutzer gespeichert",
	"DELETE /api/users/{name}":              "Benutzer gelöscht",
	"POST /api/users/{name}/reset-counters": "Zähler zurückgesetzt",
	"PUT /api/groups":                       "Gruppe gespeichert",
	"DELETE /api/groups/{name}":             "Gruppe gelöscht",
	"PUT /api/settings":                     "Einstellungen geändert",
	"POST /api/server/online":               "Online/Offline umgeschaltet",
	"DELETE /api/bans/{ip}":                 "Sperre aufgehoben",
	"POST /api/admin/password":              "Admin-Passwort geändert",
	"POST /api/shares":                      "Freigabe-Link erstellt",
	"PATCH /api/shares/{id}":                "Freigabe-Link geändert",
	"DELETE /api/shares/{id}":               "Freigabe-Link gelöscht",
	"PUT /api/events":                       "Ereignisse geändert",
	"PUT /api/notify":                       "Benachrichtigungen geändert",
	"POST /api/2fa/enable":                  "Zwei-Faktor eingeschaltet",
	"POST /api/2fa/disable":                 "Zwei-Faktor ausgeschaltet",
	"POST /api/cert/request":                "Zertifikat angefordert",
	"POST /api/restore":                     "Sicherung wiederhergestellt",
	"POST /api/logout":                      "Abgemeldet",
}

// diffKeys nennt die Einstellungen, die sich geändert haben (z. B. "sftp.listenAddr, web.useTLS").
func diffKeys(a, b any) string {
	var ma, mb map[string]any
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	_ = json.Unmarshal(ja, &ma)
	_ = json.Unmarshal(jb, &mb)
	var out []string
	var walk func(prefix string, x, y map[string]any)
	walk = func(prefix string, x, y map[string]any) {
		keys := map[string]bool{}
		for k := range x {
			keys[k] = true
		}
		for k := range y {
			keys[k] = true
		}
		for k := range keys {
			if k == "passwordHash" || k == "totpSecret" || k == "recoveryHashes" || k == "totpLastUsed" {
				continue
			}
			xv, yv := x[k], y[k]
			xm, xok := xv.(map[string]any)
			ym, yok := yv.(map[string]any)
			if xok && yok {
				walk(prefix+k+".", xm, ym)
				continue
			}
			jx, _ := json.Marshal(xv)
			jy, _ := json.Marshal(yv)
			if string(jx) != string(jy) {
				out = append(out, prefix+k)
			}
		}
	}
	walk("", ma, mb)
	sort.Strings(out)
	if len(out) > 12 {
		out = append(out[:12], "…")
	}
	return strings.Join(out, ", ")
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
	a.store().Audit(clientIP(r), "Verwaltung eingerichtet", in.Username)
	a.Hub.Log.Info("Verwaltung eingerichtet von %s", clientIP(r))
	ok(w)
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if a.loginBans.Banned(ip) {
		fail(w, http.StatusTooManyRequests, "Zu viele Fehlversuche, bitte in 10 Minuten erneut versuchen.")
		return
	}
	var in struct{ Username, Password, Code string }
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
	if st.Admin.TOTPSecret != "" {
		if strings.TrimSpace(in.Code) == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "Bitte den Code aus deiner Authenticator-App eingeben", "need2fa": true})
			return
		}
		if !a.checkSecondFactor(in.Code) {
			time.Sleep(700 * time.Millisecond)
			a.loginBans.Fail(ip, core.AntiHammer{Enabled: true, MaxAttempts: 8, WindowSec: 300, BanSec: 600})
			a.Hub.Log.Warn("Verwaltung: falscher Zwei-Faktor-Code von %s", ip)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "Der Code stimmt nicht. Achte darauf, dass die Uhrzeit auf Handy und Server stimmt.", "need2fa": true})
			return
		}
	}
	a.issueSession(w)
	a.store().Audit(ip, "Angemeldet", "")
	a.Hub.Log.Info("Verwaltung: angemeldet von %s", ip)
	ok(w)
}

// checkSecondFactor prüft einen TOTP-Code oder einen Wiederherstellungscode (der dann verbraucht ist).
func (a *Admin) checkSecondFactor(code string) bool {
	st := a.store().Settings().Admin
	if c, okc := core.CheckTOTP(st.TOTPSecret, code, time.Now(), st.TOTPLastUsed); okc {
		_ = a.store().UpdateQuiet(func(cfg *core.Config) error {
			if c > cfg.Settings.Admin.TOTPLastUsed {
				cfg.Settings.Admin.TOTPLastUsed = c
			}
			return nil
		})
		return true
	}
	norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	if len(norm) == 10 {
		norm = norm[:5] + "-" + norm[5:]
	}
	for i, h := range st.RecoveryHashes {
		if core.CheckPassword(h, norm) {
			_ = a.store().UpdateQuiet(func(cfg *core.Config) error {
				hs := cfg.Settings.Admin.RecoveryHashes
				if i < len(hs) && hs[i] == h {
					cfg.Settings.Admin.RecoveryHashes = append(hs[:i:i], hs[i+1:]...)
				}
				return nil
			})
			a.Hub.Log.Warn("Verwaltung: mit Wiederherstellungscode angemeldet, noch %d übrig", len(st.RecoveryHashes)-1)
			a.Hub.NotifyEvent("error", a.Hub.T("Wiederherstellungscode benutzt"), fmt.Sprintf(a.Hub.T("Jemand hat sich mit einem Wiederherstellungscode an der Verwaltung angemeldet. Noch %d Codes übrig."), len(st.RecoveryHashes)-1))
			return true
		}
	}
	return false
}

// ---------- Zwei-Faktor einrichten ----------

type pending2FA struct {
	secret string
	exp    time.Time
}

func (a *Admin) twofaStatus(w http.ResponseWriter, r *http.Request) {
	st := a.store().Settings().Admin
	writeJSON(w, 200, map[string]any{"enabled": st.TOTPSecret != "", "recoveryLeft": len(st.RecoveryHashes), "localNoLogin": st.LocalNoLogin})
}

func (a *Admin) twofaBegin(w http.ResponseWriter, r *http.Request) {
	st := a.store().Settings()
	if st.Admin.TOTPSecret != "" {
		fail(w, 409, "Zwei-Faktor-Anmeldung ist schon eingeschaltet")
		return
	}
	secret := core.NewTOTPSecret()
	a.mu.Lock()
	a.pending = &pending2FA{secret: secret, exp: time.Now().Add(15 * time.Minute)}
	a.mu.Unlock()
	issuer := "SG9"
	if st.ServerName != "" && st.ServerName != "SG9 Server" {
		issuer = "SG9 " + st.ServerName
	}
	uri := core.TOTPURI(secret, st.Admin.Username, issuer)
	svg, err := core.QRSVG(uri)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"secret": secret, "uri": uri, "qr": svg})
}

func (a *Admin) twofaEnable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if readJSON(r, &in) != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	a.mu.Lock()
	p := a.pending
	a.mu.Unlock()
	if p == nil || time.Now().After(p.exp) {
		fail(w, 400, "Die Einrichtung ist abgelaufen. Bitte nochmals beginnen.")
		return
	}
	c, okc := core.CheckTOTP(p.secret, in.Code, time.Now(), 0)
	if !okc {
		fail(w, 400, "Der Code stimmt nicht. Prüfe, ob die Uhrzeit auf dem Handy stimmt, und gib den aktuellen Code ein.")
		return
	}
	codes := core.NewRecoveryCodes(8)
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = core.HashPassword(c)
	}
	if err := a.store().Update(func(cfg *core.Config) error {
		cfg.Settings.Admin.TOTPSecret, cfg.Settings.Admin.TOTPLastUsed, cfg.Settings.Admin.RecoveryHashes = p.secret, c, hashes
		return nil
	}); err != nil {
		fail(w, 500, err.Error())
		return
	}
	a.mu.Lock()
	a.pending = nil
	a.mu.Unlock()
	a.logoutAll()
	a.issueSession(w)
	a.Hub.Log.Info("Zwei-Faktor-Anmeldung für die Verwaltung eingeschaltet")
	writeJSON(w, 200, map[string]any{"recoveryCodes": codes})
}

func (a *Admin) twofaDisable(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password string }
	if readJSON(r, &in) != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	if !core.CheckPassword(a.store().Settings().Admin.PasswordHash, in.Password) {
		time.Sleep(700 * time.Millisecond)
		fail(w, 400, "Das Passwort stimmt nicht")
		return
	}
	if err := a.store().Update(func(cfg *core.Config) error {
		cfg.Settings.Admin.TOTPSecret, cfg.Settings.Admin.TOTPLastUsed, cfg.Settings.Admin.RecoveryHashes = "", 0, nil
		return nil
	}); err != nil {
		fail(w, 500, err.Error())
		return
	}
	a.Hub.Log.Warn("Zwei-Faktor-Anmeldung für die Verwaltung ausgeschaltet")
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
