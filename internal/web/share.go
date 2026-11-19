package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"sg9/internal/core"
	"sg9/internal/ui"
)

func (s *Server) shareRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /s/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !s.settings().Shares {
			http.NotFound(w, r)
			return
		}
		ui.ServePage(w, "share.html")
	})
	mux.HandleFunc("GET /s/{id}/info", s.shareAPI(s.shareInfo, false))
	mux.HandleFunc("POST /s/{id}/unlock", s.shareUnlock)
	mux.HandleFunc("GET /s/{id}/ls", s.shareAPI(s.shareList, true))
	mux.HandleFunc("GET /s/{id}/dl", s.shareAPI(s.shareDownload, true))
	mux.HandleFunc("GET /s/{id}/zip", s.shareAPI(s.shareZip, true))
	mux.HandleFunc("PUT /s/{id}/up", s.shareAPI(s.shareUpload, true))
	mux.HandleFunc("POST /s/{id}/message", s.shareAPI(s.shareMessage, true))
}

type shareCtx struct {
	sh    core.Share
	sess  *httpSession
	isDir bool
	name  string
}

// shareAPI prüft Link, Ablauf, Passwort und Besitzerkonto.
func (s *Server) shareAPI(next func(w http.ResponseWriter, r *http.Request, c *shareCtx), needUnlock bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.settings().Shares {
			fail(w, 404, "Freigaben sind deaktiviert")
			return
		}
		ip := clientIP(r)
		id := r.PathValue("id")
		cfg := s.Hub.Store.Snapshot()
		sh := cfg.FindShare(id)
		if sh == nil || s.Hub.Bans.Banned(ip.String()) {
			fail(w, 404, "Dieser Link existiert nicht (mehr).")
			return
		}
		if okc, cc := s.Hub.Geo.Allowed(ip, true); !okc {
			s.Hub.Log.Warn("Freigabe %s: Zugriff aus %s (%s) durch Länderfilter abgelehnt", sh.ID, cc, ip)
			fail(w, 403, "Dieser Link ist aus deinem Land nicht erreichbar.")
			return
		}
		if sh.Expired(time.Now()) {
			fail(w, 410, "Dieser Link ist abgelaufen.")
			return
		}
		acct, valid := cfg.ShareAccount(sh)
		if !valid {
			fail(w, 410, "Dieser Link ist nicht mehr gültig.")
			return
		}
		if !s.Hub.Store.Settings().Online {
			fail(w, 503, "Server ist offline.")
			return
		}
		if needUnlock && sh.PasswordHash != "" && !s.unlocked(r, sh) {
			fail(w, 401, "Passwort erforderlich")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-SG9") != "1" {
			fail(w, 403, "CSRF-Schutz: Header fehlt")
			return
		}
		// Freigaben laufen unter dem Konto des Besitzers (mit dessen Rechten und Limits)
		// oder, bei Server-Ordnern, unter einem eigenen Konto nur für diesen Ordner.
		sess, err := s.session("share|"+sh.ID+"|"+ip.String(), core.ProtoShare, acct, ip, r.TLS != nil)
		if err != nil {
			fail(w, 503, err.Error())
			return
		}
		sess.shareID = sh.ID
		_, e, err := sess.fs.StatPath(sh.Path)
		if err != nil {
			fail(w, 410, "Der freigegebene Inhalt existiert nicht mehr.")
			return
		}
		name := e.Name
		if sh.Path == "/" {
			name = sh.Owner
			if sh.RealPath != "" {
				name = filepath.Base(sh.RealPath)
			}
		}
		ctx, done := sess.begin(r.Context(), r.Method+" "+r.URL.Path)
		defer done()
		next(w, r.WithContext(ctx), &shareCtx{sh: *sh, sess: sess, isDir: e.IsDir, name: name})
	}
}

func (s *Server) unlockCookie(sh *core.Share) string { return "sg9s_" + sh.ID }

func (s *Server) unlocked(r *http.Request, sh *core.Share) bool {
	c, err := r.Cookie(s.unlockCookie(sh))
	return err == nil && c.Value == s.sign("share", sh.ID, sh.PasswordHash)
}

func (s *Server) shareUnlock(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.Hub.Bans.Banned(ip.String()) {
		fail(w, 429, "Zu viele Fehlversuche.")
		return
	}
	cfg := s.Hub.Store.Snapshot()
	sh := cfg.FindShare(r.PathValue("id"))
	if sh == nil || sh.Expired(time.Now()) {
		fail(w, 404, "Dieser Link existiert nicht (mehr).")
		return
	}
	var in struct{ Password string }
	if readJSON(r, &in) != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	if sh.PasswordHash != "" && !core.CheckPassword(sh.PasswordHash, in.Password) {
		time.Sleep(700 * time.Millisecond)
		s.Hub.Log.Warn("Falsches Passwort für Freigabe %s von %s", sh.ID, ip)
		s.Hub.Bans.Fail(ip.String(), s.Hub.Store.Settings().AntiHammer)
		fail(w, 401, "Passwort falsch")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.unlockCookie(sh), Value: s.sign("share", sh.ID, sh.PasswordHash), Path: "/s/" + sh.ID,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// sharePath bildet einen relativen Pfad innerhalb der Freigabe ab.
func (c *shareCtx) sharePath(rel string) string {
	if !c.isDir {
		return c.sh.Path
	}
	return core.CleanVirtual(path.Join(c.sh.Path, core.CleanVirtual(rel)))
}

func (s *Server) shareInfo(w http.ResponseWriter, r *http.Request, c *shareCtx) {
	out := map[string]any{
		"name": c.name, "dir": c.isDir, "upload": c.sh.Upload, "comment": c.sh.Comment, "owner": c.sh.Owner,
		"preview":   c.sh.MaxDownloads == 0,
		"expiresAt": c.sh.ExpiresAt, "locked": c.sh.PasswordHash != "" && !s.unlocked(r, &c.sh),
		"server": s.Hub.Store.Settings().ServerName,
	}
	if c.sh.MaxDownloads > 0 {
		out["downloadsLeft"] = c.sh.MaxDownloads - c.sh.Downloads
	}
	if !c.isDir {
		if _, e, err := c.sess.fs.StatPath(c.sh.Path); err == nil {
			out["size"] = e.Size
			out["modified"] = e.ModTime
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) shareList(w http.ResponseWriter, r *http.Request, c *shareCtx) {
	if c.sh.Upload {
		fail(w, 403, "Dieser Briefkasten zeigt keinen Inhalt an.")
		return
	}
	if !c.isDir {
		fail(w, 400, "Kein Ordner")
		return
	}
	vp := c.sharePath(r.URL.Query().Get("path"))
	t, entries, err := c.sess.fs.ListPath(vp)
	if err != nil {
		failErr(w, err)
		return
	}
	rel := strings.TrimPrefix(t.Virtual, strings.TrimRight(c.sh.Path, "/"))
	if rel == "" {
		rel = "/"
	}
	writeJSON(w, 200, map[string]any{"path": rel, "entries": toJSON(entries)})
}

func (s *Server) shareDownload(w http.ResponseWriter, r *http.Request, c *shareCtx) {
	if c.sh.Upload {
		fail(w, 403, "Dieser Briefkasten erlaubt keine Downloads.")
		return
	}
	inline := r.URL.Query().Get("inline") == "1"
	if inline && c.sh.MaxDownloads > 0 {
		fail(w, 403, "Bei Links mit begrenzten Downloads gibt es keine Vorschau.")
		return
	}
	rng := r.Header.Get("Range")
	// Nur echte Downloads zählen, keine Vorschau und keine Fortsetzungs-Teilstücke.
	count := r.Method == http.MethodGet && !inline && (rng == "" || strings.HasPrefix(rng, "bytes=0-"))
	if _, n, _ := sendFile(w, r, c.sess, c.sess.fs, c.sharePath(r.URL.Query().Get("path")), inline); count && n > 0 {
		s.Hub.CountShareDownload(c.sh.ID)
	}
}

func (s *Server) shareZip(w http.ResponseWriter, r *http.Request, c *shareCtx) {
	if c.sh.Upload || !c.isDir {
		fail(w, 403, "Nicht möglich")
		return
	}
	s.Hub.CountShareDownload(c.sh.ID)
	sendZip(w, c.sess, c.sess.fs, c.sharePath(r.URL.Query().Get("path")))
}

// shareUpload legt eine Datei im Briefkasten ab, ohne Bestehendes zu überschreiben.
func (s *Server) shareUpload(w http.ResponseWriter, r *http.Request, c *shareCtx) {
	if !c.sh.Upload || !c.isDir {
		fail(w, 403, "Dieser Link erlaubt kein Hochladen.")
		return
	}
	name := path.Base(core.CleanVirtual(r.URL.Query().Get("name")))
	if name == "/" || name == "." || name == "" {
		fail(w, 400, "Dateiname fehlt")
		return
	}
	from := senderName(r.URL.Query().Get("from"))
	dir := s.senderDir(c, from)
	target, err := freeName(c.sess.fs, dir, name)
	if err != nil {
		failErr(w, err)
		return
	}
	c.sess.setNote(from)
	t, _, err := receiveUpload(r, c.sess, c.sess.fs, target)
	if err != nil {
		failErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1", "name": path.Base(t.Virtual)})
}

// shareMessage legt eine Nachricht des Absenders als Textdatei in den Briefkasten.
func (s *Server) shareMessage(w http.ResponseWriter, r *http.Request, c *shareCtx) {
	if !c.sh.Upload || !c.isDir {
		fail(w, 403, "Dieser Link erlaubt kein Hochladen.")
		return
	}
	var in struct{ From, Message string }
	if readJSON(r, &in) != nil || strings.TrimSpace(in.Message) == "" {
		fail(w, 400, "Nachricht fehlt")
		return
	}
	if len(in.Message) > 20000 {
		fail(w, 400, "Die Nachricht ist zu lang")
		return
	}
	from := senderName(in.From)
	dir := s.senderDir(c, from)
	label := "Nachricht"
	if from != "" {
		label += " von " + from
	}
	target, err := freeName(c.sess.fs, dir, label+".txt")
	if err != nil {
		failErr(w, err)
		return
	}
	body := label + ", " + time.Now().Format("02.01.2006 15:04") + "\n\n" + strings.TrimSpace(in.Message) + "\n"
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))
	c.sess.setNote(from)
	_, _, err = receiveUpload(r, c.sess, c.sess.fs, target)
	if err != nil {
		failErr(w, err)
		return
	}
	ok := map[string]string{"ok": "1"}
	writeJSON(w, 200, ok)
}

// senderName macht aus der Eingabe einen sicheren Ordnernamen.
func senderName(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '-' || r == '_' || r == '.' || r == '&' {
			b.WriteRune(r)
		}
	}
	out := strings.Trim(strings.Join(strings.Fields(b.String()), " "), ". ")
	if len([]rune(out)) > 60 {
		out = string([]rune(out)[:60])
	}
	return out
}

// senderDir liefert den Unterordner des Absenders (falls Ordner angelegt werden dürfen).
func (s *Server) senderDir(c *shareCtx, from string) string {
	if from == "" {
		return c.sh.Path
	}
	dir := path.Join(c.sh.Path, from)
	if _, e, err := c.sess.fs.StatPath(dir); err == nil && e.IsDir {
		return dir
	}
	if _, err := c.sess.fs.Mkdir(dir); err == nil {
		return dir
	}
	return c.sh.Path // kein Recht auf Unterordner: direkt in den Briefkasten
}

// freeName findet einen Dateinamen, der noch nicht existiert ("Datei (2).pdf").
func freeName(fsys *core.FS, dir, name string) (string, error) {
	target := path.Join(dir, name)
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		if _, _, err := fsys.StatPath(target); errors.Is(err, core.ErrNotFound) {
			return target, nil
		}
		if i > 999 {
			return "", core.ErrExists
		}
		target = path.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
	}
}
