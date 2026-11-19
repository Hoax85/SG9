package web

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

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
	target := path.Join(c.sh.Path, name)
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		if _, _, err := c.sess.fs.StatPath(target); errors.Is(err, core.ErrNotFound) {
			break
		}
		if i > 999 {
			fail(w, 409, "Kein freier Dateiname")
			return
		}
		target = path.Join(c.sh.Path, fmt.Sprintf("%s (%d)%s", stem, i, ext))
	}
	t, _, err := receiveUpload(r, c.sess, c.sess.fs, target)
	if err != nil {
		failErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1", "name": path.Base(t.Virtual)})
}
