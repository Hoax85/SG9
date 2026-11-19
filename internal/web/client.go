package web

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"sg9/internal/core"
	"sg9/internal/ui"
)

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

func failErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrNotFound):
		fail(w, 404, "Nicht gefunden")
	case errors.Is(err, core.ErrDenied):
		fail(w, 403, "Keine Berechtigung")
	case errors.Is(err, core.ErrExists):
		fail(w, 409, "Existiert bereits")
	case errors.Is(err, core.ErrFiltered):
		fail(w, 403, "Dieser Dateityp ist nicht erlaubt")
	case errors.Is(err, core.ErrNotEmpty):
		fail(w, 409, "Ordner ist nicht leer")
	case errors.Is(err, core.ErrQuota):
		fail(w, 507, core.ErrQuota.Error())
	case errors.Is(err, core.ErrRatio):
		fail(w, 403, core.ErrRatio.Error())
	case errors.Is(err, core.ErrInvalid):
		fail(w, 400, "Ungültiger Pfad")
	default:
		fail(w, 500, err.Error())
	}
}

func readJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	return json.NewDecoder(r.Body).Decode(v)
}

type entryJSON struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Dir      bool      `json:"dir"`
}

func toJSON(es []core.Entry) []entryJSON {
	out := make([]entryJSON, 0, len(es))
	for _, e := range es {
		out = append(out, entryJSON{Name: e.Name, Size: e.Size, Modified: e.ModTime, Dir: e.IsDir})
	}
	return out
}

type permsJSON struct {
	List, Read, Write, Delete, Rename, Mkdir, Rmdir bool
}

func permsOut(p core.Permissions) map[string]bool {
	return map[string]bool{"list": p.List, "read": p.Read, "write": p.Write, "delete": p.Delete, "rename": p.Rename, "mkdir": p.MkDir, "rmdir": p.RmDir}
}

// meteredReadSeeker bremst und zählt Downloads, die http.ServeContent liefert.
type meteredReadSeeker struct {
	f *os.File
	m *core.Meter
}

func (r *meteredReadSeeker) Read(p []byte) (int, error) {
	n, err := r.f.Read(p)
	if n > 0 {
		if e := r.m.Before(n); e != nil {
			return 0, e
		}
		r.m.After(n)
	}
	return n, err
}

func (r *meteredReadSeeker) Seek(off int64, whence int) (int64, error) { return r.f.Seek(off, whence) }

// SafeInline: Dateitypen, die im Browser angezeigt werden dürfen.
func SafeInline(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch {
	case ct == "image/svg+xml":
		return false
	case strings.HasPrefix(ct, "image/"), strings.HasPrefix(ct, "video/"), strings.HasPrefix(ct, "audio/"):
		return true
	case ct == "application/pdf", ct == "text/plain":
		return true
	}
	return false
}

func contentDisposition(kind, name string) string {
	ascii := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	return fmt.Sprintf(`%s; filename="%s"; filename*=UTF-8''%s`, kind, ascii, url.PathEscape(name))
}

// sendFile liefert eine Datei aus (mit Range-Unterstützung, Bremse und Zählung).
func sendFile(w http.ResponseWriter, r *http.Request, sess *httpSession, fsys *core.FS, vp string, inline bool) (core.Target, int64, bool) {
	f, t, e, err := fsys.OpenRead(vp)
	if err != nil {
		failErr(w, err)
		return t, 0, false
	}
	defer f.Close()
	x := &core.Xfer{Direction: "down", File: t.Virtual, Size: e.Size, Started: time.Now()}
	m := sess.downMeter(sess.acct, x)
	if m.Ratio == 0 {
		failErr(w, core.ErrRatio)
		return t, 0, false
	}
	sess.addXfer(x)
	defer sess.delXfer(x)
	ct := mime.TypeByExtension(path.Ext(e.Name))
	if ct == "" {
		ct = "application/octet-stream"
	}
	if inline {
		switch strings.ToLower(path.Ext(e.Name)) {
		case ".txt", ".log", ".md", ".csv":
			ct = "text/plain; charset=utf-8" // als reiner Text anzeigen
		}
	}
	kind := "attachment"
	// Direkt anzeigen nur bei Typen, die keine Skripte ausführen können.
	// Eine hochgeladene HTML- oder SVG-Datei würde sonst auf dieser Seite laufen.
	if inline && SafeInline(ct) {
		kind = "inline"
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		if ct == "application/pdf" {
			w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		} else {
			w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'self'")
		}
	}
	w.Header().Set("Content-Disposition", contentDisposition(kind, e.Name))
	w.Header().Set("Content-Type", ct)
	http.ServeContent(w, r, e.Name, e.ModTime, &meteredReadSeeker{f: f, m: m})
	n := x.Bytes.Load()
	full := n >= e.Size && r.Method != http.MethodHead
	if full {
		sess.srv.Hub.AddFile(sess.acct.Name, false)
		sess.log("xfer", "%s-Download %s, %s", sess.protoLabel(), t.Virtual, core.HumanBytes(n))
		sess.event("download", t, n, "")
	}
	return t, n, full
}

// sendZip packt einen Ordner on-the-fly als ZIP.
func sendZip(w http.ResponseWriter, sess *httpSession, fsys *core.FS, vp string) {
	t, e, err := fsys.StatPath(vp)
	if err != nil {
		failErr(w, err)
		return
	}
	if !e.IsDir || !t.Perms.List {
		fail(w, 403, "Nur Ordner mit Leserechten können als ZIP geladen werden")
		return
	}
	name := e.Name
	if t.Virtual == "/" || name == "" || name == "/" {
		name = "dateien"
	}
	x := &core.Xfer{Direction: "down", File: t.Virtual + " (ZIP)", Size: -1, Started: time.Now()}
	m := sess.downMeter(sess.acct, x)
	if m.Ratio == 0 {
		failErr(w, core.ErrRatio)
		return
	}
	sess.addXfer(x)
	defer sess.delXfer(x)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", contentDisposition("attachment", name+".zip"))
	zw := zip.NewWriter(w)
	files := 0
	var walk func(dir core.Target, prefix string, depth int) error
	walk = func(dir core.Target, prefix string, depth int) error {
		if depth > 32 {
			return nil
		}
		entries, err := fsys.List(dir)
		if err != nil {
			return nil
		}
		for _, c := range entries {
			ct, err := fsys.Resolve(path.Join(dir.Virtual, c.Name))
			if err != nil {
				continue
			}
			if c.IsDir {
				if ct.Perms.List {
					if err := walk(ct, prefix+c.Name+"/", depth+1); err != nil {
						return err
					}
				}
				continue
			}
			if !ct.Perms.Read || ct.Real == "" {
				continue
			}
			src, err := os.Open(ct.Real)
			if err != nil {
				continue
			}
			hdr := &zip.FileHeader{Name: prefix + c.Name, Method: zip.Deflate, Modified: c.ModTime}
			dst, err := zw.CreateHeader(hdr)
			if err == nil {
				_, err = m.Copy(dst, src)
			}
			src.Close()
			if err != nil {
				return err
			}
			files++
		}
		return nil
	}
	err = walk(t, "", 0)
	zw.Close()
	if err == nil {
		sess.log("xfer", "%s-ZIP %s, %d Dateien, %s", sess.protoLabel(), t.Virtual, files, core.HumanBytes(x.Bytes.Load()))
		sess.event("download", t, x.Bytes.Load(), "zip")
	}
}

// receiveUpload speichert den Request-Body als Datei.
func receiveUpload(r *http.Request, sess *httpSession, fsys *core.FS, vp string) (core.Target, int64, error) {
	acct := sess.acct
	q := sess.srv.Hub.Quota(acct, false)
	limit := acct.QuotaMB * 1024 * 1024
	if q != nil && limit > 0 && q.Load()+r.ContentLength > limit {
		return core.Target{}, 0, core.ErrQuota
	}
	wr, err := fsys.OpenWrite(vp, core.WriteTruncate)
	if err != nil {
		return wr.Target, 0, err
	}
	if wr.Existed && q != nil {
		q.Add(-wr.OldSize)
	}
	x := &core.Xfer{Direction: "up", File: wr.Target.Virtual, Size: r.ContentLength, Started: time.Now()}
	m := sess.upMeter(acct, x, q, limit)
	sess.addXfer(x)
	defer sess.delXfer(x)
	n, cerr := m.Copy(wr.File, r.Body)
	ferr := wr.File.Close()
	if cerr == nil {
		cerr = ferr
	}
	if cerr != nil {
		if !wr.Existed {
			if os.Remove(wr.Target.Real) == nil && q != nil {
				q.Add(-n)
			}
		}
		return wr.Target, n, cerr
	}
	sess.srv.Hub.AddFile(acct.Name, true)
	sess.log("xfer", "%s-Upload %s, %s", sess.protoLabel(), wr.Target.Virtual, core.HumanBytes(n))
	sess.event("upload", wr.Target, n, "")
	return wr.Target, n, nil
}

// ---------- Browser-Client ----------

func (s *Server) clientRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { ui.ServePage(w, "client.html") })
	mux.HandleFunc("POST /api/login", s.apiLogin)
	mux.HandleFunc("POST /api/logout", s.webAuth(s.apiLogout))
	mux.HandleFunc("GET /api/me", s.webAuth(s.apiMe))
	mux.HandleFunc("GET /api/qr", s.webAuth(func(w http.ResponseWriter, r *http.Request, _ *httpSession) { core.ServeQR(w, r) }))
	mux.HandleFunc("GET /api/ls", s.webAuth(s.apiList))
	mux.HandleFunc("GET /api/dl", s.webAuth(s.apiDownload))
	mux.HandleFunc("GET /api/zip", s.webAuth(s.apiZip))
	mux.HandleFunc("PUT /api/up", s.webAuth(s.apiUpload))
	mux.HandleFunc("POST /api/mkdir", s.webAuth(s.apiMkdir))
	mux.HandleFunc("POST /api/rm", s.webAuth(s.apiRemove))
	mux.HandleFunc("POST /api/mv", s.webAuth(s.apiMove))
	mux.HandleFunc("GET /api/shares", s.webAuth(s.apiShares))
	mux.HandleFunc("POST /api/shares", s.webAuth(s.apiShareCreate))
	mux.HandleFunc("DELETE /api/shares/{id}", s.webAuth(s.apiShareDelete))
}

type webHandler func(w http.ResponseWriter, r *http.Request, sess *httpSession)

func (s *Server) webAuth(next webHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.settings().WebClient {
			fail(w, 404, "Browser-Zugang ist deaktiviert")
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-SG9") != "1" {
			fail(w, 403, "CSRF-Schutz: Header fehlt")
			return
		}
		c, err := r.Cookie("sg9_web")
		if err != nil {
			fail(w, 401, "Nicht angemeldet")
			return
		}
		s.smu.Lock()
		sess := s.sessions["web|"+c.Value]
		s.smu.Unlock()
		if sess == nil {
			fail(w, 401, "Nicht angemeldet")
			return
		}
		// Kontoänderungen (deaktiviert, gelöscht) sofort wirksam machen.
		cfg := s.Hub.Store.Snapshot()
		if u := cfg.FindUser(sess.user); u == nil || !u.Enabled || u.Expired(time.Now()) {
			s.dropSession(sess.key)
			fail(w, 401, "Konto nicht mehr gültig")
			return
		}
		ctx, done := sess.begin(r.Context(), r.Method+" "+r.URL.Path+" "+r.URL.Query().Get("path"))
		defer done()
		next(w, r.WithContext(ctx), sess)
	}
}

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	if !s.settings().WebClient {
		fail(w, 404, "Browser-Zugang ist deaktiviert")
		return
	}
	ip := clientIP(r)
	if err := s.Hub.Admit(ip); err != nil {
		fail(w, 503, err.Error())
		return
	}
	var in struct{ Username, Password string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	acct, err := s.Hub.Login(core.LoginRequest{Name: in.Username, Password: in.Password, IP: ip, Protocol: core.ProtoWeb, Secure: r.TLS != nil})
	if err != nil {
		var le *core.LoginError
		if errors.As(err, &le) && le.Failed {
			time.Sleep(700 * time.Millisecond)
		}
		fail(w, 401, err.Error())
		return
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	sess, err := s.session("web|"+tok, core.ProtoWeb, acct, ip, r.TLS != nil)
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	_ = sess
	http.SetCookie(w, &http.Cookie{Name: "sg9_web", Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	s.dropSession(sess.key)
	sess.log("info", "Web abgemeldet")
	http.SetCookie(w, &http.Cookie{Name: "sg9_web", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	st := s.Hub.Store.Settings()
	a := sess.acct
	out := map[string]any{"user": a.Name, "server": st.ServerName, "shares": st.Web.Shares && a.AllowShares,
		"welcome": strings.ReplaceAll(a.Welcome, "%u", a.Name), "ratio": a.Ratio, "webdav": st.Web.WebDAV && a.AllowsProtocol(core.ProtoWebDAV),
		"davURL": s.PublicBase(r, "dav") + "/dav"}
	if a.Ratio > 0 {
		out["ratioLeft"] = s.Hub.RatioLeft(a)
	}
	if q := s.Hub.Quota(a, false); q != nil {
		out["quotaUsed"] = q.Load()
		out["quotaLimit"] = a.QuotaMB * 1024 * 1024
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiList(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	p := core.CleanVirtual(r.URL.Query().Get("path"))
	t, e, err := sess.fs.StatPath(p)
	if err != nil {
		failErr(w, err)
		return
	}
	if !e.IsDir {
		fail(w, 400, "Kein Ordner")
		return
	}
	if !t.Perms.List {
		fail(w, 403, "Auflisten nicht erlaubt")
		return
	}
	entries, err := sess.fs.List(t)
	if err != nil {
		failErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"path": t.Virtual, "perms": permsOut(t.Perms), "entries": toJSON(entries)})
}

func (s *Server) apiDownload(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	sendFile(w, r, sess, sess.fs, r.URL.Query().Get("path"), r.URL.Query().Get("inline") == "1")
}

func (s *Server) apiZip(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	sendZip(w, sess, sess.fs, r.URL.Query().Get("path"))
}

func (s *Server) apiUpload(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	p := core.CleanVirtual(r.URL.Query().Get("path"))
	if _, _, err := receiveUpload(r, sess, sess.fs, p); err != nil {
		failErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiMkdir(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	var in struct{ Path string }
	if readJSON(r, &in) != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	t, err := sess.fs.Mkdir(in.Path)
	if err != nil {
		failErr(w, err)
		return
	}
	sess.log("info", "Ordner angelegt: %s", t.Virtual)
	sess.event("mkdir", t, 0, "")
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiRemove(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	var in struct{ Paths []string }
	if readJSON(r, &in) != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	for _, p := range in.Paths {
		t, e, err := sess.fs.StatPath(p)
		if err == nil {
			if e.IsDir {
				_, err = sess.fs.Rmdir(p, true)
				if err == nil {
					sess.event("rmdir", t, 0, "")
				}
			} else {
				_, _, err = sess.fs.Remove(p)
				if err == nil {
					if q := s.Hub.Quota(sess.acct, false); q != nil {
						q.Add(-e.Size)
					}
					sess.event("delete", t, e.Size, "")
				}
			}
		}
		if err != nil {
			failErr(w, fmt.Errorf("%s: %w", path.Base(p), err))
			return
		}
		sess.log("info", "Gelöscht: %s", t.Virtual)
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

func (s *Server) apiMove(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	var in struct{ From, To string }
	if readJSON(r, &in) != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	_, dst, err := sess.fs.Rename(in.From, in.To)
	if err != nil {
		failErr(w, err)
		return
	}
	sess.log("info", "Umbenannt: %s -> %s", in.From, dst.Virtual)
	sess.event("rename", dst, 0, in.From)
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

type shareOut struct {
	core.Share
	URL      string `json:"url"`
	Expired  bool   `json:"expired"`
	Password bool   `json:"password"`
}

// ShareView bereitet einen Link für die Anzeige auf.
func ShareView(sh core.Share, base string) shareOut {
	o := shareOut{Share: sh, URL: core.ShareURL(base, sh.ID), Expired: sh.Expired(time.Now()), Password: sh.PasswordHash != ""}
	o.PasswordHash = ""
	return o
}

func (s *Server) apiShares(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	cfg := s.Hub.Store.Snapshot()
	out := []shareOut{}
	for _, sh := range cfg.Shares {
		if strings.EqualFold(sh.Owner, sess.user) {
			out = append(out, ShareView(sh, s.PublicBase(r, "share")))
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiShareCreate(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	if !s.settings().Shares {
		fail(w, 403, "Freigabe-Links sind deaktiviert")
		return
	}
	var in core.ShareRequest
	if readJSON(r, &in) != nil {
		fail(w, 400, "Ungültige Anfrage")
		return
	}
	in.Owner = sess.user
	sh, err := s.Hub.CreateShare(in, false)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, ShareView(sh, s.PublicBase(r, "share")))
}

func (s *Server) apiShareDelete(w http.ResponseWriter, r *http.Request, sess *httpSession) {
	if err := s.Hub.DeleteShare(r.PathValue("id"), sess.user); err != nil {
		fail(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

var _ = io.EOF
