package main

// Ende-zu-Ende-Test: startet SG9 mit allen Diensten auf freien Ports und spricht
// FTP, SFTP, WebDAV, den Browser-Zugang, die Verwaltung und Freigabe-Links an.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"sg9/internal/core"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type env struct {
	dir                                string
	ftp, sftp, web, admin              int
	stop                               chan struct{}
	user, pass, adminPass, serverShare string
}

func startServer(t *testing.T) *env {
	t.Helper()
	e := &env{dir: t.TempDir(), user: "anna", pass: "annapass123", adminPass: "adminpass123", stop: make(chan struct{})}
	e.ftp, e.sftp, e.web, e.admin = freePort(t), freePort(t), freePort(t), freePort(t)
	store, created, err := core.OpenStore(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	e.serverShare = filepath.Join(e.dir, "freigabe")
	os.MkdirAll(e.serverShare, 0o755)
	os.WriteFile(filepath.Join(e.serverShare, "bild.jpg"), []byte("\xff\xd8\xff\xe0 kein echtes Bild"), 0o644)
	os.WriteFile(filepath.Join(e.serverShare, "seite.html"), []byte("<script>alert(1)</script>"), 0o644)
	pmin := 52000 + os.Getpid()%2000
	err = store.Update(func(c *core.Config) error {
		s := &c.Settings
		s.LogFile = filepath.Join(e.dir, "sg9.log")
		s.UpdateCheckOff = true
		s.FTPEnabled = true
		s.ListenAddr = fmt.Sprintf("127.0.0.1:%d", e.ftp)
		s.PassivePortMin, s.PassivePortMax = pmin, pmin+20
		s.SFTP.Enabled = true
		s.SFTP.ListenAddr = fmt.Sprintf("127.0.0.1:%d", e.sftp)
		s.Web.Enabled, s.Web.WebClient, s.Web.WebDAV, s.Web.Shares = true, true, true, true
		s.Web.ListenAddr = fmt.Sprintf("127.0.0.1:%d", e.web)
		s.Web.DavAddr, s.Web.ShareAddr = "", ""
		s.Admin.ListenAddr = fmt.Sprintf("127.0.0.1:%d", e.admin)
		s.Admin.PasswordHash = core.HashPassword(e.adminPass)
		s.Admin.LocalNoLogin = false
		c.Users = append(c.Users, core.User{Name: e.user, PasswordHash: core.HashPassword(e.pass), Enabled: true, Group: "Standard"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	go serve(store, e.dir, created, true, e.stop)
	for _, p := range []int{e.ftp, e.sftp, e.web, e.admin} {
		ok := false
		for i := 0; i < 100 && !ok; i++ {
			if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
				c.Close()
				ok = true
			} else {
				time.Sleep(30 * time.Millisecond)
			}
		}
		if !ok {
			t.Fatalf("Port %d antwortet nicht", p)
		}
	}
	t.Cleanup(func() { close(e.stop); time.Sleep(100 * time.Millisecond) })
	return e
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("kurz")
	}
	e := startServer(t)
	content := []byte("Hallo von SG9 – " + time.Now().String())

	t.Run("FTP", func(t *testing.T) { testFTP(t, e, content) })
	t.Run("SFTP", func(t *testing.T) { testSFTP(t, e, content) })
	t.Run("WebDAV", func(t *testing.T) { testDAV(t, e, content) })
	t.Run("Verwaltung und Links", func(t *testing.T) { testShares(t, e) })
	t.Run("Falsches Passwort", func(t *testing.T) {
		c, err := textproto.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.ftp))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.ReadResponse(220)
		c.Cmd("USER %s", e.user)
		c.ReadResponse(331)
		c.Cmd("PASS falsch")
		if _, _, err := c.ReadResponse(230); err == nil {
			t.Fatal("Anmeldung mit falschem Passwort darf nicht klappen")
		}
	})
}

// --- FTP ---------------------------------------------------------------

func ftpData(t *testing.T, c *textproto.Conn) net.Conn {
	t.Helper()
	id, _ := c.Cmd("EPSV")
	c.StartResponse(id)
	_, msg, err := c.ReadResponse(229)
	c.EndResponse(id)
	if err != nil {
		t.Fatalf("EPSV: %v", err)
	}
	var port int
	if i := strings.Index(msg, "(|||"); i >= 0 {
		fmt.Sscanf(msg[i+4:], "%d", &port)
	}
	d, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("Datenverbindung: %v", err)
	}
	return d
}

func cmd(t *testing.T, c *textproto.Conn, code int, format string, args ...any) string {
	t.Helper()
	id, err := c.Cmd(format, args...)
	if err != nil {
		t.Fatal(err)
	}
	c.StartResponse(id)
	defer c.EndResponse(id)
	_, msg, err := c.ReadResponse(code)
	if err != nil {
		t.Fatalf("%s: %v", strings.Fields(format)[0], err)
	}
	return msg
}

func testFTP(t *testing.T, e *env, content []byte) {
	c, err := textproto.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.ftp))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, _, err := c.ReadResponse(220); err != nil {
		t.Fatal(err)
	}
	cmd(t, c, 331, "USER %s", e.user)
	cmd(t, c, 230, "PASS %s", e.pass)
	cmd(t, c, 200, "TYPE I")
	cmd(t, c, 257, "MKD ordner")

	d := ftpData(t, c)
	cmd(t, c, 150, "STOR ordner/hallo.txt")
	d.Write(content)
	d.Close()
	if _, _, err := c.ReadResponse(226); err != nil {
		t.Fatalf("STOR: %v", err)
	}

	d = ftpData(t, c)
	cmd(t, c, 150, "NLST ordner")
	list, _ := io.ReadAll(d)
	d.Close()
	c.ReadResponse(226)
	if !strings.Contains(string(list), "hallo.txt") {
		t.Fatalf("NLST enthält die Datei nicht: %q", list)
	}

	d = ftpData(t, c)
	cmd(t, c, 150, "RETR ordner/hallo.txt")
	got, _ := io.ReadAll(d)
	d.Close()
	c.ReadResponse(226)
	if !bytes.Equal(got, content) {
		t.Fatalf("RETR liefert %q", got)
	}

	// Aus dem Home-Ordner ausbrechen darf nicht gehen
	d = ftpData(t, c)
	id, _ := c.Cmd("RETR ../../sg9.json")
	c.StartResponse(id)
	_, _, err = c.ReadResponse(150)
	c.EndResponse(id)
	d.Close()
	if err == nil {
		t.Fatal("RETR ../../sg9.json darf nicht klappen")
	}
	cmd(t, c, 221, "QUIT")
}

// --- SFTP --------------------------------------------------------------

func testSFTP(t *testing.T, e *env, content []byte) {
	cfg := &ssh.ClientConfig{User: e.user, Auth: []ssh.AuthMethod{ssh.Password(e.pass)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second}
	conn, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.sftp), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cl, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	f, err := cl.Open("/ordner/hallo.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(f)
	f.Close()
	if !bytes.Equal(got, content) {
		t.Fatalf("SFTP liest %q", got)
	}
	w, err := cl.Create("/ordner/sftp.txt")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("über SFTP"))
	w.Close()
	if err := cl.Rename("/ordner/sftp.txt", "/ordner/umbenannt.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Stat("/ordner/umbenannt.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Open("/../sg9.json"); err == nil {
		t.Fatal("SFTP darf nicht aus dem Home-Ordner heraus")
	}
	// Eine Shell gibt es nicht: SG9 meldet das und beendet die Sitzung mit Status 1
	s, err := conn.NewSession()
	if err == nil {
		out, err := s.CombinedOutput("id")
		if err == nil || !strings.Contains(string(out), "keine Shell") {
			t.Errorf("Befehl ausgeführt? %q %v", out, err)
		}
	}
}

// --- WebDAV ------------------------------------------------------------

func testDAV(t *testing.T, e *env, content []byte) {
	base := fmt.Sprintf("http://127.0.0.1:%d/dav", e.web)
	do := func(method, path string, body io.Reader, hdr ...string) *http.Response {
		req, _ := http.NewRequest(method, base+path, body)
		req.SetBasicAuth(e.user, e.pass)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := do("GET", "/ordner/hallo.txt", nil)
	got, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !bytes.Equal(got, content) {
		t.Fatalf("GET %d %q", r.StatusCode, got)
	}
	r = do("PUT", "/ordner/dav.txt", strings.NewReader("per WebDAV"))
	r.Body.Close()
	if r.StatusCode != 201 && r.StatusCode != 204 {
		t.Fatalf("PUT %d", r.StatusCode)
	}
	r = do("PROPFIND", "/ordner/", nil, "Depth", "1")
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 207 || !strings.Contains(string(body), "dav.txt") || !strings.Contains(string(body), "umbenannt.txt") {
		t.Fatalf("PROPFIND %d: %s", r.StatusCode, body)
	}
	req, _ := http.NewRequest("GET", base+"/ordner/hallo.txt", nil)
	req.SetBasicAuth(e.user, "falsch")
	r, _ = http.DefaultClient.Do(req)
	r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("falsches Passwort: %d statt 401", r.StatusCode)
	}
}

// --- Verwaltung und Freigabe-Links -------------------------------------

func testShares(t *testing.T, e *env) {
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar}
	adm := fmt.Sprintf("http://127.0.0.1:%d", e.admin)
	call := func(method, path string, in any, out any) int {
		var body io.Reader
		if in != nil {
			b, _ := json.Marshal(in)
			body = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, adm+path, body)
		req.Header.Set("X-SG9", "1")
		req.Header.Set("Content-Type", "application/json")
		r, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		if out != nil {
			json.NewDecoder(r.Body).Decode(out)
		}
		return r.StatusCode
	}
	if code := call("GET", "/api/users", nil, nil); code != 401 {
		t.Fatalf("ohne Anmeldung: %d statt 401", code)
	}
	if code := call("POST", "/api/login", map[string]string{"username": "admin", "password": "falsch"}, nil); code == 200 {
		t.Fatal("falsches Admin-Passwort akzeptiert")
	}
	if code := call("POST", "/api/login", map[string]string{"username": "admin", "password": e.adminPass}, nil); code != 200 {
		t.Fatalf("Anmeldung: %d", code)
	}
	// Ohne X-SG9-Header (CSRF) wird nichts geändert
	req, _ := http.NewRequest("POST", adm+"/api/shares", strings.NewReader(`{"serverPath":"/"}`))
	if r, _ := cl.Do(req); r.StatusCode == 200 {
		t.Fatal("Anfrage ohne CSRF-Header wurde angenommen")
	}

	var dl, box struct{ ID, URL string }
	if code := call("POST", "/api/shares", map[string]any{"serverPath": e.serverShare}, &dl); code != 200 || dl.ID == "" {
		t.Fatalf("Link anlegen: %d", code)
	}
	boxDir := filepath.Join(e.dir, "briefkasten")
	os.MkdirAll(boxDir, 0o755)
	if code := call("POST", "/api/shares", map[string]any{"serverPath": boxDir, "upload": true}, &box); code != 200 {
		t.Fatalf("Briefkasten anlegen: %d", code)
	}

	web := fmt.Sprintf("http://127.0.0.1:%d/s/", e.web)
	get := func(url string) (*http.Response, []byte) {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("X-SG9", "1")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		return r, b
	}
	r, b := get(web + dl.ID + "/ls?path=/")
	if r.StatusCode != 200 || !strings.Contains(string(b), "bild.jpg") {
		t.Fatalf("Link-Liste %d: %s", r.StatusCode, b)
	}
	// Vorschau: Bild direkt, HTML nie
	r, _ = get(web + dl.ID + "/dl?inline=1&path=/bild.jpg")
	if !strings.HasPrefix(r.Header.Get("Content-Disposition"), "inline") {
		t.Errorf("Bild sollte inline kommen: %s", r.Header.Get("Content-Disposition"))
	}
	r, _ = get(web + dl.ID + "/dl?inline=1&path=/seite.html")
	if !strings.HasPrefix(r.Header.Get("Content-Disposition"), "attachment") {
		t.Errorf("HTML darf nie inline kommen: %s", r.Header.Get("Content-Disposition"))
	}
	r, _ = get(web + dl.ID + "/dl?path=/../../sg9.json")
	if r.StatusCode == 200 {
		t.Fatal("Link darf nicht aus dem Ordner heraus")
	}

	// Briefkasten mit Absender
	put := func(name, from, body string) int {
		req, _ := http.NewRequest("PUT", web+box.ID+"/up?name="+name+"&from="+from, strings.NewReader(body))
		req.Header.Set("X-SG9", "1")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if code := put("rechnung.pdf", "Anna%20M%C3%BCller", "%PDF"); code != 200 {
		t.Fatalf("Briefkasten-Upload: %d", code)
	}
	put("rechnung.pdf", "Anna%20M%C3%BCller", "%PDF 2")
	put("..%2F..%2Fboese.txt", "..%2F..", "x")
	for _, want := range []string{"Anna Müller/rechnung.pdf", "Anna Müller/rechnung (1).pdf", "boese.txt"} {
		if _, err := os.Stat(filepath.Join(boxDir, want)); err != nil {
			t.Errorf("%s fehlt im Briefkasten", want)
		}
	}
	if _, err := os.Stat(filepath.Join(e.dir, "boese.txt")); err == nil {
		t.Error("Upload ist aus dem Briefkasten ausgebrochen")
	}
	r, _ = get(web + box.ID + "/ls?path=/")
	if r.StatusCode == 200 {
		t.Error("Briefkasten darf seinen Inhalt nicht zeigen")
	}

	// QR-Code und Prüfprotokoll
	req, _ = http.NewRequest("GET", adm+"/api/qr?text="+dl.URL, nil)
	if r, _ := cl.Do(req); r.StatusCode != 200 || r.Header.Get("Content-Type") != "image/svg+xml" {
		t.Errorf("QR-Code: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	var audit []map[string]any
	call("GET", "/api/audit", nil, &audit)
	if len(audit) == 0 {
		t.Error("Prüfprotokoll ist leer, obwohl Links angelegt wurden")
	}
	// Übersetzungen werden ausgeliefert
	r, b = get(fmt.Sprintf("http://127.0.0.1:%d/assets/i18n/fr.json", e.web))
	if r.StatusCode != 200 || !strings.Contains(string(b), "Enregistrer") {
		t.Error("französische Übersetzung fehlt")
	}
}
