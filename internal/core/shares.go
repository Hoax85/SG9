package core

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ShareRequest beschreibt einen neuen Freigabe-Link.
type ShareRequest struct {
	Owner        string `json:"owner"`
	Path         string `json:"path"`
	Comment      string `json:"comment"`
	ExpiresAt    string `json:"expiresAt"`
	Password     string `json:"password"`
	MaxDownloads int    `json:"maxDownloads"`
	Upload       bool   `json:"upload"`
	ServerPath   string `json:"serverPath"` // nur Verwaltung: Datei oder Ordner direkt auf dem Server
}

// ShareAccount liefert das Konto, unter dem ein Link läuft.
// Links auf Server-Ordner bekommen ein eigenes, eng begrenztes Konto.
func (c *Config) ShareAccount(sh *Share) (Account, bool) {
	if sh.RealPath != "" {
		perms := Permissions{List: true, Read: true}
		if sh.Upload {
			perms = Permissions{Write: true, MkDir: true}
		}
		a := Account{Name: "", Home: sh.RealPath, HomePerms: perms,
			HideFiles: append([]string(nil), c.Settings.HideFiles...), DenyUpload: append([]string(nil), c.Settings.DenyUpload...)}
		if fi, err := os.Stat(sh.RealPath); err != nil || !fi.IsDir() {
			return a, false
		}
		return a, true
	}
	u := c.FindUser(sh.Owner)
	if u == nil || !u.Enabled || u.Expired(time.Now()) {
		return Account{}, false
	}
	return c.Resolve(u), true
}

// createServerShare legt einen Link direkt auf einen Ordner oder eine Datei des Servers an.
func (h *Hub) createServerShare(r ShareRequest) (Share, error) {
	p := filepath.Clean(strings.TrimSpace(r.ServerPath))
	if !filepath.IsAbs(p) {
		return Share{}, errors.New("Bitte einen vollständigen Pfad auf dem Server wählen")
	}
	fi, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return Share{}, fmt.Errorf("SG9 darf %s nicht lesen. Läuft SG9 als Dienst, fehlen ihm die Rechte für diesen Ordner", p)
		}
		return Share{}, fmt.Errorf("%s gibt es nicht", p)
	}
	sh := Share{ID: NewShareID(), Owner: "", Comment: strings.TrimSpace(r.Comment), Created: time.Now(),
		ExpiresAt: r.ExpiresAt, MaxDownloads: r.MaxDownloads, Upload: r.Upload}
	if fi.IsDir() {
		if _, err := os.ReadDir(p); err != nil {
			return Share{}, fmt.Errorf("SG9 darf den Ordner %s nicht lesen. Läuft SG9 als Dienst, fehlen ihm die Rechte dafür", p)
		}
		sh.RealPath, sh.Path = p, "/"
	} else {
		if r.Upload {
			return Share{}, errors.New("Ein Briefkasten braucht einen Ordner, keine Datei")
		}
		f, err := os.Open(p)
		if err != nil {
			return Share{}, fmt.Errorf("SG9 darf die Datei %s nicht lesen. Läuft SG9 als Dienst, fehlen ihm die Rechte dafür", p)
		}
		f.Close()
		sh.RealPath, sh.Path = filepath.Dir(p), "/"+filepath.Base(p)
	}
	if r.Upload {
		if f, err := os.CreateTemp(sh.RealPath, ".sg9-test-*"); err != nil {
			return Share{}, fmt.Errorf("SG9 darf in %s nicht schreiben, ein Briefkasten geht dort nicht", p)
		} else {
			f.Close()
			os.Remove(f.Name())
		}
	}
	if r.Password != "" {
		sh.PasswordHash = HashPassword(r.Password)
	}
	if err := h.Store.Update(func(c *Config) error { c.Shares = append(c.Shares, sh); return nil }); err != nil {
		return Share{}, err
	}
	h.Log.Info("Freigabe-Link %s für Server-Pfad %s angelegt", sh.ID, p)
	h.Fire(EventData{Event: "share", Protocol: ProtoShare, Path: p, Extra: "created " + sh.ID})
	return sh, nil
}

// NewShareID erzeugt eine zufällige, URL-taugliche ID.
func NewShareID() string {
	const chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

// CreateShare prüft Rechte und legt einen Freigabe-Link an.
func (h *Hub) CreateShare(r ShareRequest, byAdmin bool) (Share, error) {
	if r.ExpiresAt != "" {
		if _, err := time.Parse("2006-01-02", r.ExpiresAt); err != nil {
			return Share{}, errors.New("Ablaufdatum ungültig (JJJJ-MM-TT)")
		}
	}
	if byAdmin && strings.TrimSpace(r.ServerPath) != "" {
		return h.createServerShare(r)
	}
	cfg := h.Store.Snapshot()
	u := cfg.FindUser(r.Owner)
	if u == nil {
		return Share{}, errors.New("Benutzer existiert nicht")
	}
	a := cfg.Resolve(u)
	if !byAdmin && !a.AllowShares {
		return Share{}, errors.New("Freigabe-Links sind für dieses Konto nicht erlaubt")
	}
	if r.ExpiresAt != "" {
		if _, err := time.Parse("2006-01-02", r.ExpiresAt); err != nil {
			return Share{}, errors.New("Ablaufdatum ungültig (JJJJ-MM-TT)")
		}
	}
	_ = a.EnsureHome()
	fs := NewFS(a, cfg.Settings.FollowSymlinks)
	t, e, err := fs.StatPath(r.Path)
	if err != nil {
		return Share{}, fmt.Errorf("Pfad %s: %w", r.Path, err)
	}
	if r.Upload {
		if !e.IsDir {
			return Share{}, errors.New("Ein Briefkasten braucht einen Ordner")
		}
		if !t.Perms.Write {
			return Share{}, errors.New("Keine Schreibrechte in diesem Ordner")
		}
	} else if !t.Perms.Read || (e.IsDir && !t.Perms.List) {
		return Share{}, errors.New("Keine Leserechte für diesen Pfad")
	}
	sh := Share{ID: NewShareID(), Owner: u.Name, Path: t.Virtual, Comment: strings.TrimSpace(r.Comment), Created: time.Now(),
		ExpiresAt: r.ExpiresAt, MaxDownloads: r.MaxDownloads, Upload: r.Upload}
	if r.Password != "" {
		sh.PasswordHash = HashPassword(r.Password)
	}
	if err := h.Store.Update(func(c *Config) error { c.Shares = append(c.Shares, sh); return nil }); err != nil {
		return Share{}, err
	}
	kind := "Download"
	if sh.Upload {
		kind = "Briefkasten"
	}
	h.Log.Info("Freigabe-Link %s (%s) für %s:%s angelegt", sh.ID, kind, sh.Owner, sh.Path)
	h.Fire(EventData{Event: "share", User: sh.Owner, Protocol: ProtoShare, Path: sh.Path, Extra: "created " + sh.ID})
	return sh, nil
}

// DeleteShare entfernt einen Link (owner leer = egal wem er gehört).
func (h *Hub) DeleteShare(id, owner string) error {
	return h.Store.Update(func(c *Config) error {
		for i, s := range c.Shares {
			if s.ID == id && (owner == "" || strings.EqualFold(s.Owner, owner)) {
				c.Shares = append(c.Shares[:i], c.Shares[i+1:]...)
				return nil
			}
		}
		return errors.New("Freigabe nicht gefunden")
	})
}

// CountShareDownload erhöht den Download-Zähler eines Links.
func (h *Hub) CountShareDownload(id string) {
	_ = h.Store.UpdateQuiet(func(c *Config) error {
		if s := c.FindShare(id); s != nil {
			s.Downloads++
		}
		return nil
	})
}

// ShareURL baut den öffentlichen Link.
func ShareURL(base, id string) string {
	return strings.TrimRight(base, "/") + "/s/" + id
}
