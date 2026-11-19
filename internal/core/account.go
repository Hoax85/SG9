package core

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const pbkdf2Iter = 120000

// HashPassword erzeugt einen PBKDF2-SHA256-Hash.
func HashPassword(pw string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	key, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// CheckPassword prüft ein Passwort gegen einen Hash (zeitkonstant).
func CheckPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1000 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// RandomPassword erzeugt ein lesbares Zufallspasswort.
func RandomPassword(n int) string {
	const chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

// CleanVirtual normalisiert einen virtuellen Pfad auf /a/b-Form.
func CleanVirtual(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

// Account ist das zusammengeführte Ergebnis aus Benutzer + Gruppe.
type Account struct {
	Name           string
	Group          string
	Home           string
	HomePerms      Permissions
	Mounts         []Mount
	DownloadKBps   int
	UploadKBps     int
	MaxConnections int
	QuotaMB        int64
	Ratio          int
	RatioCreditMB  int64
	IPAllow        []string
	IPDeny         []string
	ForceTLS       bool
	Anonymous      bool
	Protocols      []string
	AllowShares    bool
	Welcome        string
	HideFiles      []string
	DenyUpload     []string
	SSHKeys        []string
}

// AllowsProtocol prüft, ob das Konto ein Protokoll nutzen darf.
func (a Account) AllowsProtocol(p string) bool {
	if len(a.Protocols) == 0 {
		return true
	}
	for _, x := range a.Protocols {
		if strings.EqualFold(x, p) {
			return true
		}
	}
	return false
}

// Resolve berechnet die effektiven Einstellungen eines Benutzers.
func (c *Config) Resolve(u *User) Account {
	a := Account{Name: u.Name, Group: u.Group, Anonymous: strings.EqualFold(u.Name, "anonymous")}
	var g *Group
	if u.Group != "" {
		g = c.FindGroup(u.Group)
	}
	pick := func(uv, gv int) int {
		if uv != 0 {
			return uv
		}
		return gv
	}
	pick64 := func(uv, gv int64) int64 {
		if uv != 0 {
			return uv
		}
		return gv
	}
	home := u.Home
	if g != nil {
		if home == "" {
			home = g.Home
		}
		a.HomePerms = g.HomePerms
		a.Mounts = append(a.Mounts, g.Mounts...)
		a.DownloadKBps = g.DownloadKBps
		a.UploadKBps = g.UploadKBps
		a.MaxConnections = g.MaxConnections
		a.QuotaMB = g.QuotaMB
		a.Ratio = g.Ratio
		a.RatioCreditMB = g.RatioCreditMB
		a.IPAllow = append(a.IPAllow, g.IPAllow...)
		a.IPDeny = append(a.IPDeny, g.IPDeny...)
		a.ForceTLS = g.ForceTLS
		a.Protocols = append(a.Protocols, g.Protocols...)
		a.AllowShares = g.AllowShares
		a.Welcome = g.Welcome
		a.HideFiles = append(a.HideFiles, g.HideFiles...)
		a.DenyUpload = append(a.DenyUpload, g.DenyUpload...)
		a.Group = g.Name
	} else {
		a.HomePerms = Permissions{List: true, Read: true}
	}
	if u.HomePerms != nil {
		a.HomePerms = *u.HomePerms
	}
	// Benutzer-Mounts überschreiben gleichnamige Gruppen-Mounts.
	for _, um := range u.Mounts {
		replaced := false
		for i := range a.Mounts {
			if a.Mounts[i].VirtualPath == um.VirtualPath {
				a.Mounts[i] = um
				replaced = true
			}
		}
		if !replaced {
			a.Mounts = append(a.Mounts, um)
		}
	}
	a.DownloadKBps = pick(u.DownloadKBps, a.DownloadKBps)
	a.UploadKBps = pick(u.UploadKBps, a.UploadKBps)
	a.MaxConnections = pick(u.MaxConnections, a.MaxConnections)
	a.QuotaMB = pick64(u.QuotaMB, a.QuotaMB)
	a.Ratio = pick(u.Ratio, a.Ratio)
	a.RatioCreditMB = pick64(u.RatioCreditMB, a.RatioCreditMB)
	a.IPAllow = append(a.IPAllow, u.IPAllow...)
	a.IPDeny = append(a.IPDeny, u.IPDeny...)
	a.ForceTLS = a.ForceTLS || u.ForceTLS
	if len(u.Protocols) > 0 {
		a.Protocols = append([]string(nil), u.Protocols...)
	}
	if u.AllowShares != nil {
		a.AllowShares = *u.AllowShares
	}
	if u.Welcome != "" {
		a.Welcome = u.Welcome
	}
	a.HideFiles = append(a.HideFiles, u.HideFiles...)
	a.DenyUpload = append(a.DenyUpload, u.DenyUpload...)
	a.SSHKeys = append(a.SSHKeys, u.SSHKeys...)
	a.HideFiles = append(a.HideFiles, c.Settings.HideFiles...)
	a.DenyUpload = append(a.DenyUpload, c.Settings.DenyUpload...)
	a.Home = expandHome(home, u.Name)
	for i := range a.Mounts {
		a.Mounts[i].RealPath = expandHome(a.Mounts[i].RealPath, u.Name)
	}
	return a
}

func expandHome(p, user string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "%u", user)
	p = strings.ReplaceAll(p, "%U", user)
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return abs
}

// Expired meldet, ob ein Konto abgelaufen ist.
func (u *User) Expired(now time.Time) bool {
	if u.ExpiresAt == "" {
		return false
	}
	t, err := time.ParseInLocation("2006-01-02", u.ExpiresAt, time.Local)
	if err != nil {
		return false
	}
	return now.After(t.Add(24 * time.Hour))
}

// EnsureHome legt den Home-Ordner an, falls er noch fehlt (z. B. vor der ersten Anmeldung).
func (a Account) EnsureHome() error {
	if a.Home == "" {
		return nil
	}
	return os.MkdirAll(a.Home, 0o750)
}
