package core

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Was in eine Sicherung gehört. Dateien der Benutzer (Home-Ordner) gehören nicht dazu.
var backupFiles = []string{"sg9.json", "sg9-userstats.json", "sg9-hostkey", "sg9-cert.pem", "sg9-key.pem", "sg9-secret"}

const backupDirLE = "letsencrypt"

// WriteBackup schreibt eine ZIP-Sicherung nach w.
func (s *Store) WriteBackup(w io.Writer) error {
	zw := zip.NewWriter(w)
	add := func(rel string) error {
		b, err := os.ReadFile(filepath.Join(s.DataDir, rel))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		f, err := zw.CreateHeader(&zip.FileHeader{Name: filepath.ToSlash(rel), Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		return err
	}
	s.mu.RLock()
	err := func() error {
		for _, f := range backupFiles {
			if err := add(f); err != nil {
				return err
			}
		}
		return nil
	}()
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	_ = filepath.WalkDir(filepath.Join(s.DataDir, backupDirLE), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(s.DataDir, p)
			_ = add(rel)
		}
		return nil
	})
	info, _ := json.Marshal(map[string]any{"created": time.Now(), "app": "SG9"})
	if f, err := zw.Create("sg9-backup.json"); err == nil {
		f.Write(info)
	}
	return zw.Close()
}

// RestoreBackup prüft eine ZIP-Sicherung und übernimmt sie.
// Danach gilt die Konfiguration sofort; Schlüssel und Zertifikate liegen wieder an ihrem Platz.
func (s *Store) RestoreBackup(data []byte) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return errors.New("Das ist keine gültige SG9-Sicherung (keine ZIP-Datei)")
	}
	allowed := map[string]bool{}
	for _, f := range backupFiles {
		allowed[f] = true
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		name := f.Name
		ok := allowed[name] || (strings.HasPrefix(name, backupDirLE+"/") && !strings.Contains(name, "..") && !strings.HasSuffix(name, "/"))
		if !ok || f.UncompressedSize64 > 50<<20 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 50<<20))
		rc.Close()
		if err != nil {
			return err
		}
		files[name] = b
	}
	raw, ok := files["sg9.json"]
	if !ok {
		return errors.New("In der Sicherung fehlt sg9.json, es ist wohl keine SG9-Sicherung")
	}
	cfg := DefaultConfig(s.DataDir)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("sg9.json in der Sicherung ist beschädigt: %v", err)
	}
	if cfg.Notify.On == nil {
		cfg.Notify.On = append([]string(nil), DefaultNotifyOn...)
	}
	if err := validate(&cfg); err != nil {
		return fmt.Errorf("Die Sicherung passt nicht: %v", err)
	}
	// Erst die übrigen Dateien, dann die Konfiguration (die die Dienste neu startet).
	for name, b := range files {
		if name == "sg9.json" {
			continue
		}
		p := filepath.Join(s.DataDir, filepath.FromSlash(name))
		_ = os.MkdirAll(filepath.Dir(p), 0o750)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return err
		}
	}
	return s.Update(func(c *Config) error { *c = cfg; return nil })
}

// AutoBackup legt einmal am Tag eine Sicherung unter backups/ an und behält die letzten keep.
func (s *Store) AutoBackup(log *Logger, keep int) {
	run := func() {
		dir := filepath.Join(s.DataDir, "backups")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			log.Error("Automatische Sicherung: %v", err)
			return
		}
		name := filepath.Join(dir, "sg9-"+time.Now().Format("2006-01-02")+".zip")
		if _, err := os.Stat(name); err == nil {
			return // heute schon gesichert
		}
		f, err := os.OpenFile(name+".tmp", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			log.Error("Automatische Sicherung: %v", err)
			return
		}
		err = s.WriteBackup(f)
		f.Close()
		if err == nil {
			err = os.Rename(name+".tmp", name)
		}
		if err != nil {
			os.Remove(name + ".tmp")
			log.Error("Automatische Sicherung: %v", err)
			return
		}
		old, _ := filepath.Glob(filepath.Join(dir, "sg9-*.zip"))
		sort.Strings(old)
		for len(old) > keep {
			os.Remove(old[0])
			old = old[1:]
		}
	}
	go func() {
		time.Sleep(time.Minute)
		for {
			run()
			time.Sleep(6 * time.Hour)
		}
	}()
}

// BackupInfo beschreibt eine gespeicherte automatische Sicherung.
type BackupInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
}

// ListBackups liefert die automatischen Sicherungen, neueste zuerst.
func (s *Store) ListBackups() []BackupInfo {
	out := []BackupInfo{}
	files, _ := filepath.Glob(filepath.Join(s.DataDir, "backups", "*.zip"))
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil {
			out = append(out, BackupInfo{Name: filepath.Base(f), Size: fi.Size(), Created: fi.ModTime()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

// ---------- Prüfprotokoll ----------

// AuditEntry ist eine Änderung in der Verwaltung.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	IP     string    `json:"ip"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
}

func (s *Store) auditPath() string { return filepath.Join(s.DataDir, "sg9-audit.log") }

// Audit hängt einen Eintrag an das Prüfprotokoll (eine JSON-Zeile pro Änderung).
func (s *Store) Audit(ip, action, detail string) {
	b, _ := json.Marshal(AuditEntry{Time: time.Now(), IP: ip, Action: action, Detail: detail})
	f, err := os.OpenFile(s.auditPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	f.Write(append(b, '\n'))
	f.Close()
	// Grösse begrenzen: ab 5 MB die ältere Hälfte abschneiden.
	if fi, err := os.Stat(s.auditPath()); err == nil && fi.Size() > 5<<20 {
		if all, err := os.ReadFile(s.auditPath()); err == nil {
			half := all[len(all)/2:]
			if i := bytes.IndexByte(half, '\n'); i >= 0 {
				_ = os.WriteFile(s.auditPath(), half[i+1:], 0o600)
			}
		}
	}
}

// AuditLog liefert die letzten n Einträge, neueste zuerst.
func (s *Store) AuditLog(n int) []AuditEntry {
	b, err := os.ReadFile(s.auditPath())
	out := []AuditEntry{}
	if err != nil {
		return out
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		var e AuditEntry
		if json.Unmarshal([]byte(lines[i]), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}
