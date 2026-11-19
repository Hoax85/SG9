package core

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Fehler des virtuellen Dateisystems.
var (
	ErrDenied   = errors.New("Zugriff verweigert")
	ErrNotFound = errors.New("Datei oder Ordner nicht gefunden")
	ErrExists   = errors.New("existiert bereits")
	ErrInvalid  = errors.New("ungültiger Pfad")
	ErrFiltered = errors.New("Dateityp nicht erlaubt")
	ErrNotEmpty = errors.New("Ordner ist nicht leer")
)

// FS bildet virtuelle Pfade eines Kontos auf echte Pfade ab (Home + virtuelle Ordner)
// und prüft dabei Rechte und Dateifilter. Alle Protokolle nutzen es gemeinsam.
type FS struct {
	home           string
	homePerms      Permissions
	mounts         []Mount // nach Länge absteigend sortiert
	followSymlinks bool
	hide           []string
	denyUpload     []string
}

// Target ist ein aufgelöster Pfad.
type Target struct {
	Virtual string
	Real    string // leer bei rein virtuellen Zwischenordnern
	Root    string
	Perms   Permissions
	IsMount bool // genau ein Mountpunkt
}

// Entry ist ein Verzeichniseintrag.
type Entry struct {
	Name    string
	Size    int64
	Mode    fs.FileMode
	ModTime time.Time
	IsDir   bool
}

// NewFS erzeugt das Dateisystem eines Kontos.
func NewFS(a Account, follow bool) *FS {
	v := &FS{home: a.Home, homePerms: a.HomePerms, followSymlinks: follow}
	v.mounts = append(v.mounts, a.Mounts...)
	sort.Slice(v.mounts, func(i, j int) bool { return len(v.mounts[i].VirtualPath) > len(v.mounts[j].VirtualPath) })
	for _, p := range a.HideFiles {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			v.hide = append(v.hide, p)
		}
	}
	for _, p := range a.DenyUpload {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			v.denyUpload = append(v.denyUpload, p)
		}
	}
	return v
}

func matchAny(patterns []string, name string) bool {
	name = strings.ToLower(name)
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// Hidden meldet, ob ein Name ausgeblendet ist.
func (v *FS) Hidden(name string) bool { return matchAny(v.hide, name) }

// UploadDenied meldet, ob ein Dateiname nicht hochgeladen werden darf.
func (v *FS) UploadDenied(name string) bool { return matchAny(v.denyUpload, name) }

func hasPrefixPath(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// Resolve wandelt einen virtuellen Pfad um.
func (v *FS) Resolve(vp string) (Target, error) {
	vp = CleanVirtual(vp)
	t := Target{Virtual: vp}
	if len(v.hide) > 0 {
		for _, seg := range strings.Split(vp, "/") {
			if seg != "" && v.Hidden(seg) {
				return t, ErrNotFound
			}
		}
	}
	for _, m := range v.mounts {
		if hasPrefixPath(vp, m.VirtualPath) {
			rel := strings.TrimPrefix(vp, m.VirtualPath)
			t.Root = filepath.Clean(m.RealPath)
			t.Real = filepath.Join(t.Root, filepath.FromSlash(rel))
			t.Perms = m.Perms
			t.IsMount = rel == ""
			return t, v.checkInside(t)
		}
	}
	if v.home == "" {
		if vp == "/" || v.isVirtualParent(vp) {
			t.Perms = Permissions{List: true}
			return t, nil
		}
		return t, ErrNotFound
	}
	t.Root = filepath.Clean(v.home)
	t.Real = filepath.Join(t.Root, filepath.FromSlash(vp))
	t.Perms = v.homePerms
	return t, v.checkInside(t)
}

// checkInside verhindert Ausbrüche über symbolische Links.
func (v *FS) checkInside(t Target) error {
	if v.followSymlinks || t.Real == "" {
		return nil
	}
	p := t.Real
	for {
		if _, err := os.Lstat(p); err == nil {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
	realP, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil
	}
	rootReal, err := filepath.EvalSymlinks(t.Root)
	if err != nil {
		rootReal = t.Root
	}
	rel, err := filepath.Rel(rootReal, realP)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ErrDenied
	}
	return nil
}

func (v *FS) isVirtualParent(vp string) bool {
	for _, m := range v.mounts {
		if vp == "/" || strings.HasPrefix(m.VirtualPath, vp+"/") {
			return true
		}
	}
	return false
}

func entryFromInfo(name string, fi fs.FileInfo) Entry {
	return Entry{Name: name, Size: fi.Size(), Mode: fi.Mode(), ModTime: fi.ModTime(), IsDir: fi.IsDir()}
}

func virtualDirEntry(name string) Entry {
	return Entry{Name: name, Mode: fs.ModeDir | 0o755, ModTime: time.Now(), IsDir: true}
}

func (v *FS) osStat(p string) (fs.FileInfo, error) {
	if v.followSymlinks {
		return os.Stat(p)
	}
	fi, err := os.Lstat(p)
	if err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return os.Stat(p)
	}
	return fi, err
}

// Stat liefert Infos zu einem Ziel (auch rein virtuelle Ordner).
func (v *FS) Stat(t Target) (Entry, error) {
	name := path.Base(t.Virtual)
	if t.Real != "" {
		fi, err := v.osStat(t.Real)
		if err == nil {
			e := entryFromInfo(name, fi)
			if t.IsMount {
				e.IsDir = fi.IsDir()
			}
			return e, nil
		}
		if !v.isVirtualParent(t.Virtual) {
			return Entry{}, ErrNotFound
		}
	}
	if t.Virtual == "/" || v.isVirtualParent(t.Virtual) {
		return virtualDirEntry(name), nil
	}
	return Entry{}, ErrNotFound
}

// StatPath ist Resolve + Stat.
func (v *FS) StatPath(vp string) (Target, Entry, error) {
	t, err := v.Resolve(vp)
	if err != nil {
		return t, Entry{}, err
	}
	e, err := v.Stat(t)
	return t, e, err
}

// List liefert den Inhalt eines Ordners inklusive virtueller Unterordner.
func (v *FS) List(t Target) ([]Entry, error) {
	seen := map[string]bool{}
	var out []Entry
	realOK := false
	if t.Real != "" {
		des, err := os.ReadDir(t.Real)
		if err == nil {
			realOK = true
			for _, de := range des {
				if v.Hidden(de.Name()) {
					continue
				}
				childT, err := v.Resolve(path.Join(t.Virtual, de.Name()))
				if err != nil || childT.Real == "" {
					continue
				}
				fi, err := v.osStat(childT.Real)
				if err != nil {
					continue
				}
				out = append(out, entryFromInfo(de.Name(), fi))
				seen[de.Name()] = true
			}
		}
	}
	prefix := t.Virtual
	if prefix != "/" {
		prefix += "/"
	}
	for _, m := range v.mounts {
		if !strings.HasPrefix(m.VirtualPath, prefix) {
			continue
		}
		rest := strings.TrimPrefix(m.VirtualPath, prefix)
		name := strings.SplitN(rest, "/", 2)[0]
		if name == "" || seen[name] || v.Hidden(name) {
			continue
		}
		seen[name] = true
		if !strings.Contains(rest, "/") {
			if fi, err := os.Stat(m.RealPath); err == nil {
				e := entryFromInfo(name, fi)
				e.IsDir = true
				out = append(out, e)
				continue
			}
		}
		out = append(out, virtualDirEntry(name))
	}
	if !realOK && len(out) == 0 && !(t.Virtual == "/" || v.isVirtualParent(t.Virtual)) {
		return nil, ErrNotFound
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// ListPath prüft das Auflisten-Recht und liefert den Inhalt.
func (v *FS) ListPath(vp string) (Target, []Entry, error) {
	t, e, err := v.StatPath(vp)
	if err != nil {
		return t, nil, err
	}
	if !e.IsDir {
		return t, []Entry{e}, nil
	}
	if !t.Perms.List {
		return t, nil, ErrDenied
	}
	l, err := v.List(t)
	return t, l, err
}

// ChildPerms liefert die Rechte eines Eintrags in einem Ordner.
func (v *FS) ChildPerms(dir Target, name string) Permissions {
	if ct, err := v.Resolve(path.Join(dir.Virtual, name)); err == nil {
		return ct.Perms
	}
	return dir.Perms
}

// ---------- Operationen mit Rechteprüfung ----------

// OpenRead öffnet eine Datei zum Lesen.
func (v *FS) OpenRead(vp string) (*os.File, Target, Entry, error) {
	t, e, err := v.StatPath(vp)
	if err != nil {
		return nil, t, e, err
	}
	if e.IsDir {
		return nil, t, e, ErrInvalid
	}
	if !t.Perms.Read {
		return nil, t, e, ErrDenied
	}
	f, err := os.Open(t.Real)
	if err != nil {
		return nil, t, e, mapOSErr(err)
	}
	return f, t, e, nil
}

// WriteMode legt fest, wie eine Datei geschrieben wird.
type WriteMode int

// Schreibarten.
const (
	WriteTruncate WriteMode = iota // neu oder überschreiben
	WriteAppend                    // anhängen
	WriteAt                        // an Position schreiben (Fortsetzen)
)

// WriteResult beschreibt eine geöffnete Zieldatei.
type WriteResult struct {
	File    *os.File
	Target  Target
	Existed bool
	OldSize int64
}

// OpenWrite öffnet eine Datei zum Schreiben mit Rechte- und Filterprüfung.
func (v *FS) OpenWrite(vp string, mode WriteMode) (WriteResult, error) {
	var r WriteResult
	t, err := v.Resolve(vp)
	if err != nil {
		return r, err
	}
	r.Target = t
	if t.Real == "" || t.IsMount || t.Virtual == "/" {
		return r, ErrInvalid
	}
	if v.UploadDenied(path.Base(t.Virtual)) {
		return r, ErrFiltered
	}
	fi, statErr := os.Stat(t.Real)
	r.Existed = statErr == nil
	if r.Existed {
		if fi.IsDir() {
			return r, ErrExists
		}
		r.OldSize = fi.Size()
	}
	switch {
	case mode != WriteTruncate && !t.Perms.Append:
		return r, ErrDenied
	case mode == WriteTruncate && !t.Perms.Write:
		return r, ErrDenied
	case mode == WriteTruncate && r.Existed && !t.Perms.Delete && !t.Perms.Append:
		return r, ErrDenied // Überschreiben braucht zusätzlich Löschen oder Anhängen
	}
	flags := os.O_WRONLY | os.O_CREATE
	switch mode {
	case WriteTruncate:
		flags |= os.O_TRUNC
	case WriteAppend:
		flags |= os.O_APPEND
	}
	f, err := os.OpenFile(t.Real, flags, 0o644)
	if err != nil {
		return r, mapOSErr(err)
	}
	r.File = f
	return r, nil
}

// Remove löscht eine Datei.
func (v *FS) Remove(vp string) (Target, Entry, error) {
	t, e, err := v.StatPath(vp)
	if err != nil {
		return t, e, err
	}
	if e.IsDir {
		return t, e, ErrInvalid
	}
	if !t.Perms.Delete {
		return t, e, ErrDenied
	}
	return t, e, mapOSErr(os.Remove(t.Real))
}

// Mkdir legt einen Ordner an.
func (v *FS) Mkdir(vp string) (Target, error) {
	t, err := v.Resolve(vp)
	if err != nil {
		return t, err
	}
	if t.Real == "" || t.IsMount {
		return t, ErrInvalid
	}
	if !t.Perms.MkDir {
		return t, ErrDenied
	}
	return t, mapOSErr(os.Mkdir(t.Real, 0o755))
}

// Rmdir löscht einen leeren Ordner (oder mit recursive einen ganzen Baum).
func (v *FS) Rmdir(vp string, recursive bool) (Target, error) {
	t, e, err := v.StatPath(vp)
	if err != nil {
		return t, err
	}
	if t.Real == "" || t.IsMount || t.Virtual == "/" || !e.IsDir {
		return t, ErrInvalid
	}
	if !t.Perms.RmDir || (recursive && !t.Perms.Delete) {
		return t, ErrDenied
	}
	if recursive {
		return t, mapOSErr(os.RemoveAll(t.Real))
	}
	if err := os.Remove(t.Real); err != nil {
		if des, _ := os.ReadDir(t.Real); len(des) > 0 {
			return t, ErrNotEmpty
		}
		return t, mapOSErr(err)
	}
	return t, nil
}

// Rename benennt um oder verschiebt.
func (v *FS) Rename(from, to string) (Target, Target, error) {
	src, _, err := v.StatPath(from)
	if err != nil {
		return src, Target{}, err
	}
	dst, err := v.Resolve(to)
	if err != nil {
		return src, dst, err
	}
	if src.Real == "" || src.IsMount || src.Virtual == "/" || dst.Real == "" || dst.IsMount {
		return src, dst, ErrInvalid
	}
	if !src.Perms.Rename || !dst.Perms.Rename {
		return src, dst, ErrDenied
	}
	if fi, err := os.Stat(src.Real); err == nil && !fi.IsDir() && v.UploadDenied(path.Base(dst.Virtual)) {
		return src, dst, ErrFiltered
	}
	if _, err := os.Lstat(dst.Real); err == nil && !strings.EqualFold(src.Real, dst.Real) {
		return src, dst, ErrExists
	}
	return src, dst, mapOSErr(os.Rename(src.Real, dst.Real))
}

// Chtimes setzt die Änderungszeit.
func (v *FS) Chtimes(vp string, t time.Time) error {
	tg, _, err := v.StatPath(vp)
	if err != nil {
		return err
	}
	if !tg.Perms.Write || tg.Real == "" {
		return ErrDenied
	}
	return mapOSErr(os.Chtimes(tg.Real, t, t))
}

func mapOSErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		return ErrNotFound
	case errors.Is(err, os.ErrExist):
		return ErrExists
	case errors.Is(err, os.ErrPermission):
		return ErrDenied
	}
	return err
}

// DirSize summiert die Dateigrößen unterhalb eines Ordners (für Kontingente).
func DirSize(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total
}

// ReadDirMessage liest eine .message-Datei (max. 2 KiB) für FTP-Ordnernachrichten.
func ReadDirMessage(dir string) string {
	f, err := os.Open(filepath.Join(dir, ".message"))
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 2048))
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\r", ""))
}

// HumanBytes formatiert eine Bytezahl lesbar (KiB, MiB, ...).
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
