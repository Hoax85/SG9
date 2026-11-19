package sftpd

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/pkg/sftp"

	"sg9/internal/core"
)

type handlers struct{ s *session }

// mapErr übersetzt SG9-Fehler in SFTP-Statuscodes.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, core.ErrNotFound):
		return os.ErrNotExist
	case errors.Is(err, core.ErrDenied), errors.Is(err, core.ErrFiltered), errors.Is(err, core.ErrQuota), errors.Is(err, core.ErrRatio):
		return sftp.ErrSSHFxPermissionDenied
	case errors.Is(err, core.ErrExists), errors.Is(err, core.ErrNotEmpty), errors.Is(err, core.ErrInvalid):
		return sftp.ErrSSHFxFailure
	}
	return err
}

func (h *handlers) fs() *core.FS { h.s.mu.Lock(); defer h.s.mu.Unlock(); return h.s.fs }

func (h *handlers) addXfer(x *core.Xfer) {
	h.s.mu.Lock()
	h.s.xfers[x] = true
	h.s.mu.Unlock()
}

func (h *handlers) delXfer(x *core.Xfer) {
	h.s.mu.Lock()
	delete(h.s.xfers, x)
	h.s.mu.Unlock()
}

// ---------- Lesen ----------

type reader struct {
	h    *handlers
	f    *os.File
	m    *core.Meter
	x    *core.Xfer
	t    core.Target
	once sync.Once
}

func (r *reader) ReadAt(p []byte, off int64) (int, error) {
	if r.m.Ratio == 0 {
		return 0, core.ErrRatio
	}
	n, err := r.f.ReadAt(p, off)
	if n > 0 {
		if e := r.m.Before(n); e != nil {
			return 0, e
		}
		r.m.After(n)
	}
	return n, err
}

func (r *reader) Close() error {
	r.once.Do(func() {
		r.h.delXfer(r.x)
		n := r.x.Bytes.Load()
		s := r.h.s
		if n >= r.x.Size {
			s.hub.AddFile(s.user, false)
			s.hub.Fire(core.EventData{Event: "download", User: s.user, IP: s.ip, Protocol: core.ProtoSFTP, Path: r.t.Virtual, RealPath: r.t.Real, Bytes: n})
		}
		if n > 0 {
			s.log("xfer", "SFTP-Download %s, %s", r.t.Virtual, core.HumanBytes(n))
		}
	})
	return r.f.Close()
}

func (h *handlers) Fileread(req *sftp.Request) (io.ReaderAt, error) {
	h.s.touch("GET " + req.Filepath)
	f, t, e, err := h.fs().OpenRead(req.Filepath)
	if err != nil {
		return nil, mapErr(err)
	}
	x := &core.Xfer{Direction: "down", File: t.Virtual, Size: e.Size, Started: time.Now()}
	s := h.s
	s.mu.Lock()
	acct := s.acct
	s.mu.Unlock()
	m := &core.Meter{Hub: s.hub, User: s.user, Lims: []*core.Limiter{s.downLim, s.hub.GlobalDown}, Xfer: x, Ratio: s.hub.RatioLeft(acct)}
	if m.Ratio == 0 {
		f.Close()
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	h.addXfer(x)
	return &reader{h: h, f: f, m: m, x: x, t: t}, nil
}

// ---------- Schreiben ----------

type writer struct {
	h       *handlers
	f       *os.File
	m       *core.Meter
	x       *core.Xfer
	t       core.Target
	failed  error
	created bool
	once    sync.Once
}

func (w *writer) WriteAt(p []byte, off int64) (int, error) {
	if w.failed != nil {
		return 0, w.failed
	}
	if err := w.m.Before(len(p)); err != nil {
		w.failed = err
		return 0, err
	}
	n, err := w.f.WriteAt(p, off)
	w.m.After(n)
	return n, err
}

func (w *writer) Close() error {
	err := w.f.Close()
	w.once.Do(func() {
		w.h.delXfer(w.x)
		s := w.h.s
		n := w.x.Bytes.Load()
		if errors.Is(w.failed, core.ErrQuota) {
			if w.created && os.Remove(w.t.Real) == nil && w.m.Quota != nil {
				w.m.Quota.Add(-n)
			}
			s.log("warn", "SFTP-Upload %s: Kontingent überschritten", w.t.Virtual)
			return
		}
		s.hub.AddFile(s.user, true)
		s.log("xfer", "SFTP-Upload %s, %s", w.t.Virtual, core.HumanBytes(n))
		s.hub.Fire(core.EventData{Event: "upload", User: s.user, IP: s.ip, Protocol: core.ProtoSFTP, Path: w.t.Virtual, RealPath: w.t.Real, Bytes: n})
	})
	return err
}

func (h *handlers) Filewrite(req *sftp.Request) (io.WriterAt, error) {
	h.s.touch("PUT " + req.Filepath)
	fl := req.Pflags()
	mode := core.WriteAt
	switch {
	case fl.Trunc:
		mode = core.WriteTruncate
	case fl.Append:
		mode = core.WriteAppend
	}
	fsys := h.fs()
	if mode == core.WriteAt {
		// Neue Datei ohne TRUNC: wie ein normaler Upload behandeln.
		if _, _, err := fsys.StatPath(req.Filepath); errors.Is(err, core.ErrNotFound) {
			mode = core.WriteTruncate
		}
	}
	if fl.Excl {
		if _, _, err := fsys.StatPath(req.Filepath); err == nil {
			return nil, sftp.ErrSSHFxFailure
		}
	}
	s := h.s
	s.mu.Lock()
	acct := s.acct
	s.mu.Unlock()
	quota := s.hub.Quota(acct, false)
	limit := acct.QuotaMB * 1024 * 1024
	if quota != nil && limit > 0 && quota.Load() >= limit {
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	wr, err := fsys.OpenWrite(req.Filepath, mode)
	if err != nil {
		return nil, mapErr(err)
	}
	if wr.Existed && quota != nil && mode == core.WriteTruncate {
		quota.Add(-wr.OldSize)
	}
	x := &core.Xfer{Direction: "up", File: wr.Target.Virtual, Size: -1, Started: time.Now()}
	m := &core.Meter{Hub: s.hub, User: s.user, Upload: true, Lims: []*core.Limiter{s.upLim, s.hub.GlobalUp}, Xfer: x, Quota: quota, Limit: limit, Ratio: -1}
	h.addXfer(x)
	return &writer{h: h, f: wr.File, m: m, x: x, t: wr.Target, created: !wr.Existed}, nil
}

// ---------- Befehle ----------

func (h *handlers) Filecmd(req *sftp.Request) error {
	s := h.s
	s.touch(req.Method + " " + req.Filepath)
	fsys := h.fs()
	ev := func(name string, t core.Target, extra string) {
		s.hub.Fire(core.EventData{Event: name, User: s.user, IP: s.ip, Protocol: core.ProtoSFTP, Path: t.Virtual, RealPath: t.Real, Extra: extra})
	}
	switch req.Method {
	case "Setstat":
		fl := req.AttrFlags()
		if fl.Acmodtime {
			return mapErr(fsys.Chtimes(req.Filepath, time.Unix(int64(req.Attributes().Mtime), 0)))
		}
		if fl.Size {
			t, _, err := fsys.StatPath(req.Filepath)
			if err != nil {
				return mapErr(err)
			}
			if !t.Perms.Write {
				return sftp.ErrSSHFxPermissionDenied
			}
			return os.Truncate(t.Real, int64(req.Attributes().Size))
		}
		return nil // Rechte/Besitzer ändern ignorieren wir bewusst
	case "Rename", "PosixRename":
		_, dst, err := fsys.Rename(req.Filepath, req.Target)
		if err == nil {
			s.log("info", "Umbenannt: %s -> %s", req.Filepath, dst.Virtual)
			ev("rename", dst, req.Filepath)
		}
		return mapErr(err)
	case "Rmdir":
		t, err := fsys.Rmdir(req.Filepath, false)
		if err == nil {
			s.log("info", "Ordner gelöscht: %s", t.Virtual)
			ev("rmdir", t, "")
		}
		return mapErr(err)
	case "Mkdir":
		t, err := fsys.Mkdir(req.Filepath)
		if err == nil {
			s.log("info", "Ordner angelegt: %s", t.Virtual)
			ev("mkdir", t, "")
		}
		return mapErr(err)
	case "Remove":
		t, e, err := fsys.Remove(req.Filepath)
		if err == nil {
			s.mu.Lock()
			acct := s.acct
			s.mu.Unlock()
			if q := s.hub.Quota(acct, false); q != nil {
				q.Add(-e.Size)
			}
			s.log("info", "Gelöscht: %s", t.Virtual)
			ev("delete", t, "")
		}
		return mapErr(err)
	}
	return sftp.ErrSSHFxOpUnsupported
}

// ---------- Auflisten ----------

type fileInfo struct{ e core.Entry }

func (f fileInfo) Name() string       { return f.e.Name }
func (f fileInfo) Size() int64        { return f.e.Size }
func (f fileInfo) ModTime() time.Time { return f.e.ModTime }
func (f fileInfo) IsDir() bool        { return f.e.IsDir }
func (f fileInfo) Sys() any           { return nil }
func (f fileInfo) Mode() fs.FileMode {
	m := f.e.Mode.Perm()
	if m == 0 {
		m = 0o644
		if f.e.IsDir {
			m = 0o755
		}
	}
	if f.e.IsDir {
		return m | fs.ModeDir
	}
	return m
}

type lister []os.FileInfo

func (l lister) ListAt(out []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(out, l[off:])
	if n < len(out) {
		return n, io.EOF
	}
	return n, nil
}

func (h *handlers) Filelist(req *sftp.Request) (sftp.ListerAt, error) {
	h.s.touch(req.Method + " " + req.Filepath)
	fsys := h.fs()
	switch req.Method {
	case "List":
		t, e, err := fsys.StatPath(req.Filepath)
		if err != nil {
			return nil, mapErr(err)
		}
		if !e.IsDir {
			return lister{fileInfo{e}}, nil
		}
		if !t.Perms.List {
			return nil, sftp.ErrSSHFxPermissionDenied
		}
		entries, err := fsys.List(t)
		if err != nil {
			return nil, mapErr(err)
		}
		out := make(lister, 0, len(entries))
		for _, c := range entries {
			out = append(out, fileInfo{c})
		}
		return out, nil
	case "Stat", "Lstat":
		_, e, err := fsys.StatPath(req.Filepath)
		if err != nil {
			return nil, mapErr(err)
		}
		if req.Filepath == "/" || req.Filepath == "" {
			e.Name = "/"
		}
		return lister{fileInfo{e}}, nil
	}
	return nil, sftp.ErrSSHFxOpUnsupported
}
