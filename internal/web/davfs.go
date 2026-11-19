package web

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"mime"
	"os"
	"path"
	"sync"
	"time"

	"golang.org/x/net/webdav"

	"sg9/internal/core"
)

// davFS verbindet WebDAV mit dem virtuellen Dateisystem eines Kontos.
type davFS struct {
	fs   *core.FS
	sess *httpSession
	srv  *Server
	acct core.Account
}

func davErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, core.ErrNotFound):
		return os.ErrNotExist
	case errors.Is(err, core.ErrExists):
		return os.ErrExist
	case errors.Is(err, core.ErrDenied), errors.Is(err, core.ErrFiltered), errors.Is(err, core.ErrInvalid),
		errors.Is(err, core.ErrQuota), errors.Is(err, core.ErrRatio), errors.Is(err, core.ErrNotEmpty):
		return os.ErrPermission
	}
	return err
}

// davInfo ist ein FileInfo mit Inhaltstyp, damit WebDAV keine Dateien zum Erraten öffnet.
type davInfo struct{ e core.Entry }

func (d davInfo) Name() string       { return d.e.Name }
func (d davInfo) Size() int64        { return d.e.Size }
func (d davInfo) ModTime() time.Time { return d.e.ModTime }
func (d davInfo) IsDir() bool        { return d.e.IsDir }
func (d davInfo) Sys() any           { return nil }
func (d davInfo) Mode() fs.FileMode {
	if d.e.IsDir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (d davInfo) ContentType(context.Context) (string, error) {
	if t := mime.TypeByExtension(path.Ext(d.e.Name)); t != "" {
		return t, nil
	}
	return "application/octet-stream", nil
}

func (d *davFS) Stat(_ context.Context, name string) (os.FileInfo, error) {
	_, e, err := d.fs.StatPath(name)
	if err != nil {
		return nil, davErr(err)
	}
	if core.CleanVirtual(name) == "/" {
		e.Name = "/"
	}
	return davInfo{e}, nil
}

func (d *davFS) Mkdir(_ context.Context, name string, _ os.FileMode) error {
	t, err := d.fs.Mkdir(name)
	if err == nil {
		d.sess.event("mkdir", t, 0, "")
	}
	return davErr(err)
}

func (d *davFS) RemoveAll(_ context.Context, name string) error {
	t, e, err := d.fs.StatPath(name)
	if err != nil {
		return davErr(err)
	}
	if e.IsDir {
		_, err = d.fs.Rmdir(name, true)
		if err == nil {
			d.sess.event("rmdir", t, 0, "")
		}
	} else {
		_, _, err = d.fs.Remove(name)
		if err == nil {
			if q := d.srv.Hub.Quota(d.acct, false); q != nil {
				q.Add(-e.Size)
			}
			d.sess.event("delete", t, e.Size, "")
		}
	}
	return davErr(err)
}

func (d *davFS) Rename(_ context.Context, oldName, newName string) error {
	_, dst, err := d.fs.Rename(oldName, newName)
	if err == nil {
		d.sess.event("rename", dst, 0, oldName)
	}
	return davErr(err)
}

func (d *davFS) OpenFile(_ context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
		return d.openWrite(name, flag)
	}
	t, e, err := d.fs.StatPath(name)
	if err != nil {
		return nil, davErr(err)
	}
	if core.CleanVirtual(name) == "/" {
		e.Name = "/"
	}
	if e.IsDir {
		return &davDir{d: d, t: t, e: e}, nil
	}
	f, t, e, err := d.fs.OpenRead(name)
	if err != nil {
		return nil, davErr(err)
	}
	x := &core.Xfer{Direction: "down", File: t.Virtual, Size: e.Size, Started: time.Now()}
	m := d.sess.downMeter(d.acct, x)
	return &davFile{d: d, f: f, t: t, e: e, m: m, x: x}, nil
}

func (d *davFS) openWrite(name string, flag int) (webdav.File, error) {
	mode := core.WriteTruncate
	if flag&os.O_APPEND != 0 {
		mode = core.WriteAppend
	}
	q := d.srv.Hub.Quota(d.acct, false)
	limit := d.acct.QuotaMB * 1024 * 1024
	if q != nil && limit > 0 && q.Load() >= limit {
		return nil, os.ErrPermission
	}
	wr, err := d.fs.OpenWrite(name, mode)
	if err != nil {
		return nil, davErr(err)
	}
	if wr.Existed && q != nil && mode == core.WriteTruncate {
		q.Add(-wr.OldSize)
	}
	x := &core.Xfer{Direction: "up", File: wr.Target.Virtual, Size: -1, Started: time.Now()}
	m := d.sess.upMeter(d.acct, x, q, limit)
	e := core.Entry{Name: path.Base(wr.Target.Virtual), ModTime: time.Now()}
	return &davFile{d: d, f: wr.File, t: wr.Target, e: e, m: m, x: x, write: true, created: !wr.Existed}, nil
}

// davFile ist eine geöffnete Datei mit Bremse und Zählung.
type davFile struct {
	d       *davFS
	f       *os.File
	t       core.Target
	e       core.Entry
	m       *core.Meter
	x       *core.Xfer
	write   bool
	created bool
	failed  error
	once    sync.Once
	used    bool
}

func (f *davFile) Read(p []byte) (int, error) {
	if !f.used {
		f.used = true
		f.d.sess.addXfer(f.x)
	}
	if f.m.Ratio == 0 {
		return 0, core.ErrRatio
	}
	n, err := f.f.Read(p)
	if n > 0 {
		if e := f.m.Before(n); e != nil {
			return 0, e
		}
		f.m.After(n)
	}
	return n, err
}

func (f *davFile) Write(p []byte) (int, error) {
	if !f.used {
		f.used = true
		f.d.sess.addXfer(f.x)
	}
	if f.failed != nil {
		return 0, f.failed
	}
	if err := f.m.Before(len(p)); err != nil {
		f.failed = err
		return 0, err
	}
	n, err := f.f.Write(p)
	f.m.After(n)
	return n, err
}

func (f *davFile) Seek(off int64, whence int) (int64, error) { return f.f.Seek(off, whence) }
func (f *davFile) Readdir(int) ([]fs.FileInfo, error)        { return nil, os.ErrInvalid }

func (f *davFile) Stat() (fs.FileInfo, error) {
	fi, err := f.f.Stat()
	if err != nil {
		return nil, err
	}
	return davInfo{core.Entry{Name: f.e.Name, Size: fi.Size(), ModTime: fi.ModTime(), Mode: fi.Mode()}}, nil
}

func (f *davFile) Close() error {
	err := f.f.Close()
	f.once.Do(func() {
		s := f.d.sess
		s.delXfer(f.x)
		n := f.x.Bytes.Load()
		if f.write {
			if errors.Is(f.failed, core.ErrQuota) {
				if f.created && os.Remove(f.t.Real) == nil && f.m.Quota != nil {
					f.m.Quota.Add(-n)
				}
				s.log("warn", "Upload %s: Kontingent überschritten", f.t.Virtual)
				return
			}
			if !f.used && !f.created {
				return
			}
			f.d.srv.Hub.AddFile(s.user, true)
			s.log("xfer", "%s-Upload %s, %s", s.protoLabel(), f.t.Virtual, core.HumanBytes(n))
			s.event("upload", f.t, n, "")
			return
		}
		if n > 0 && n >= f.e.Size {
			f.d.srv.Hub.AddFile(s.user, false)
			s.log("xfer", "%s-Download %s, %s", s.protoLabel(), f.t.Virtual, core.HumanBytes(n))
			s.event("download", f.t, n, "")
		}
	})
	return err
}

// davDir ist ein geöffneter Ordner.
type davDir struct {
	d    *davFS
	t    core.Target
	e    core.Entry
	done bool
}

func (d *davDir) Read([]byte) (int, error)       { return 0, os.ErrInvalid }
func (d *davDir) Write([]byte) (int, error)      { return 0, os.ErrPermission }
func (d *davDir) Seek(int64, int) (int64, error) { return 0, nil }
func (d *davDir) Close() error                   { return nil }
func (d *davDir) Stat() (fs.FileInfo, error)     { return davInfo{d.e}, nil }
func (d *davDir) Readdir(count int) ([]fs.FileInfo, error) {
	if d.done || !d.t.Perms.List {
		if count > 0 {
			return nil, io.EOF
		}
		return []fs.FileInfo{}, nil
	}
	d.done = true
	entries, err := d.d.fs.List(d.t)
	if err != nil {
		return nil, davErr(err)
	}
	out := make([]fs.FileInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, davInfo{e})
	}
	return out, nil
}
