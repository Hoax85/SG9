package ftp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"sg9/internal/core"
)

// Befehle, die ohne Anmeldung erlaubt sind.
var preLogin = map[string]bool{
	"USER": true, "PASS": true, "QUIT": true, "AUTH": true, "PBSZ": true, "PROT": true, "FEAT": true,
	"SYST": true, "NOOP": true, "HELP": true, "OPTS": true, "CLNT": true, "HOST": true, "STAT": true, "CCC": true,
}

// dispatch führt einen Befehl aus; false beendet die Sitzung.
func (s *Session) dispatch(cmd, arg string) bool {
	if !s.loggedIn.Load() && !preLogin[cmd] {
		s.reply(530, "Bitte zuerst anmelden (USER/PASS).")
		return true
	}
	// REST gilt nur für den unmittelbar folgenden Befehl.
	if cmd != "REST" && cmd != "RETR" && cmd != "STOR" && cmd != "APPE" {
		s.restOffset = 0
	}
	switch cmd {
	case "USER":
		s.cmdUser(arg)
	case "PASS":
		s.cmdPass(arg)
	case "QUIT":
		s.xferWG.Wait()
		s.reply(221, "Tschüss!")
		return false
	case "NOOP":
		s.reply(200, "OK")
	case "SYST":
		s.reply(215, "UNIX Type: L8")
	case "FEAT":
		s.cmdFeat()
	case "OPTS":
		s.cmdOpts(arg)
	case "CLNT":
		s.reply(200, "Schön, dich kennenzulernen.")
	case "HOST":
		s.reply(220, "Host akzeptiert.")
	case "HELP":
		s.reply(214, "Unterstützte Befehle:\nABOR ALLO APPE AUTH CCC CDUP CLNT CWD DELE EPRT EPSV FEAT HELP LIST MDTM MFMT\nMKD MLSD MLST MODE NLST NOOP OPTS PASS PASV PBSZ PORT PROT PWD QUIT REST RETR\nRMD RNFR RNTO SITE SIZE STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD XPWD XRMD\nHilfe Ende.")
	case "AUTH":
		s.cmdAuth(arg)
	case "PBSZ":
		if !s.tlsCtrl.Load() {
			s.reply(503, "Zuerst AUTH TLS.")
		} else {
			s.reply(200, "PBSZ=0")
		}
	case "PROT":
		s.cmdProt(arg)
	case "CCC":
		s.reply(534, "CCC wird aus Sicherheitsgründen nicht unterstützt.")
	case "TYPE":
		switch strings.ToUpper(strings.TrimSpace(arg)) {
		case "A", "A N":
			s.reply(200, "Typ auf ASCII gesetzt.")
		case "I", "L 8", "L8":
			s.reply(200, "Typ auf Binär gesetzt.")
		default:
			s.reply(504, "Typ nicht unterstützt.")
		}
	case "MODE":
		if strings.EqualFold(strings.TrimSpace(arg), "S") {
			s.reply(200, "Modus Stream.")
		} else {
			s.reply(504, "Nur Modus S wird unterstützt.")
		}
	case "STRU":
		if strings.EqualFold(strings.TrimSpace(arg), "F") {
			s.reply(200, "Struktur Datei.")
		} else {
			s.reply(504, "Nur Struktur F wird unterstützt.")
		}
	case "ALLO":
		s.reply(202, "ALLO nicht nötig.")
	case "PWD", "XPWD":
		s.reply(257, quotePath(s.cwdGet())+" ist das aktuelle Verzeichnis.")
	case "CWD", "XCWD":
		s.cmdCwd(arg)
	case "CDUP", "XCUP":
		s.cmdCwd("..")
	case "PASV":
		s.cmdPasv(false)
	case "EPSV":
		if strings.EqualFold(strings.TrimSpace(arg), "ALL") {
			s.epsvAll = true
			s.reply(200, "EPSV ALL akzeptiert.")
		} else {
			s.cmdPasv(true)
		}
	case "PORT":
		s.cmdPort(arg)
	case "EPRT":
		s.cmdEprt(arg)
	case "REST":
		n, err := strconv.ParseInt(strings.TrimSpace(arg), 10, 64)
		if err != nil || n < 0 {
			s.reply(501, "Ungültige Position.")
		} else {
			s.restOffset = n
			s.reply(350, fmt.Sprintf("Fortsetzen ab Byte %d.", n))
		}
	case "LIST", "NLST", "MLSD":
		s.cmdList(cmd, arg)
	case "MLST":
		s.cmdMlst(arg)
	case "STAT":
		s.cmdStat(arg)
	case "SIZE":
		s.cmdSize(arg)
	case "MDTM":
		s.cmdMdtm(arg)
	case "MFMT":
		s.cmdMfmt(arg)
	case "RETR":
		s.cmdRetr(arg)
	case "STOR":
		s.cmdStore(arg, false, false)
	case "APPE":
		s.cmdStore(arg, true, false)
	case "STOU":
		s.cmdStore(arg, false, true)
	case "ABOR":
		s.cmdAbor()
	case "DELE":
		s.cmdDele(arg)
	case "MKD", "XMKD":
		s.cmdMkd(arg)
	case "RMD", "XRMD":
		s.cmdRmd(arg)
	case "RNFR":
		s.cmdRnfr(arg)
	case "RNTO":
		s.cmdRnto(arg)
	case "SITE":
		s.cmdSite(arg)
	case "ACCT":
		s.reply(202, "ACCT nicht nötig.")
	default:
		s.reply(502, "Befehl nicht implementiert: "+cmd)
	}
	if cmd != "RNFR" {
		s.renameFrom = ""
	}
	return true
}

func (s *Session) cmdFeat() {
	f := []string{"Funktionen:", "UTF8", "EPRT", "EPSV", "PASV", "SIZE", "MDTM", "MFMT", "REST STREAM",
		"MLST type*;size*;modify*;perm*;", "TVFS", "CLNT", "HOST"}
	if (s.srv.tlsConf != nil && s.settings().TLS.Mode != "off") || s.implicit {
		f = append(f, "AUTH TLS", "PBSZ", "PROT")
	}
	f = append(f, "Ende")
	s.reply(211, strings.Join(f, "\n"))
}

func (s *Session) cmdOpts(arg string) {
	k, _, _ := strings.Cut(strings.ToUpper(strings.TrimSpace(arg)), " ")
	switch k {
	case "UTF8", "UTF-8":
		s.reply(200, "UTF8 ist immer aktiv.")
	case "MLST":
		s.reply(200, "MLST OPTS type;size;modify;perm;")
	default:
		s.reply(501, "Option nicht unterstützt.")
	}
}

func (s *Session) cmdAuth(arg string) {
	mech := strings.ToUpper(strings.TrimSpace(arg))
	if mech != "TLS" && mech != "SSL" && mech != "TLS-C" && mech != "TLS-P" {
		s.reply(504, "Nur AUTH TLS wird unterstützt.")
		return
	}
	if s.srv.tlsConf == nil || s.settings().TLS.Mode == "off" {
		s.reply(502, "TLS ist auf diesem Server deaktiviert.")
		return
	}
	if s.tlsCtrl.Load() {
		s.reply(503, "Verbindung ist bereits verschlüsselt.")
		return
	}
	s.reply(234, "AUTH "+mech+" erfolgreich, starte TLS.")
	tc := tls.Server(s.raw, s.srv.tlsConf)
	tc.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tc.Handshake(); err != nil {
		s.logf("warn", "TLS-Handshake fehlgeschlagen: %v", err)
		s.Kick()
		return
	}
	tc.SetDeadline(time.Time{})
	s.wmu.Lock()
	s.ctrl = tc
	s.r = bufio.NewReaderSize(tc, 8192)
	s.wmu.Unlock()
	s.tlsCtrl.Store(true)
	if mech == "SSL" || mech == "TLS-P" {
		s.protP = true
	}
	s.logf("info", "Steuerverbindung verschlüsselt (%s)", tlsVersion(tc.ConnectionState().Version))
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return "TLS"
}

func (s *Session) cmdProt(arg string) {
	if !s.tlsCtrl.Load() {
		s.reply(503, "Zuerst AUTH TLS.")
		return
	}
	switch strings.ToUpper(strings.TrimSpace(arg)) {
	case "P":
		s.protP = true
		s.reply(200, "Datenverbindungen werden verschlüsselt.")
	case "C":
		if s.settings().TLS.Mode == "required" {
			s.reply(534, "Unverschlüsselte Datenverbindungen sind nicht erlaubt.")
			return
		}
		s.protP = false
		s.reply(200, "Datenverbindungen unverschlüsselt.")
	default:
		s.reply(504, "Nur PROT P oder C.")
	}
}

func (s *Session) requireProt() bool {
	if s.settings().TLS.Mode == "required" && !s.protP {
		s.reply(521, "Datenverbindung muss verschlüsselt sein (PROT P).")
		return false
	}
	return true
}

func (s *Session) cmdCwd(arg string) {
	t, e, err := s.fsRef().StatPath(s.absPath(arg))
	if err != nil || !e.IsDir {
		s.reply(550, "Ordner nicht gefunden.")
		return
	}
	s.mu.Lock()
	s.cwd = t.Virtual
	s.mu.Unlock()
	msg := "Verzeichnis gewechselt nach " + quotePath(t.Virtual) + "."
	if s.settings().DirMessages && t.Real != "" && t.Perms.List {
		if m := core.ReadDirMessage(t.Real); m != "" {
			msg = m + "\n" + msg
		}
	}
	s.reply(250, msg)
}

// ---------- Auflistungen ----------

func listArgs(arg string) string {
	// Optionen wie -la ignorieren, die viele Clients senden.
	fields := strings.Fields(arg)
	rest := []string{}
	skipping := true
	for _, f := range fields {
		if skipping && strings.HasPrefix(f, "-") {
			continue
		}
		skipping = false
		rest = append(rest, f)
	}
	if len(rest) == 0 {
		return ""
	}
	idx := strings.Index(arg, rest[0])
	return arg[idx:]
}

func lsLine(e core.Entry) string {
	var mode [10]byte
	mode[0] = '-'
	if e.IsDir {
		mode[0] = 'd'
	}
	perm := e.Mode.Perm()
	if runtime.GOOS == "windows" || perm == 0 {
		perm = 0o644
		if e.IsDir {
			perm = 0o755
		}
	}
	const rwx = "rwxrwxrwx"
	for i := 0; i < 9; i++ {
		if perm&(1<<uint(8-i)) != 0 {
			mode[i+1] = rwx[i]
		} else {
			mode[i+1] = '-'
		}
	}
	t := e.ModTime
	ts := t.Format("Jan _2 15:04")
	if time.Since(t) > 180*24*time.Hour || t.After(time.Now().Add(24*time.Hour)) {
		ts = t.Format("Jan _2  2006")
	}
	return fmt.Sprintf("%s 1 ftp ftp %13d %s %s\r\n", mode[:], e.Size, ts, e.Name)
}

func mlsFacts(e core.Entry, perms core.Permissions, kind string) string {
	if kind == "" {
		kind = "file"
		if e.IsDir {
			kind = "dir"
		}
	}
	p := ""
	if e.IsDir {
		p = "e"
		for _, x := range []struct {
			ok bool
			c  string
		}{{perms.List, "l"}, {perms.Write, "c"}, {perms.MkDir, "m"}, {perms.RmDir, "d"}, {perms.Delete, "p"}, {perms.Rename, "f"}} {
			if x.ok {
				p += x.c
			}
		}
	} else {
		for _, x := range []struct {
			ok bool
			c  string
		}{{perms.Read, "r"}, {perms.Write, "w"}, {perms.Append, "a"}, {perms.Delete, "d"}, {perms.Rename, "f"}} {
			if x.ok {
				p += x.c
			}
		}
	}
	mod := e.ModTime.UTC().Format("20060102150405")
	if e.IsDir {
		return fmt.Sprintf("type=%s;modify=%s;perm=%s;", kind, mod, p)
	}
	return fmt.Sprintf("type=%s;size=%d;modify=%s;perm=%s;", kind, e.Size, mod, p)
}

// buildListing erzeugt den Text für LIST/NLST/MLSD.
func (s *Session) buildListing(cmd, arg string) ([]byte, int, string) {
	fs := s.fsRef()
	if cmd != "MLSD" {
		arg = listArgs(arg)
	}
	t, e, err := fs.StatPath(s.absPath(arg))
	if err != nil {
		if cmd == "NLST" {
			return []byte{}, 0, ""
		}
		return nil, 550, "Nicht gefunden."
	}
	if !t.Perms.List {
		return nil, 550, "Auflisten nicht erlaubt."
	}
	var buf bytes.Buffer
	if !e.IsDir {
		if cmd == "MLSD" {
			return nil, 501, "MLSD braucht einen Ordner."
		}
		if cmd == "NLST" {
			buf.WriteString(arg + "\r\n")
		} else {
			buf.WriteString(lsLine(e))
		}
		return buf.Bytes(), 0, ""
	}
	entries, err := fs.List(t)
	if err != nil {
		return nil, 550, "Ordner kann nicht gelesen werden."
	}
	if cmd == "MLSD" {
		buf.WriteString(mlsFacts(e, t.Perms, "cdir") + " .\r\n")
	}
	for _, c := range entries {
		switch cmd {
		case "NLST":
			buf.WriteString(c.Name + "\r\n")
		case "MLSD":
			buf.WriteString(mlsFacts(c, fs.ChildPerms(t, c.Name), "") + " " + c.Name + "\r\n")
		default:
			buf.WriteString(lsLine(c))
		}
	}
	return buf.Bytes(), 0, ""
}

func (s *Session) cmdList(cmd, arg string) {
	if !s.requireProt() {
		return
	}
	data, code, msg := s.buildListing(cmd, arg)
	if code != 0 {
		s.closePassive()
		s.reply(code, msg)
		return
	}
	x := &core.Xfer{Direction: "list", File: s.absPath(listArgs(arg)), Size: int64(len(data)), Started: time.Now()}
	s.setXfer(x)
	s.reply(150, "Öffne Datenverbindung für Verzeichnisliste.")
	s.runTransfer(func() {
		dc, err := s.openData()
		if err != nil {
			s.reply(425, "Datenverbindung fehlgeschlagen: "+err.Error())
			return
		}
		dc.SetDeadline(time.Now().Add(60 * time.Second))
		_, err = dc.Write(data)
		x.Bytes.Store(int64(len(data)))
		if err != nil || s.aborted.Load() {
			s.reply(426, "Übertragung abgebrochen.")
			return
		}
		s.reply(226, "Verzeichnisliste gesendet.")
	})
}

func (s *Session) cmdMlst(arg string) {
	t, e, err := s.fsRef().StatPath(s.absPath(arg))
	if err != nil {
		s.reply(550, "Nicht gefunden.")
		return
	}
	s.reply(250, "Eintrag:\n"+mlsFacts(e, t.Perms, "")+" "+t.Virtual+"\nEnde")
}

func (s *Session) cmdStat(arg string) {
	if strings.TrimSpace(arg) == "" {
		st := s.settings()
		var b strings.Builder
		fmt.Fprintf(&b, "%s Status:\n", st.ServerName)
		fmt.Fprintf(&b, "Verbunden von %s\n", s.ipStr)
		if u := s.userName(); u != "" {
			fmt.Fprintf(&b, "Angemeldet als %s\n", u)
		}
		fmt.Fprintf(&b, "TLS Steuerung: %v, Daten: %v\n", s.tlsCtrl.Load(), s.protP)
		if x := s.Info().Transfer; x != nil {
			fmt.Fprintf(&b, "Übertragung: %s %s, %d Bytes\n", x.Direction, x.File, x.Bytes)
		}
		b.WriteString("Ende des Status")
		s.reply(211, b.String())
		return
	}
	if !s.loggedIn.Load() {
		s.reply(530, "Bitte zuerst anmelden.")
		return
	}
	data, code, msg := s.buildListing("LIST", arg)
	if code != 0 {
		s.reply(code, msg)
		return
	}
	body := strings.TrimRight(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	s.reply(213, "Status von "+s.absPath(listArgs(arg))+":\n"+body+"\nEnde")
}

// ---------- Dateiinfos ----------

func (s *Session) fileTarget(arg string) (core.Target, core.Entry, bool) {
	t, e, err := s.fsRef().StatPath(s.absPath(arg))
	if err != nil || e.IsDir {
		s.reply(550, "Datei nicht gefunden.")
		return t, e, false
	}
	return t, e, true
}

func (s *Session) cmdSize(arg string) {
	if _, e, ok := s.fileTarget(arg); ok {
		s.reply(213, strconv.FormatInt(e.Size, 10))
	}
}

func parseFTPTime(v string) (time.Time, bool) {
	v = strings.SplitN(v, ".", 2)[0]
	t, err := time.ParseInLocation("20060102150405", v, time.UTC)
	return t, err == nil
}

func (s *Session) cmdMdtm(arg string) {
	arg = strings.TrimSpace(arg)
	if f := strings.SplitN(arg, " ", 2); len(f) == 2 && len(f[0]) >= 14 {
		if tm, ok := parseFTPTime(f[0]); ok {
			s.setMtime(tm, f[1])
			return
		}
	}
	if _, e, ok := s.fileTarget(arg); ok {
		s.reply(213, e.ModTime.UTC().Format("20060102150405"))
	}
}

func (s *Session) cmdMfmt(arg string) {
	f := strings.SplitN(strings.TrimSpace(arg), " ", 2)
	if len(f) != 2 {
		s.reply(501, "Syntax: MFMT YYYYMMDDHHMMSS datei")
		return
	}
	tm, ok := parseFTPTime(f[0])
	if !ok {
		s.reply(501, "Ungültige Zeitangabe.")
		return
	}
	s.setMtime(tm, f[1])
}

func (s *Session) setMtime(tm time.Time, file string) {
	vp := s.absPath(file)
	if err := s.fsRef().Chtimes(vp, tm); err != nil {
		s.errReply(err, "Zeit kann nicht gesetzt werden.")
		return
	}
	s.reply(213, fmt.Sprintf("Modify=%s; %s", tm.Format("20060102150405"), vp))
}

// ---------- Übertragungen ----------

func (s *Session) cmdRetr(arg string) {
	offset := s.restOffset
	s.restOffset = 0
	if !s.requireProt() {
		return
	}
	f, t, e, err := s.fsRef().OpenRead(s.absPath(arg))
	if err != nil {
		s.closePassive()
		if errors.Is(err, core.ErrDenied) {
			s.reply(550, "Download nicht erlaubt.")
		} else {
			s.reply(550, "Datei nicht gefunden.")
		}
		return
	}
	if offset > 0 {
		if offset > e.Size {
			f.Close()
			s.reply(554, "Position hinter dem Dateiende.")
			return
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			s.reply(554, "Position nicht möglich.")
			return
		}
	}
	x := &core.Xfer{Direction: "down", File: t.Virtual, Size: e.Size - offset, Started: time.Now()}
	m := s.meter(false, x)
	if m.Ratio == 0 {
		f.Close()
		s.closePassive()
		s.reply(550, core.ErrRatio.Error()+".")
		return
	}
	s.setXfer(x)
	s.reply(150, fmt.Sprintf("Öffne BINARY-Datenverbindung für %s (%d Bytes).", path.Base(t.Virtual), e.Size))
	s.runTransfer(func() {
		defer f.Close()
		dc, err := s.openData()
		if err != nil {
			s.reply(425, "Datenverbindung fehlgeschlagen: "+err.Error())
			return
		}
		n, err := s.pump(dc, f, dc, m)
		cerr := dc.Close()
		dur := time.Since(x.Started)
		switch {
		case s.aborted.Load():
			s.reply(426, "Übertragung abgebrochen.")
			s.logf("xfer", "Download abgebrochen: %s (%s)", t.Virtual, human(n))
		case errors.Is(err, core.ErrRatio):
			s.reply(426, core.ErrRatio.Error()+".")
			s.logf("xfer", "Download %s: Ratio-Guthaben aufgebraucht", t.Virtual)
		case err != nil || cerr != nil:
			s.reply(426, "Verbindung unterbrochen.")
			s.logf("xfer", "Download unterbrochen: %s (%s)", t.Virtual, human(n))
		default:
			s.hub.AddFile(s.userName(), false)
			s.reply(226, "Übertragung abgeschlossen.")
			s.logf("xfer", "Download %s, %s in %s (%s/s)", t.Virtual, human(n), dur.Round(time.Millisecond), human(rate(n, dur)))
			s.fire("download", t.Virtual, t.Real, n)
		}
	})
}

func (s *Session) cmdStore(arg string, appendMode, unique bool) {
	offset := s.restOffset
	s.restOffset = 0
	if !s.requireProt() {
		return
	}
	fs := s.fsRef()
	if unique {
		base := strings.TrimSpace(arg)
		if base == "" {
			base = "upload"
		}
		for i := 0; ; i++ {
			cand := fmt.Sprintf("%s.%d", base, time.Now().UnixNano()+int64(i))
			if _, _, err := fs.StatPath(s.absPath(cand)); errors.Is(err, core.ErrNotFound) {
				arg = cand
				break
			}
			if i > 20 {
				s.reply(553, "Kein eindeutiger Name möglich.")
				return
			}
		}
	}
	mode := core.WriteTruncate
	switch {
	case appendMode:
		mode = core.WriteAppend
	case offset > 0:
		mode = core.WriteAt
	}
	if s.quota != nil && s.quotaLimit > 0 && s.quota.Load() >= s.quotaLimit {
		s.closePassive()
		s.reply(552, "Speicherplatz-Kontingent erschöpft.")
		return
	}
	wr, err := fs.OpenWrite(s.absPath(arg), mode)
	if err != nil {
		s.closePassive()
		switch {
		case errors.Is(err, core.ErrDenied) && mode != core.WriteTruncate:
			s.reply(550, "Fortsetzen/Anhängen nicht erlaubt.")
		case errors.Is(err, core.ErrDenied):
			s.reply(550, "Upload nicht erlaubt.")
		case errors.Is(err, core.ErrExists):
			s.reply(553, "Ein Ordner mit diesem Namen existiert bereits.")
		default:
			s.errReply(err, "Datei kann nicht angelegt werden.")
		}
		return
	}
	f, t := wr.File, wr.Target
	if wr.Existed && s.quota != nil {
		switch {
		case mode == core.WriteAt && offset < wr.OldSize:
			s.quota.Add(-(wr.OldSize - offset))
		case mode == core.WriteTruncate:
			s.quota.Add(-wr.OldSize)
		}
	}
	if mode == core.WriteAt {
		if err := f.Truncate(offset); err == nil {
			_, err = f.Seek(offset, io.SeekStart)
		}
		if err != nil {
			f.Close()
			s.reply(554, "Position nicht möglich.")
			return
		}
	}
	x := &core.Xfer{Direction: "up", File: t.Virtual, Size: -1, Started: time.Now()}
	m := s.meter(true, x)
	s.setXfer(x)
	if unique {
		s.reply(150, "FILE: "+path.Base(t.Virtual))
	} else {
		s.reply(150, "Bereit zum Empfang von "+path.Base(t.Virtual)+".")
	}
	s.runTransfer(func() {
		dc, err := s.openData()
		if err != nil {
			f.Close()
			s.reply(425, "Datenverbindung fehlgeschlagen: "+err.Error())
			return
		}
		w := bufio.NewWriterSize(f, 256*1024)
		n, perr := s.pump(w, dc, dc, m)
		ferr := w.Flush()
		if cerr := f.Close(); ferr == nil {
			ferr = cerr
		}
		dur := time.Since(x.Started)
		switch {
		case s.aborted.Load():
			s.reply(426, "Übertragung abgebrochen.")
			s.logf("xfer", "Upload abgebrochen: %s (%s)", t.Virtual, human(n))
		case errors.Is(perr, core.ErrQuota):
			if !wr.Existed && mode == core.WriteTruncate && os.Remove(t.Real) == nil && s.quota != nil {
				s.quota.Add(-n) // unvollständige neue Datei wieder entfernen
			}
			s.reply(552, "Speicherplatz-Kontingent überschritten.")
			s.logf("warn", "Upload %s: Kontingent überschritten", t.Virtual)
		case perr != nil:
			s.reply(426, "Verbindung unterbrochen.")
			s.logf("xfer", "Upload unterbrochen: %s (%s)", t.Virtual, human(n))
		case ferr != nil:
			s.reply(451, "Schreibfehler auf dem Server.")
			s.logf("error", "Upload %s: %v", t.Virtual, ferr)
		default:
			s.hub.AddFile(s.userName(), true)
			s.reply(226, "Übertragung abgeschlossen.")
			s.logf("xfer", "Upload %s, %s in %s (%s/s)", t.Virtual, human(n), dur.Round(time.Millisecond), human(rate(n, dur)))
			s.fire("upload", t.Virtual, t.Real, n)
		}
	})
}

func (s *Session) cmdAbor() {
	if !s.xferActive.Load() {
		s.closePassive()
		s.reply(225, "Keine Übertragung aktiv.")
		return
	}
	s.aborted.Store(true)
	s.closePassive()
	s.closeData()
	s.xferWG.Wait()
	s.reply(226, "ABOR erfolgreich.")
}

// ---------- Dateioperationen ----------

func (s *Session) cmdDele(arg string) {
	t, e, err := s.fsRef().Remove(s.absPath(arg))
	if err != nil {
		s.errReply(err, "Löschen fehlgeschlagen.")
		return
	}
	if s.quota != nil {
		s.quota.Add(-e.Size)
	}
	s.logf("info", "Gelöscht: %s", t.Virtual)
	s.fire("delete", t.Virtual, t.Real, e.Size)
	s.reply(250, "Datei gelöscht.")
}

func (s *Session) cmdMkd(arg string) {
	t, err := s.fsRef().Mkdir(s.absPath(arg))
	if err != nil {
		s.errReply(err, "Ordner kann nicht angelegt werden.")
		return
	}
	s.logf("info", "Ordner angelegt: %s", t.Virtual)
	s.fire("mkdir", t.Virtual, t.Real, 0)
	s.reply(257, quotePath(t.Virtual)+" angelegt.")
}

func (s *Session) cmdRmd(arg string) {
	t, err := s.fsRef().Rmdir(s.absPath(arg), false)
	if err != nil {
		s.errReply(err, "Ordner kann nicht gelöscht werden.")
		return
	}
	s.logf("info", "Ordner gelöscht: %s", t.Virtual)
	s.fire("rmdir", t.Virtual, t.Real, 0)
	s.reply(250, "Ordner gelöscht.")
}

func (s *Session) cmdRnfr(arg string) {
	t, _, err := s.fsRef().StatPath(s.absPath(arg))
	if err != nil {
		s.reply(550, "Nicht gefunden.")
		return
	}
	if t.Real == "" || t.IsMount || t.Virtual == "/" || !t.Perms.Rename {
		s.reply(550, "Umbenennen nicht erlaubt.")
		return
	}
	s.renameFrom = t.Virtual
	s.reply(350, "Bereit für RNTO.")
}

func (s *Session) cmdRnto(arg string) {
	from := s.renameFrom
	s.renameFrom = ""
	if from == "" {
		s.reply(503, "Zuerst RNFR senden.")
		return
	}
	_, dst, err := s.fsRef().Rename(from, s.absPath(arg))
	if err != nil {
		if errors.Is(err, core.ErrExists) {
			s.reply(553, "Ziel existiert bereits.")
		} else {
			s.errReply(err, "Umbenennen fehlgeschlagen (evtl. über Laufwerksgrenzen).")
		}
		return
	}
	s.logf("info", "Umbenannt: %s -> %s", from, dst.Virtual)
	s.hub.Fire(core.EventData{Event: "rename", User: s.userName(), IP: s.ipStr, Protocol: core.ProtoFTP, Path: dst.Virtual, RealPath: dst.Real, Extra: from})
	s.reply(250, "Umbenannt.")
}

func (s *Session) cmdSite(arg string) {
	sub, rest, _ := strings.Cut(strings.TrimSpace(arg), " ")
	switch strings.ToUpper(sub) {
	case "HELP":
		s.reply(214, "SITE-Befehle:\nCHMOD <modus> <datei>\nRATIO\nHELP\nEnde")
	case "RATIO":
		s.mu.Lock()
		acct := s.acct
		s.mu.Unlock()
		if acct.Ratio <= 0 {
			s.reply(200, "Kein Ratio für dieses Konto.")
			return
		}
		c := s.hub.Counters(acct.Name)
		s.reply(200, fmt.Sprintf("Ratio 1:%d, hochgeladen %s, heruntergeladen %s, Guthaben %s", acct.Ratio, human(c.BytesUp), human(c.BytesDown), human(s.hub.RatioLeft(acct))))
	case "CHMOD":
		modeStr, file, ok := strings.Cut(strings.TrimSpace(rest), " ")
		m, err := strconv.ParseUint(modeStr, 8, 32)
		if !ok || err != nil {
			s.reply(501, "Syntax: SITE CHMOD 644 datei")
			return
		}
		t, err := s.resolve(file)
		if err != nil || t.Real == "" {
			s.reply(550, "Nicht gefunden.")
			return
		}
		if !t.Perms.Write {
			s.reply(550, "Keine Schreibrechte.")
			return
		}
		if err := os.Chmod(t.Real, os.FileMode(m)); err != nil {
			s.reply(550, "CHMOD fehlgeschlagen.")
			return
		}
		s.reply(200, "CHMOD erfolgreich.")
	default:
		s.reply(504, "SITE-Befehl nicht unterstützt.")
	}
}

// ---------- Hilfen ----------

func rate(n int64, d time.Duration) int64 {
	if d <= 0 {
		return n
	}
	return int64(float64(n) / d.Seconds())
}

func human(n int64) string { return core.HumanBytes(n) }
