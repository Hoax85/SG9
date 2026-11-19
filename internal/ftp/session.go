package ftp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sg9/internal/core"
)

// Session ist eine FTP-Steuerverbindung.
type Session struct {
	srv       *Server
	hub       *core.Hub
	id        int64
	raw       net.Conn
	ctrl      net.Conn
	r         *bufio.Reader
	wmu       sync.Mutex
	ip        net.IP
	ipStr     string
	connected time.Time
	implicit  bool

	tlsCtrl atomic.Bool
	protP   bool

	mu          sync.Mutex // schützt die Felder bis xfer
	user        string
	acct        core.Account
	fs          *core.FS
	cwd         string
	lastCmd     string
	lastActive  time.Time
	pasvLn      net.Listener
	activeAddr  *net.TCPAddr
	dataConn    net.Conn
	xfer        *core.Xfer
	pendingUser string

	loggedIn   atomic.Bool
	xferActive atomic.Bool
	aborted    atomic.Bool
	closing    atomic.Bool
	xferWG     sync.WaitGroup

	epsvAll    bool
	restOffset int64
	renameFrom string
	downLim    *core.Limiter
	upLim      *core.Limiter
	quota      *atomic.Int64
	quotaLimit int64
}

func newSession(srv *Server, c net.Conn, id int64, implicit bool) *Session {
	ip := remoteIP(c)
	now := time.Now()
	return &Session{
		srv: srv, hub: srv.Hub, id: id, raw: c, ctrl: c, r: bufio.NewReaderSize(c, 8192),
		ip: ip, ipStr: ip.String(), connected: now, lastActive: now, implicit: implicit, cwd: "/",
	}
}

func (s *Session) userName() string { s.mu.Lock(); defer s.mu.Unlock(); return s.user }

func (s *Session) logf(level, format string, a ...any) {
	s.hub.Log.Add(level, s.id, s.ipStr, s.userName(), format, a...)
}

func (s *Session) fire(event, vpath, real string, n int64) {
	s.hub.Fire(core.EventData{Event: event, User: s.userName(), IP: s.ipStr, Protocol: core.ProtoFTP, Path: vpath, RealPath: real, Bytes: n})
}

// Info liefert den Zustand für den Admin.
func (s *Session) Info() core.SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	proto := "ftp"
	if s.tlsCtrl.Load() {
		proto = "ftps"
	}
	return core.SessionInfo{ID: s.id, Protocol: proto, IP: s.ipStr, User: s.user, Connected: s.connected, LastCommand: s.lastCmd,
		LastActive: s.lastActive, Cwd: s.cwd, TLS: s.tlsCtrl.Load(), Transfer: s.xfer.Info()}
}

// reply sendet eine (ggf. mehrzeilige) Antwort.
func (s *Session) reply(code int, msg string) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	lines := strings.Split(strings.TrimRight(msg, "\n"), "\n")
	var b strings.Builder
	for i, l := range lines {
		if i == len(lines)-1 {
			fmt.Fprintf(&b, "%d %s\r\n", code, l)
		} else if i == 0 {
			fmt.Fprintf(&b, "%d-%s\r\n", code, l)
		} else {
			fmt.Fprintf(&b, " %s\r\n", l)
		}
	}
	s.ctrl.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, _ = io.WriteString(s.ctrl, b.String())
}

// Kick trennt die Sitzung.
func (s *Session) Kick() {
	s.closing.Store(true)
	s.mu.Lock()
	if s.dataConn != nil {
		s.dataConn.Close()
	}
	if s.pasvLn != nil {
		s.pasvLn.Close()
	}
	s.mu.Unlock()
	s.ctrl.Close()
	s.raw.Close()
}

func (s *Session) settings() core.Settings { return s.hub.Store.Settings() }

func (s *Session) serve() {
	defer s.cleanup()
	st := s.settings()
	s.logf("info", "FTP verbunden")
	if s.implicit {
		tc := tls.Server(s.raw, s.srv.tlsConf)
		tc.SetDeadline(time.Now().Add(30 * time.Second))
		if err := tc.Handshake(); err != nil {
			s.logf("warn", "TLS-Handshake fehlgeschlagen: %v", err)
			return
		}
		tc.SetDeadline(time.Time{})
		s.ctrl = tc
		s.r = bufio.NewReaderSize(tc, 8192)
		s.tlsCtrl.Store(true)
		s.protP = true
	}
	banner := st.Banner
	if strings.Contains(banner, "%s") {
		banner = fmt.Sprintf(banner, st.ServerName)
	}
	s.reply(220, banner)

	for !s.closing.Load() {
		st = s.settings()
		switch {
		case !s.loggedIn.Load():
			s.ctrl.SetReadDeadline(s.connected.Add(time.Duration(st.LoginTimeoutSec) * time.Second))
		case s.xferActive.Load():
			s.ctrl.SetReadDeadline(time.Time{})
		case st.IdleTimeoutSec > 0:
			s.ctrl.SetReadDeadline(time.Now().Add(time.Duration(st.IdleTimeoutSec) * time.Second))
		default:
			s.ctrl.SetReadDeadline(time.Time{})
		}
		line, err := s.readLine()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && !s.closing.Load() {
				s.reply(421, "Zeitüberschreitung, Verbindung wird getrennt.")
				s.logf("info", "Zeitüberschreitung")
			}
			return
		}
		if line == "" {
			continue
		}
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(cmd)
		logged := line
		if cmd == "PASS" {
			logged = "PASS ***"
		}
		s.mu.Lock()
		s.lastCmd = logged
		s.lastActive = time.Now()
		s.mu.Unlock()

		if s.xferActive.Load() {
			switch cmd {
			case "ABOR", "STAT", "NOOP", "QUIT":
			default:
				s.xferWG.Wait()
			}
		}
		if !s.dispatch(cmd, arg) {
			return
		}
	}
}

// readLine liest eine Befehlszeile und entfernt Telnet-Steuerzeichen.
func (s *Session) readLine() (string, error) {
	b, err := s.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = s.r.ReadSlice('\n')
		}
		if err != nil {
			return "", err
		}
		s.reply(500, "Befehlszeile zu lang.")
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == 0xFF { // Telnet IAC + Befehl überspringen
			i++
			continue
		}
		if c == '\r' || c == '\n' || c == 0 || (c >= 0xF0 && c < 0xFF && out.Len() == 0) {
			continue
		}
		out.WriteByte(c)
	}
	return strings.TrimLeft(out.String(), " "), nil
}

func (s *Session) cleanup() {
	s.closing.Store(true)
	s.mu.Lock()
	if s.dataConn != nil {
		s.dataConn.Close()
	}
	if s.pasvLn != nil {
		s.pasvLn.Close()
	}
	s.mu.Unlock()
	s.xferWG.Wait()
	s.ctrl.Close()
	s.raw.Close()
	if s.loggedIn.Load() {
		s.fire("logout", "", "", 0)
	}
	s.logf("info", "Getrennt (Dauer %s)", time.Since(s.connected).Round(time.Second))
}

// ---------- Pfade ----------

func (s *Session) absPath(arg string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return s.cwdGet()
	}
	arg = strings.ReplaceAll(arg, "\\", "/")
	if !strings.HasPrefix(arg, "/") {
		arg = path.Join(s.cwdGet(), arg)
	}
	return core.CleanVirtual(arg)
}

func (s *Session) cwdGet() string { s.mu.Lock(); defer s.mu.Unlock(); return s.cwd }

func (s *Session) fsRef() *core.FS { s.mu.Lock(); defer s.mu.Unlock(); return s.fs }

func (s *Session) resolve(arg string) (core.Target, error) {
	return s.fsRef().Resolve(s.absPath(arg))
}

func quotePath(p string) string { return `"` + strings.ReplaceAll(p, `"`, `""`) + `"` }

// errReply wandelt Dateisystemfehler in FTP-Antworten.
func (s *Session) errReply(err error, fallback string) {
	switch {
	case errors.Is(err, core.ErrNotFound):
		s.reply(550, "Nicht gefunden.")
	case errors.Is(err, core.ErrDenied):
		s.reply(550, "Keine Berechtigung.")
	case errors.Is(err, core.ErrExists):
		s.reply(550, "Existiert bereits.")
	case errors.Is(err, core.ErrFiltered):
		s.reply(553, "Dieser Dateityp ist nicht erlaubt.")
	case errors.Is(err, core.ErrNotEmpty):
		s.reply(550, "Ordner ist nicht leer.")
	case errors.Is(err, core.ErrInvalid):
		s.reply(553, "Ungültiger Pfad.")
	default:
		s.reply(550, fallback)
	}
}

// ---------- Anmeldung ----------

func (s *Session) cmdUser(arg string) {
	st := s.settings()
	if s.loggedIn.Load() {
		s.reply(503, "Bereits angemeldet.")
		return
	}
	if st.TLS.Mode == "required" && !s.tlsCtrl.Load() {
		s.reply(530, "Dieser Server verlangt eine verschlüsselte Verbindung (AUTH TLS).")
		return
	}
	name := strings.TrimSpace(arg)
	s.mu.Lock()
	s.pendingUser = name
	s.mu.Unlock()
	if strings.EqualFold(name, "anonymous") || strings.EqualFold(name, "ftp") {
		s.reply(331, "Anonyme Anmeldung: bitte E-Mail-Adresse als Passwort senden.")
		return
	}
	s.reply(331, "Passwort für "+name+" erforderlich.")
}

func (s *Session) cmdPass(arg string) {
	s.mu.Lock()
	name := s.pendingUser
	s.pendingUser = ""
	s.mu.Unlock()
	if s.loggedIn.Load() {
		s.reply(503, "Bereits angemeldet.")
		return
	}
	if name == "" {
		s.reply(503, "Zuerst USER senden.")
		return
	}
	acct, err := s.hub.Login(core.LoginRequest{Name: name, Password: arg, IP: s.ip, Protocol: core.ProtoFTP,
		Secure: s.tlsCtrl.Load(), Session: s.id, CountsSession: true})
	if err != nil {
		var le *core.LoginError
		errors.As(err, &le)
		if le != nil && le.Failed {
			time.Sleep(time.Second)
		}
		if le != nil && le.Banned {
			s.reply(421, "Zu viele Fehlversuche, IP gesperrt.")
			s.Kick()
			return
		}
		s.reply(530, err.Error())
		return
	}
	s.mu.Lock()
	s.user = acct.Name
	s.acct = acct
	s.fs = core.NewFS(acct, s.settings().FollowSymlinks)
	s.cwd = "/"
	s.mu.Unlock()
	s.downLim = core.NewLimiter(acct.DownloadKBps)
	s.upLim = core.NewLimiter(acct.UploadKBps)
	s.quota = s.hub.Quota(acct, true)
	s.quotaLimit = acct.QuotaMB * 1024 * 1024
	s.loggedIn.Store(true)
	if acct.Anonymous {
		s.logf("info", "Anonym angemeldet (%s)", strings.TrimSpace(arg))
	} else {
		s.logf("info", "Angemeldet")
	}
	s.fire("login", "/", "", 0)
	msg := "Angemeldet. Viel Spass!"
	if w := strings.TrimSpace(acct.Welcome); w != "" {
		msg = strings.ReplaceAll(strings.ReplaceAll(w, "\r", ""), "%u", acct.Name) + "\n" + msg
	}
	if acct.Ratio > 0 {
		left := s.hub.RatioLeft(acct)
		msg = fmt.Sprintf("Ratio 1:%d, Download-Guthaben: %s\n", acct.Ratio, human(left)) + msg
	}
	s.reply(230, msg)
}

// ---------- Datenverbindung ----------

func (s *Session) closePassive() {
	s.mu.Lock()
	if s.pasvLn != nil {
		s.pasvLn.Close()
		s.pasvLn = nil
	}
	s.mu.Unlock()
}

// advertiseIP bestimmt die IP, die bei PASV genannt wird.
func (s *Session) advertiseIP() net.IP {
	st := s.settings()
	local := s.raw.LocalAddr().(*net.TCPAddr).IP
	if st.PublicIP != "" && !(s.ip.IsPrivate() || s.ip.IsLoopback()) {
		if ip := net.ParseIP(st.PublicIP); ip != nil {
			return ip
		}
		if addrs, err := net.LookupIP(st.PublicIP); err == nil {
			for _, a := range addrs {
				if a.To4() != nil {
					return a
				}
			}
		}
	}
	return local
}

func (s *Session) cmdPasv(extended bool) {
	if !extended && s.epsvAll {
		s.reply(501, "Nach EPSV ALL ist nur EPSV erlaubt.")
		return
	}
	s.closePassive()
	ip := s.advertiseIP()
	if !extended && ip.To4() == nil {
		s.reply(425, "PASV nur über IPv4 möglich, bitte EPSV verwenden.")
		return
	}
	ln, err := s.srv.listenPassive()
	if err != nil {
		s.reply(425, "Kein freier Passiv-Port.")
		s.logf("error", "Passiv-Port: %v", err)
		return
	}
	s.mu.Lock()
	s.pasvLn = ln
	s.activeAddr = nil
	s.mu.Unlock()
	port := ln.Addr().(*net.TCPAddr).Port
	if extended {
		s.reply(229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", port))
		return
	}
	v4 := ip.To4()
	s.reply(227, fmt.Sprintf("Entering Passive Mode (%d,%d,%d,%d,%d,%d)", v4[0], v4[1], v4[2], v4[3], port>>8, port&0xFF))
}

func (s *Session) setActive(ip net.IP, port int) {
	if !s.settings().AllowFXP && !ip.Equal(s.ip) {
		s.reply(504, "Aktive Verbindung nur zur eigenen IP erlaubt (FXP ist aus).")
		return
	}
	if port < 1024 {
		s.reply(504, "Ports unter 1024 sind nicht erlaubt.")
		return
	}
	s.closePassive()
	s.mu.Lock()
	s.activeAddr = &net.TCPAddr{IP: ip, Port: port}
	s.mu.Unlock()
	s.reply(200, "PORT-Befehl erfolgreich.")
}

func (s *Session) cmdPort(arg string) {
	if s.epsvAll {
		s.reply(501, "Nach EPSV ALL ist nur EPSV erlaubt.")
		return
	}
	var h [6]int
	if n, _ := fmt.Sscanf(strings.TrimSpace(arg), "%d,%d,%d,%d,%d,%d", &h[0], &h[1], &h[2], &h[3], &h[4], &h[5]); n != 6 {
		s.reply(501, "Syntaxfehler in PORT.")
		return
	}
	for _, v := range h {
		if v < 0 || v > 255 {
			s.reply(501, "Syntaxfehler in PORT.")
			return
		}
	}
	s.setActive(net.IPv4(byte(h[0]), byte(h[1]), byte(h[2]), byte(h[3])), h[4]<<8|h[5])
}

func (s *Session) cmdEprt(arg string) {
	if s.epsvAll {
		s.reply(501, "Nach EPSV ALL ist nur EPSV erlaubt.")
		return
	}
	arg = strings.TrimSpace(arg)
	if len(arg) < 2 {
		s.reply(501, "Syntaxfehler in EPRT.")
		return
	}
	parts := strings.Split(arg[1:], arg[:1])
	if len(parts) < 3 {
		s.reply(501, "Syntaxfehler in EPRT.")
		return
	}
	ip := net.ParseIP(parts[1])
	var port int
	if _, err := fmt.Sscanf(parts[2], "%d", &port); err != nil || ip == nil || port > 65535 {
		s.reply(501, "Syntaxfehler in EPRT.")
		return
	}
	if parts[0] != "1" && parts[0] != "2" {
		s.reply(522, "Protokoll nicht unterstützt, verwende (1,2)")
		return
	}
	s.setActive(ip, port)
}

// openData baut die Datenverbindung auf (passiv oder aktiv, ggf. mit TLS).
func (s *Session) openData() (net.Conn, error) {
	st := s.settings()
	s.mu.Lock()
	ln, active := s.pasvLn, s.activeAddr
	s.pasvLn = nil
	s.mu.Unlock()
	var c net.Conn
	switch {
	case ln != nil:
		defer ln.Close()
		deadline := time.Now().Add(30 * time.Second)
		for {
			if tl, ok := ln.(*net.TCPListener); ok {
				tl.SetDeadline(deadline)
			}
			conn, err := ln.Accept()
			if err != nil {
				return nil, err
			}
			if st.AllowFXP || remoteIP(conn).Equal(s.ip) {
				c = conn
				break
			}
			s.logf("warn", "Fremde Datenverbindung von %s abgewiesen", remoteIP(conn))
			conn.Close()
		}
	case active != nil:
		d := net.Dialer{Timeout: 15 * time.Second}
		conn, err := d.Dial("tcp", active.String())
		if err != nil {
			return nil, err
		}
		c = conn
	default:
		return nil, errors.New("zuerst PASV/EPSV oder PORT/EPRT senden")
	}
	if s.protP {
		tc := tls.Server(c, s.srv.tlsConf)
		tc.SetDeadline(time.Now().Add(30 * time.Second))
		if err := tc.Handshake(); err != nil {
			c.Close()
			return nil, fmt.Errorf("TLS auf Datenverbindung: %w", err)
		}
		tc.SetDeadline(time.Time{})
		c = tc
	}
	s.mu.Lock()
	s.dataConn = c
	s.mu.Unlock()
	return c, nil
}

func (s *Session) closeData() {
	s.mu.Lock()
	c := s.dataConn
	s.dataConn = nil
	s.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

func (s *Session) setXfer(x *core.Xfer) { s.mu.Lock(); s.xfer = x; s.mu.Unlock() }

// runTransfer führt fn im Hintergrund aus, damit ABOR/STAT weiter funktionieren.
func (s *Session) runTransfer(fn func()) {
	s.aborted.Store(false)
	s.xferActive.Store(true)
	s.xferWG.Add(1)
	go func() {
		defer func() {
			s.closeData()
			s.setXfer(nil)
			s.xferActive.Store(false)
			if idle := s.settings().IdleTimeoutSec; idle > 0 && !s.closing.Load() {
				s.ctrl.SetReadDeadline(time.Now().Add(time.Duration(idle) * time.Second))
			}
			s.xferWG.Done()
		}()
		fn()
	}()
}

func (s *Session) meter(upload bool, x *core.Xfer) *core.Meter {
	m := &core.Meter{Hub: s.hub, User: s.userName(), Upload: upload, Xfer: x, Ratio: -1}
	if upload {
		m.Lims = []*core.Limiter{s.upLim, s.hub.GlobalUp}
		m.Quota, m.Limit = s.quota, s.quotaLimit
	} else {
		m.Lims = []*core.Limiter{s.downLim, s.hub.GlobalDown}
		s.mu.Lock()
		acct := s.acct
		s.mu.Unlock()
		m.Ratio = s.hub.RatioLeft(acct)
	}
	return m
}

// pump kopiert mit Bandbreitenbegrenzung, Zählung und Leerlauf-Timeout.
func (s *Session) pump(dst io.Writer, src io.Reader, dc net.Conn, m *core.Meter) (int64, error) {
	idle := time.Duration(s.settings().IdleTimeoutSec) * time.Second
	if idle <= 0 {
		idle = 5 * time.Minute
	}
	buf := make([]byte, 16*1024)
	var total int64
	for {
		dc.SetDeadline(time.Now().Add(idle))
		n, rerr := src.Read(buf)
		if n > 0 {
			if err := m.Before(n); err != nil {
				return total, err
			}
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			m.After(w)
			if werr != nil {
				return total, werr
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}
