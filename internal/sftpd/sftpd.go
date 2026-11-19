// Package sftpd stellt SFTP (Dateiübertragung über SSH) bereit.
package sftpd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"sg9/internal/core"
)

// Server ist der SFTP-Dienst.
type Server struct {
	Hub *core.Hub

	mu        sync.Mutex
	ln        net.Listener
	addr      string
	signer    ssh.Signer
	accounts  sync.Map // SessionID -> core.Account
	listenKey string
}

// New erstellt den SFTP-Server.
func New(h *core.Hub) *Server { return &Server{Hub: h} }

// Fingerprint liefert den SHA256-Fingerabdruck des Host-Schlüssels.
func (s *Server) Fingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signer == nil {
		return ""
	}
	return ssh.FingerprintSHA256(s.signer.PublicKey())
}

// Listening meldet die Adresse.
func (s *Server) Listening() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return []string{}
	}
	return []string{s.ln.Addr().String()}
}

func (s *Server) hostKey() (ssh.Signer, error) {
	p := filepath.Join(s.Hub.Store.DataDir, "sg9-hostkey")
	if b, err := os.ReadFile(p); err == nil {
		return ssh.ParsePrivateKey(b)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "SG9 host key")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// Start öffnet den Listener, falls SFTP aktiv ist.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked()
}

func (s *Server) startLocked() error {
	st := s.Hub.Store.Settings().SFTP
	s.listenKey = fmt.Sprint(st.Enabled, st.ListenAddr)
	if !st.Enabled {
		return nil
	}
	if s.signer == nil {
		sg, err := s.hostKey()
		if err != nil {
			return fmt.Errorf("SSH-Host-Schlüssel: %w", err)
		}
		s.signer = sg
	}
	ln, err := net.Listen("tcp", st.ListenAddr)
	if err != nil {
		return fmt.Errorf("SFTP-Port %s nicht verfügbar: %w", st.ListenAddr, err)
	}
	s.ln = ln
	go s.acceptLoop(ln)
	s.Hub.Log.Info("SFTP lauscht auf %s (Host-Schlüssel %s)", ln.Addr(), ssh.FingerprintSHA256(s.signer.PublicKey()))
	return nil
}

// Stop schließt den Listener.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		s.ln.Close()
		s.ln = nil
	}
}

// Reload startet neu, wenn sich Adresse oder Aktivierung geändert haben.
func (s *Server) Reload() {
	st := s.Hub.Store.Settings().SFTP
	s.mu.Lock()
	defer s.mu.Unlock()
	if fmt.Sprint(st.Enabled, st.ListenAddr) == s.listenKey {
		return
	}
	if s.ln != nil {
		s.ln.Close()
		s.ln = nil
	}
	if err := s.startLocked(); err != nil {
		s.Hub.Log.Error("SFTP-Neustart fehlgeschlagen: %v", err)
	}
}

func remoteIP(a net.Addr) net.IP {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP
	}
	return net.IPv4zero
}

func (s *Server) config(sessID int64) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-SG9",
		MaxAuthTries:  6,
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			a, err := s.Hub.Login(core.LoginRequest{Name: c.User(), Password: string(pw), IP: remoteIP(c.RemoteAddr()),
				Protocol: core.ProtoSFTP, Secure: true, Session: sessID, CountsSession: true})
			if err != nil {
				var le *core.LoginError
				if errors.As(err, &le) && le.Failed {
					time.Sleep(time.Second)
				}
				return nil, err
			}
			s.accounts.Store(string(c.SessionID()), a)
			return &ssh.Permissions{Extensions: map[string]string{"auth": "password"}}, nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Nur prüfen, ob der Schlüssel hinterlegt ist; Kontoregeln folgen nach der Signaturprüfung.
			cfg := s.Hub.Store.Snapshot()
			u := cfg.FindUser(c.User())
			if u == nil || !u.Enabled || !keyMatches(cfg.Resolve(u).SSHKeys, key) {
				return nil, errors.New("Schlüssel unbekannt")
			}
			return &ssh.Permissions{Extensions: map[string]string{"auth": "publickey"}}, nil
		},
	}
	s.mu.Lock()
	cfg.AddHostKey(s.signer)
	s.mu.Unlock()
	return cfg
}

func keyMatches(lines []string, key ssh.PublicKey) bool {
	want := key.Marshal()
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err == nil && bytes.Equal(k.Marshal(), want) {
			return true
		}
	}
	return false
}

func (s *Server) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handle(c)
	}
}

func (s *Server) handle(nc net.Conn) {
	ip := remoteIP(nc.RemoteAddr())
	if err := s.Hub.Admit(ip); err != nil {
		nc.Close()
		return
	}
	id := s.Hub.NextID()
	sess := &session{srv: s, hub: s.Hub, id: id, ip: ip.String(), connected: time.Now(), raw: nc}
	sess.lastActive = sess.connected
	s.Hub.Register(id, sess)
	s.Hub.Stats.Connections.Add(1)
	defer s.Hub.Unregister(id)

	nc.SetDeadline(time.Now().Add(time.Duration(s.Hub.Store.Settings().LoginTimeoutSec) * time.Second))
	conn, chans, reqs, err := ssh.NewServerConn(nc, s.config(id))
	if err != nil {
		if !errors.Is(err, io.EOF) {
			s.Hub.Log.Add("info", id, sess.ip, "", "SSH-Handshake beendet: %v", err)
		}
		nc.Close()
		return
	}
	nc.SetDeadline(time.Time{})
	sess.conn = conn
	key := string(conn.SessionID())
	var acct core.Account
	if v, ok := s.accounts.LoadAndDelete(key); ok {
		acct = v.(core.Account)
	} else {
		// Schlüssel-Anmeldung: jetzt alle Kontoregeln anwenden.
		a, err := s.Hub.Login(core.LoginRequest{Name: conn.User(), CheckKey: func(*core.User) bool { return true },
			IP: ip, Protocol: core.ProtoSFTP, Secure: true, Session: id, CountsSession: true})
		if err != nil {
			conn.Close()
			return
		}
		acct = a
	}
	sess.start(acct, conn.Permissions.Extensions["auth"])
	defer sess.finish()

	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "nur session-Kanäle")
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go sess.handleChannel(ch, chReqs)
	}
}

// ---------- Sitzung ----------

type session struct {
	srv       *Server
	hub       *core.Hub
	id        int64
	ip        string
	raw       net.Conn
	conn      *ssh.ServerConn
	connected time.Time

	mu         sync.Mutex
	user       string
	acct       core.Account
	fs         *core.FS
	lastCmd    string
	lastActive time.Time
	xfers      map[*core.Xfer]bool
	downLim    *core.Limiter
	upLim      *core.Limiter
}

func (s *session) start(a core.Account, method string) {
	s.mu.Lock()
	s.user = a.Name
	s.acct = a
	s.fs = core.NewFS(a, s.hub.Store.Settings().FollowSymlinks)
	s.xfers = map[*core.Xfer]bool{}
	s.mu.Unlock()
	s.downLim = core.NewLimiter(a.DownloadKBps)
	s.upLim = core.NewLimiter(a.UploadKBps)
	s.log("info", "SFTP angemeldet (%s)", method)
	s.hub.Fire(core.EventData{Event: "login", User: a.Name, IP: s.ip, Protocol: core.ProtoSFTP})
}

func (s *session) finish() {
	s.hub.Fire(core.EventData{Event: "logout", User: s.user, IP: s.ip, Protocol: core.ProtoSFTP})
	s.log("info", "SFTP getrennt (Dauer %s)", time.Since(s.connected).Round(time.Second))
}

func (s *session) log(level, f string, a ...any) {
	s.mu.Lock()
	u := s.user
	s.mu.Unlock()
	s.hub.Log.Add(level, s.id, s.ip, u, f, a...)
}

// Info für den Admin.
func (s *session) Info() core.SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := core.SessionInfo{ID: s.id, Protocol: "sftp", IP: s.ip, User: s.user, Connected: s.connected,
		LastCommand: s.lastCmd, LastActive: s.lastActive, TLS: true}
	for x := range s.xfers {
		in.Transfer = x.Info()
		in.Cwd = path.Dir(x.File)
		break
	}
	return in
}

// Kick trennt die SSH-Verbindung.
func (s *session) Kick() {
	if s.conn != nil {
		s.conn.Close()
	}
	s.raw.Close()
}

func (s *session) touch(cmd string) {
	s.mu.Lock()
	s.lastCmd = cmd
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *session) handleChannel(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "subsystem":
			if len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
				req.Reply(true, nil)
				s.serveSFTP(ch)
				return
			}
			req.Reply(false, nil)
		case "env", "pty-req":
			req.Reply(true, nil)
		case "shell", "exec":
			req.Reply(true, nil)
			io.WriteString(ch.Stderr(), "SG9: Dieser Server bietet nur Dateiübertragung per SFTP an, keine Shell.\r\n")
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{1}))
			return
		default:
			req.Reply(false, nil)
		}
	}
}

func (s *session) serveSFTP(ch ssh.Channel) {
	h := &handlers{s: s}
	srv := sftp.NewRequestServer(ch, sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h})
	if err := srv.Serve(); err != nil && !errors.Is(err, io.EOF) {
		s.log("warn", "SFTP: %v", err)
	}
	srv.Close()
}
