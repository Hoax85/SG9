// Package ftp implementiert den FTP/FTPS-Server von SG9.
package ftp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sg9/internal/core"
)

// Server verwaltet die FTP-Listener.
type Server struct {
	Hub *core.Hub

	mu        sync.Mutex
	listeners []net.Listener
	tlsConf   *tls.Config
	listenKey string

	passiveNext atomic.Int64
}

// New erstellt einen FTP-Server.
func New(h *core.Hub) *Server { return &Server{Hub: h} }

func (s *Server) settings() core.Settings { return s.Hub.Store.Settings() }

func listenKey(st core.Settings) string {
	return strings.Join([]string{fmt.Sprint(st.FTPEnabled), st.ListenAddr, st.TLS.ImplicitAddr, st.TLS.Mode, st.TLS.CertFile, st.TLS.KeyFile}, "|")
}

// Start öffnet die Listener gemäß Konfiguration.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startLocked()
}

func (s *Server) startLocked() error {
	st := s.settings()
	s.listenKey = listenKey(st)
	if !st.FTPEnabled {
		s.Hub.Log.Info("FTP ist deaktiviert")
		return nil
	}
	s.tlsConf = nil
	if st.TLS.Mode != "off" || st.TLS.ImplicitAddr != "" {
		if _, err := core.LoadOrCreateCert(s.Hub.Store.DataDir, st.TLS, st.ServerName); err != nil {
			return fmt.Errorf("TLS-Zertifikat: %w", err)
		}
		s.tlsConf = s.Hub.Certs.TLSConfig()
	}
	ln, err := net.Listen("tcp", st.ListenAddr)
	if err != nil {
		return fmt.Errorf("FTP-Port %s nicht verfügbar: %w", st.ListenAddr, err)
	}
	s.listeners = []net.Listener{ln}
	go s.acceptLoop(ln, false)
	s.Hub.Log.Info("FTP lauscht auf %s (TLS: %s)", ln.Addr(), st.TLS.Mode)
	if st.TLS.ImplicitAddr != "" && s.tlsConf != nil {
		iln, err := net.Listen("tcp", st.TLS.ImplicitAddr)
		if err != nil {
			s.Hub.Log.Error("Implizites FTPS auf %s nicht möglich: %v", st.TLS.ImplicitAddr, err)
		} else {
			s.listeners = append(s.listeners, iln)
			go s.acceptLoop(iln, true)
			s.Hub.Log.Info("Implizites FTPS lauscht auf %s", iln.Addr())
		}
	}
	return nil
}

// Stop schließt die Listener (Sitzungen bleiben bestehen).
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.listeners {
		l.Close()
	}
	s.listeners = nil
}

// Reload startet die Listener neu, wenn sich Ports oder TLS geändert haben.
func (s *Server) Reload() {
	st := s.settings()
	s.mu.Lock()
	defer s.mu.Unlock()
	if listenKey(st) != s.listenKey {
		for _, l := range s.listeners {
			l.Close()
		}
		s.listeners = nil
		if err := s.startLocked(); err != nil {
			s.Hub.Log.Error("FTP-Neustart fehlgeschlagen: %v", err)
		}
	}
}

// Listening meldet die aktiven Adressen.
func (s *Server) Listening() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []string{}
	for _, l := range s.listeners {
		out = append(out, l.Addr().String())
	}
	return out
}

func (s *Server) acceptLoop(ln net.Listener, implicit bool) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.Hub.Log.Error("FTP Accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handleConn(c, implicit)
	}
}

func remoteIP(c net.Conn) net.IP {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP
	}
	return net.IPv4zero
}

func (s *Server) handleConn(c net.Conn, implicit bool) {
	if err := s.Hub.Admit(remoteIP(c)); err != nil {
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(c, "421 %s\r\n", err.Error())
		c.Close()
		return
	}
	id := s.Hub.NextID()
	sess := newSession(s, c, id, implicit)
	s.Hub.Register(id, sess)
	s.Hub.Stats.Connections.Add(1)
	defer s.Hub.Unregister(id)
	sess.serve()
}

// listenPassive belegt einen freien Port aus dem Passivbereich.
func (s *Server) listenPassive() (net.Listener, error) {
	st := s.settings()
	lo, hi := st.PassivePortMin, st.PassivePortMax
	n := hi - lo + 1
	start := int(s.passiveNext.Add(1) % int64(n))
	for i := 0; i < n; i++ {
		port := lo + (start+i)%n
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			return ln, nil
		}
	}
	return nil, errors.New("kein freier Passiv-Port")
}
