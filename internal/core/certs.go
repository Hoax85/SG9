package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Certs liefert Zertifikate für alle verschlüsselten Dienste:
// Let's Encrypt für die eingestellte Domain, sonst das eigene oder ein selbst signiertes.
// Änderungen der Einstellungen gelten sofort, ohne Neustart der Dienste.
type Certs struct {
	store *Store
	log   *Logger

	mu       sync.Mutex
	mgr      *autocert.Manager
	mgrKey   string
	fallback *tls.Certificate
	fbKey    string
	lastErr  string
	lastTry  time.Time
}

// NewCerts erstellt den Zertifikats-Dienst.
func NewCerts(store *Store, log *Logger) *Certs { return &Certs{store: store, log: log} }

func (c *Certs) acmeDir() string { return filepath.Join(c.store.DataDir, "letsencrypt") }

// manager liefert den Let's-Encrypt-Manager oder nil, wenn ausgeschaltet.
func (c *Certs) manager() *autocert.Manager {
	st := c.store.Settings()
	a := st.Web.ACME
	c.mu.Lock()
	defer c.mu.Unlock()
	if !a.Enabled || a.Domain == "" {
		c.mgr, c.mgrKey = nil, ""
		return nil
	}
	key := a.Domain + "|" + a.Email
	if c.mgr != nil && c.mgrKey == key {
		return c.mgr
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(c.acmeDir()),
		HostPolicy: autocert.HostWhitelist(a.Domain),
		Email:      a.Email,
	}
	if os.Getenv("SG9_ACME_STAGING") != "" {
		m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
	}
	c.mgr, c.mgrKey, c.lastErr = m, key, ""
	return m
}

func (c *Certs) fallbackCert() (*tls.Certificate, error) {
	st := c.store.Settings()
	key := st.TLS.CertFile + "|" + st.TLS.KeyFile
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fallback != nil && c.fbKey == key {
		return c.fallback, nil
	}
	cert, err := LoadOrCreateCert(c.store.DataDir, st.TLS, st.ServerName)
	if err != nil {
		return nil, err
	}
	c.fallback, c.fbKey = &cert, key
	return c.fallback, nil
}

// Reset verwirft zwischengespeicherte Zertifikate (nach einer Wiederherstellung).
func (c *Certs) Reset() {
	c.mu.Lock()
	c.fallback, c.fbKey, c.mgr, c.mgrKey, c.lastErr = nil, "", nil, "", ""
	c.mu.Unlock()
}

// TLSConfig für einen Dienst. Die Zertifikatswahl passiert bei jeder Verbindung.
func (c *Certs) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1", acme.ALPNProto},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if m := c.manager(); m != nil {
				name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
				domain := c.store.Settings().Web.ACME.Domain
				if name == domain {
					cert, err := m.GetCertificate(hello)
					if err == nil {
						return cert, nil
					}
					c.noteErr(err)
					// Während der Ausstellung oder bei Fehlern: selbst signiert ausliefern statt abbrechen.
				}
			}
			return c.fallbackCert()
		},
	}
}

func (c *Certs) noteErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	msg := explainACME(err)
	// autocert meldet nach einem Fehlschlag eine Weile nur "missing certificate": dann die eigentliche Ursache behalten.
	if strings.Contains(err.Error(), "missing certificate") {
		if c.lastErr != "" {
			return
		}
		msg = "Das Zertifikat wird gerade geholt oder der letzte Versuch ist fehlgeschlagen. In ein paar Minuten nochmals versuchen."
	}
	if msg != c.lastErr || time.Since(c.lastTry) > 10*time.Minute {
		c.log.Error("Let's Encrypt: %s", msg)
	}
	c.lastErr, c.lastTry = msg, time.Now()
}

// explainACME übersetzt typische Fehler in verständliche Hinweise.
func explainACME(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "letsencrypt.org/directory"):
		return "Dieser Rechner erreicht Let's Encrypt nicht. Internetverbindung, Firewall oder Proxy prüfen."
	case strings.Contains(s, "NXDOMAIN") || strings.Contains(s, "no valid A records") || strings.Contains(s, "DNS problem"):
		return "Die Domain zeigt auf keine IP-Adresse. DynDNS-Eintrag prüfen."
	case strings.Contains(s, "Connection refused") || strings.Contains(s, "Timeout") || strings.Contains(s, "timeout") || strings.Contains(s, "connection"):
		return "Let's Encrypt erreicht deinen Server nicht über Port 443. Portweiterleitung im Router prüfen (aussen 443 → Port der Freigabe-Links)."
	case strings.Contains(s, "rateLimited") || strings.Contains(s, "too many"):
		return "Zu viele Versuche bei Let's Encrypt. Bitte in einer Stunde erneut versuchen."
	case strings.Contains(s, "acme/autocert: host") && strings.Contains(s, "not configured"):
		return "Die aufgerufene Adresse passt nicht zur eingestellten Domain."
	}
	return s
}

// CertStatus beschreibt das aktuelle Zertifikat für die Verwaltung.
type CertStatus struct {
	Enabled   bool       `json:"enabled"`
	Domain    string     `json:"domain"`
	Valid     bool       `json:"valid"`
	Issuer    string     `json:"issuer,omitempty"`
	NotAfter  *time.Time `json:"notAfter,omitempty"`
	LastError string     `json:"lastError,omitempty"`
}

// Status liest das gespeicherte Let's-Encrypt-Zertifikat, ohne eines anzufordern.
func (c *Certs) Status() CertStatus {
	a := c.store.Settings().Web.ACME
	st := CertStatus{Enabled: a.Enabled, Domain: a.Domain}
	c.mu.Lock()
	st.LastError = c.lastErr
	c.mu.Unlock()
	if !a.Enabled || a.Domain == "" {
		return st
	}
	data, err := autocert.DirCache(c.acmeDir()).Get(context.Background(), a.Domain)
	if err != nil {
		return st
	}
	if cert := parseCachedCert(data); cert != nil {
		st.Issuer = cert.Issuer.CommonName
		if len(cert.Issuer.Organization) > 0 {
			st.Issuer = cert.Issuer.Organization[0] + " " + cert.Issuer.CommonName
		}
		na := cert.NotAfter
		st.NotAfter = &na
		st.Valid = time.Now().Before(cert.NotAfter)
		if st.Valid {
			st.LastError = ""
		}
	}
	return st
}

func parseCachedCert(data []byte) *x509.Certificate {
	// Der Cache enthält Schlüssel und Zertifikatskette als PEM.
	for {
		i := strings.Index(string(data), "-----BEGIN CERTIFICATE-----")
		if i < 0 {
			return nil
		}
		data = data[i:]
		if blk, rest := pemDecode(data); blk != nil {
			if cert, err := x509.ParseCertificate(blk); err == nil {
				return cert
			}
			data = rest
		} else {
			return nil
		}
	}
}

// Request fordert das Zertifikat jetzt an (für den Knopf in der Verwaltung).
func (c *Certs) Request(ctx context.Context) error {
	m := c.manager()
	if m == nil {
		return errors.New("Let's Encrypt ist nicht eingeschaltet")
	}
	domain := c.store.Settings().Web.ACME.Domain
	done := make(chan error, 1)
	go func() {
		_, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: domain, SupportedProtos: []string{"http/1.1"},
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			c.noteErr(err)
			c.mu.Lock()
			msg := c.lastErr
			c.mu.Unlock()
			if msg == "" {
				msg = explainACME(err)
			}
			return errors.New(msg)
		}
		c.mu.Lock()
		c.lastErr = ""
		c.mu.Unlock()
		c.log.Info("Let's Encrypt: Zertifikat für %s ist da", domain)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("Let's Encrypt antwortet nicht rechtzeitig, bitte später nochmals versuchen")
	}
}

func pemDecode(data []byte) ([]byte, []byte) {
	blk, rest := pem.Decode(data)
	if blk == nil {
		return nil, nil
	}
	return blk.Bytes, rest
}
