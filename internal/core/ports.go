package core

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Listener beschreibt einen Dienst mit seiner Adresse.
type Listener struct {
	ID   string // ftp, ftps, sftp, web, dav, share, admin
	Name string
	Addr string
}

// SplitAddr zerlegt "host:port" (host darf leer sein).
func SplitAddr(addr string) (host string, port int, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", 0, fmt.Errorf("Adresse fehlt")
	}
	if !strings.Contains(addr, ":") {
		addr = ":" + addr // nur Port angegeben
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("%q ist keine gültige Adresse (Beispiel :2121 oder 192.168.1.10:2121)", addr)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("Port %q ungültig (1–65535)", p)
	}
	if h == "0.0.0.0" || h == "::" || h == "*" {
		h = ""
	}
	return h, n, nil
}

// ActiveListeners liefert alle eingeschalteten Dienste mit ihren Adressen.
// Web-Dienste mit derselben Adresse teilen sich bewusst einen Port.
func ActiveListeners(st Settings) []Listener {
	var out []Listener
	if st.FTPEnabled {
		out = append(out, Listener{"ftp", "FTP", st.ListenAddr})
		if st.TLS.ImplicitAddr != "" {
			out = append(out, Listener{"ftps", "FTPS implizit", st.TLS.ImplicitAddr})
		}
	}
	if st.SFTP.Enabled {
		out = append(out, Listener{"sftp", "SFTP", st.SFTP.ListenAddr})
	}
	if st.Web.Enabled {
		if st.Web.WebClient {
			out = append(out, Listener{"web", "Browser", st.Web.ListenAddr})
		}
		if st.Web.WebDAV {
			out = append(out, Listener{"dav", "WebDAV", st.Web.EffectiveDav()})
		}
		if st.Web.Shares {
			out = append(out, Listener{"share", "Freigabe-Links", st.Web.EffectiveShare()})
		}
	}
	out = append(out, Listener{"admin", "Verwaltung", st.Admin.ListenAddr})
	return out
}

func isWeb(id string) bool { return id == "web" || id == "dav" || id == "share" }

func hostsOverlap(a, b string) bool { return a == "" || b == "" || strings.EqualFold(a, b) }

// CheckPorts prüft Adressen und Portkonflikte zwischen den Diensten.
func CheckPorts(st Settings) error {
	ls := ActiveListeners(st)
	type parsed struct {
		Listener
		host string
		port int
	}
	var ps []parsed
	for _, l := range ls {
		h, p, err := SplitAddr(l.Addr)
		if err != nil {
			return fmt.Errorf("%s: %v", l.Name, err)
		}
		ps = append(ps, parsed{l, h, p})
	}
	for i := 0; i < len(ps); i++ {
		for j := i + 1; j < len(ps); j++ {
			a, b := ps[i], ps[j]
			if a.port != b.port || !hostsOverlap(a.host, b.host) {
				continue
			}
			// Browser, WebDAV und Links dürfen sich einen Port teilen, wenn die Adresse identisch ist.
			if isWeb(a.ID) && isWeb(b.ID) && a.host == b.host {
				continue
			}
			return fmt.Errorf("Port %d ist doppelt vergeben: %s und %s", a.port, a.Name, b.Name)
		}
	}
	if st.FTPEnabled {
		for _, p := range ps {
			if p.port >= st.PassivePortMin && p.port <= st.PassivePortMax {
				return fmt.Errorf("Port %d von %s liegt im FTP-Passivbereich %d–%d", p.port, p.Name, st.PassivePortMin, st.PassivePortMax)
			}
		}
	}
	return nil
}

// NormAddr vereinheitlicht eine Adresse für Vergleiche (":8080" == "0.0.0.0:8080").
func NormAddr(addr string) string {
	h, p, err := SplitAddr(addr)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(h, strconv.Itoa(p))
}
