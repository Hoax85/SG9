package core

import (
	"net"
	"testing"
)

func TestPassword(t *testing.T) {
	h := HashPassword("geheim123")
	if !CheckPassword(h, "geheim123") || CheckPassword(h, "geheim124") || CheckPassword("", "") {
		t.Fatal("Passwortprüfung falsch")
	}
	if HashPassword("geheim123") == h {
		t.Fatal("gleiches Passwort muss verschiedene Hashes geben (Salz)")
	}
}

func TestCleanVirtual(t *testing.T) {
	for in, want := range map[string]string{
		"": "/", "/": "/", "a/b": "/a/b", "/a/../..": "/", "../../etc/passwd": "/etc/passwd", `a\..\..\b`: "/b", "/a//b/": "/a/b",
	} {
		if got := CleanVirtual(in); got != want {
			t.Errorf("CleanVirtual(%q) = %q, erwartet %q", in, got, want)
		}
	}
}

func TestIPAllowed(t *testing.T) {
	ip := net.ParseIP("192.168.1.20")
	cases := []struct {
		allow, deny []string
		want        bool
	}{
		{nil, nil, true},
		{[]string{"192.168.1.*"}, nil, true},
		{[]string{"10.0.0.0/8"}, nil, false},
		{nil, []string{"192.168.0.0/16"}, false},
		{[]string{"192.168.1.*"}, []string{"192.168.1.20"}, false},
	}
	for _, c := range cases {
		if got := IPAllowed(c.allow, c.deny, ip); got != c.want {
			t.Errorf("IPAllowed(%v, %v) = %v", c.allow, c.deny, got)
		}
	}
}

func TestCheckPorts(t *testing.T) {
	st := Settings{ListenAddr: ":2121", FTPEnabled: true, PassivePortMin: 50000, PassivePortMax: 50100}
	st.SFTP = SFTPSettings{Enabled: true, ListenAddr: ":2222"}
	st.Web = WebSettings{Enabled: true, ListenAddr: ":8080", WebClient: true, WebDAV: true, Shares: true}
	st.Admin = AdminSettings{ListenAddr: "127.0.0.1:8021"}
	if err := CheckPorts(st); err != nil {
		t.Fatalf("gültige Ports abgelehnt: %v", err)
	}
	bad := st
	bad.SFTP.ListenAddr = ":2121"
	if CheckPorts(bad) == nil {
		t.Error("doppelter Port nicht erkannt")
	}
	bad = st
	bad.Web.ListenAddr = ":50050"
	if CheckPorts(bad) == nil {
		t.Error("Port im Passivbereich nicht erkannt")
	}
}
