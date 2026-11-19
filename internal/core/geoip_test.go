package core

import (
	"net"
	"path/filepath"
	"testing"
)

func TestGeoIPFilter(t *testing.T) {
	dir := t.TempDir()
	store, _, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := filepath.Abs("testdata/GeoIP2-Country-Test.mmdb")
	g := NewGeoIP(store, NewLogger("", true))
	set := func(allow []string, all bool) {
		if err := store.Update(func(c *Config) error {
			c.Settings.Web.Geo = GeoSettings{Enabled: true, DBPath: db, Allow: allow, AllProto: all}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	gb := net.ParseIP("81.2.69.160") // laut Testdatenbank: Grossbritannien

	set([]string{"CH"}, false)
	if cc, _ := g.Country(gb); cc != "GB" {
		t.Fatalf("Land %q, erwartet GB", cc)
	}
	if ok, _ := g.Allowed(gb, true); ok {
		t.Error("GB darf bei Erlaubt=CH keinen Link öffnen")
	}
	if ok, _ := g.Allowed(gb, false); !ok {
		t.Error("Filter gilt nur für Links, FTP & Co. müssen erlaubt sein")
	}
	if ok, _ := g.Allowed(net.ParseIP("192.168.1.20"), true); !ok {
		t.Error("Eigenes Netz muss immer erlaubt sein")
	}

	set([]string{"ch", "gb"}, true)
	if ok, _ := g.Allowed(gb, false); !ok {
		t.Error("GB ist erlaubt (Kleinschreibung)")
	}

	set([]string{"CH"}, true)
	if ok, _ := g.Allowed(gb, false); ok {
		t.Error("Mit „alle Dienste“ muss auch FTP gesperrt sein")
	}

	// Fehlende Datenbank: nicht sperren
	store.Update(func(c *Config) error { c.Settings.Web.Geo.DBPath = filepath.Join(dir, "fehlt.mmdb"); return nil })
	if ok, _ := g.Allowed(gb, true); !ok {
		t.Error("Ohne Datenbank darf nicht gesperrt werden")
	}
}
