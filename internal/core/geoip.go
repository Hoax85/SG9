package core

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// GeoSettings: Zugriffe nur aus bestimmten Ländern zulassen.
type GeoSettings struct {
	Enabled  bool     `json:"enabled"`
	DBPath   string   `json:"dbPath"`   // .mmdb von DB-IP (Lite) oder MaxMind GeoLite2 Country
	Allow    []string `json:"allow"`    // ISO-Codes, z. B. CH, DE, AT
	AllProto bool     `json:"allProto"` // false = nur Freigabe-Links, true = alle Dienste
}

// GeoIP prüft Länder anhand einer lokalen Datenbank. Private Adressen sind immer erlaubt.
type GeoIP struct {
	store *Store
	log   *Logger

	mu     sync.Mutex
	db     *maxminddb.Reader
	dbPath string
	dbMod  time.Time
	err    string
}

// NewGeoIP erstellt den Länderfilter.
func NewGeoIP(store *Store, log *Logger) *GeoIP { return &GeoIP{store: store, log: log} }

func (g *GeoIP) reader(path string) (*maxminddb.Reader, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("Datenbank %s nicht gefunden", path)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.db != nil && g.dbPath == path && g.dbMod.Equal(fi.ModTime()) {
		return g.db, nil
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		g.err = "Datenbank lässt sich nicht lesen: " + err.Error()
		return nil, errors.New(g.err)
	}
	if g.db != nil {
		g.db.Close()
	}
	g.db, g.dbPath, g.dbMod, g.err = db, path, fi.ModTime(), ""
	return db, nil
}

// Country liefert den ISO-Code eines Landes oder "".
func (g *GeoIP) Country(ip net.IP) (string, error) {
	st := g.store.Settings().Web.Geo
	if st.DBPath == "" {
		return "", errors.New("keine Datenbank eingetragen")
	}
	db, err := g.reader(st.DBPath)
	if err != nil {
		return "", err
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := db.Lookup(ip, &rec); err != nil {
		return "", err
	}
	return strings.ToUpper(rec.Country.ISOCode), nil
}

// Allowed prüft eine Adresse. links=true für Freigabe-Links, false für die übrigen Dienste.
// Ist die Datenbank kaputt oder fehlt sie, wird nicht gesperrt (aber gewarnt).
func (g *GeoIP) Allowed(ip net.IP, links bool) (bool, string) {
	st := g.store.Settings().Web.Geo
	if !st.Enabled || len(st.Allow) == 0 || (!links && !st.AllProto) {
		return true, ""
	}
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true, ""
	}
	cc, err := g.Country(ip)
	if err != nil {
		g.mu.Lock()
		first := g.err != err.Error()
		g.err = err.Error()
		g.mu.Unlock()
		if first {
			g.log.Error("Länderfilter: %v. Zugriffe werden nicht gefiltert.", err)
		}
		return true, ""
	}
	for _, a := range st.Allow {
		if strings.EqualFold(strings.TrimSpace(a), cc) {
			return true, cc
		}
	}
	if cc == "" {
		cc = "unbekannt"
	}
	return false, cc
}

// Status für die Verwaltung.
func (g *GeoIP) Status() map[string]any {
	st := g.store.Settings().Web.Geo
	out := map[string]any{"enabled": st.Enabled, "ok": false}
	if st.DBPath == "" {
		out["message"] = "Noch keine Datenbank eingetragen."
		return out
	}
	db, err := g.reader(st.DBPath)
	if err != nil {
		out["message"] = err.Error()
		return out
	}
	out["ok"] = true
	out["message"] = fmt.Sprintf("%s vom %s", db.Metadata.DatabaseType, time.Unix(int64(db.Metadata.BuildEpoch), 0).Format("02.01.2006"))
	return out
}
