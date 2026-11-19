package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UpdateRepo: eingebautes GitHub-Projekt (owner/name), von main gesetzt.
var UpdateRepo = ""

var repoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

type updateState struct {
	mu      sync.Mutex
	latest  string
	url     string
	checked time.Time
	err     string
}

var upd updateState

func (a *Admin) updateRepo() string {
	st := a.store().Settings()
	if st.UpdateCheckOff {
		return ""
	}
	if r := strings.TrimSpace(st.UpdateRepo); r != "" {
		return r
	}
	return UpdateRepo
}

// StartUpdateCheck fragt einmal täglich bei GitHub nach der neusten Version.
// Es wird nichts heruntergeladen oder installiert, nur ein Hinweis angezeigt.
func (a *Admin) StartUpdateCheck() {
	go func() {
		time.Sleep(20 * time.Second)
		for {
			a.checkUpdate()
			time.Sleep(24 * time.Hour)
		}
	}()
}

func (a *Admin) checkUpdate() {
	repo := a.updateRepo()
	if repo == "" || !repoRe.MatchString(repo) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "SG9/"+Version)
	resp, err := http.DefaultClient.Do(req)
	upd.mu.Lock()
	defer upd.mu.Unlock()
	upd.checked = time.Now()
	if err != nil {
		upd.err = err.Error()
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		upd.err = fmt.Sprintf("GitHub antwortet mit %d", resp.StatusCode)
		return
	}
	var rel struct {
		Tag  string `json:"tag_name"`
		URL  string `json:"html_url"`
		Pre  bool   `json:"prerelease"`
		Draf bool   `json:"draft"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil || rel.Pre || rel.Draf {
		return
	}
	upd.latest, upd.url, upd.err = strings.TrimPrefix(rel.Tag, "v"), rel.URL, ""
	if newerVersion(upd.latest, Version) {
		a.Hub.Log.Info("Neue Version %s verfügbar: %s", upd.latest, upd.url)
	}
}

func (a *Admin) updateInfo() map[string]any {
	upd.mu.Lock()
	defer upd.mu.Unlock()
	out := map[string]any{"enabled": a.updateRepo() != ""}
	if upd.latest != "" && newerVersion(upd.latest, Version) {
		out["available"] = upd.latest
		out["url"] = upd.url
	}
	return out
}

// newerVersion: ist a neuer als b? (1.10.0 > 1.9.3)
func newerVersion(a, b string) bool {
	pa, pb := splitVer(a), splitVer(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func splitVer(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v = strings.SplitN(v, "-", 2)[0]
	for i, p := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}
