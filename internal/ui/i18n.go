package ui

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Übersetzungen: eine Tabelle mit Spalten Deutsch, Englisch, Französisch, Italienisch.
// Deutsch ist die Ausgangssprache. {} steht für einen veränderlichen Teil (Zahl, Name, …);
// in der Übersetzung werden die Teile der Reihe nach eingesetzt, oder gezielt mit {1}, {2}.
//
//go:embed i18n/sg9.tsv
var tsv []byte

// Languages: unterstützte Sprachen, Deutsch zuerst.
var Languages = []string{"de", "en", "fr", "it"}

type dict struct {
	Exact    map[string]string `json:"exact"`
	Patterns [][2]string       `json:"patterns"`
}

var (
	dictOnce sync.Once
	dicts    map[string][]byte
	dictsGo  map[string]*goDict
)

type goDict struct {
	exact map[string]string
	pats  []goPat
}

type goPat struct {
	re  *regexp.Regexp
	out string
}

var slotRe2 = regexp.MustCompile(`\$\d+`)

var slotRe = regexp.MustCompile(`\{(\d*|#)\}`)

// pattern wandelt "Noch {} Downloads" in einen regulären Ausdruck und die Ersetzung.
func pattern(de, tr string) (string, string) {
	// {} = beliebiger Text, {#} = Zahl
	var re strings.Builder
	re.WriteString("^")
	rest := de
	for {
		i := strings.Index(rest, "{")
		if i < 0 || !(strings.HasPrefix(rest[i:], "{}") || strings.HasPrefix(rest[i:], "{#}")) {
			if i < 0 {
				re.WriteString(regexp.QuoteMeta(rest))
				break
			}
			re.WriteString(regexp.QuoteMeta(rest[:i+1]))
			rest = rest[i+1:]
			continue
		}
		re.WriteString(regexp.QuoteMeta(rest[:i]))
		if strings.HasPrefix(rest[i:], "{#}") {
			re.WriteString("([0-9][0-9'’.,\u00a0\u202f ]*)") // auch Tausendertrennzeichen
			rest = rest[i+3:]
		} else {
			re.WriteString("(.+?)")
			rest = rest[i+2:]
		}
	}
	re.WriteString("$")
	n := 0
	out := slotRe.ReplaceAllStringFunc(tr, func(m string) string {
		if m == "{}" || m == "{#}" {
			n++
			return "$" + strconv.Itoa(n)
		}
		return "$" + m[1:len(m)-1]
	})
	return re.String(), out
}

func loadDicts() {
	dicts = map[string][]byte{}
	dictsGo = map[string]*goDict{}
	all := map[string]*dict{}
	for _, l := range Languages[1:] {
		all[l] = &dict{Exact: map[string]string{}}
		dictsGo[l] = &goDict{exact: map[string]string{}}
	}
	sc := bufio.NewScanner(bytes.NewReader(tsv))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 2 {
			continue
		}
		de := strings.ReplaceAll(cols[0], `\n`, "\n")
		for i, l := range Languages[1:] {
			if i+1 >= len(cols) || strings.TrimSpace(cols[i+1]) == "" {
				continue
			}
			tr := strings.ReplaceAll(cols[i+1], `\n`, "\n")
			if strings.Contains(de, "{}") || strings.Contains(de, "{#}") {
				re, out := pattern(de, tr)
				all[l].Patterns = append(all[l].Patterns, [2]string{re, out})
				if rx, err := regexp.Compile(re); err == nil {
					dictsGo[l].pats = append(dictsGo[l].pats, goPat{rx, out})
				}
			} else {
				all[l].Exact[de] = tr
				dictsGo[l].exact[de] = tr
			}
		}
	}
	// Genauere Muster zuerst: "Browser, WebDAV, Freigabe-Links auf {}" vor "{} auf {}"
	lit := func(p string) int { return len(slotRe.ReplaceAllString(p, "")) }
	for l, d := range all {
		sort.SliceStable(d.Patterns, func(i, j int) bool { return lit(d.Patterns[i][0]) > lit(d.Patterns[j][0]) })
		g := dictsGo[l]
		sort.SliceStable(g.pats, func(i, j int) bool { return lit(g.pats[i].re.String()) > lit(g.pats[j].re.String()) })
		b, _ := json.Marshal(d)
		dicts[l] = b
	}
}

// serveDict liefert /assets/i18n/<lang>.json.
func serveDict(w http.ResponseWriter, lang string) bool {
	dictOnce.Do(loadDicts)
	b, ok := dicts[lang]
	if !ok {
		return false
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
	return true
}

// Translate übersetzt eine deutsche Meldung (für Server-Texte wie Benachrichtigungen).
func Translate(lang, s string) string {
	dictOnce.Do(loadDicts)
	d := dictsGo[lang]
	if d == nil {
		return s
	}
	if t, ok := d.exact[s]; ok {
		return t
	}
	for _, p := range d.pats {
		if m := p.re.FindStringSubmatch(s); m != nil {
			// Teile, die selbst in der Tabelle stehen, mitübersetzen ("Freigabe verbunden")
			for i := 1; i < len(m); i++ {
				if t, ok := d.exact[m[i]]; ok {
					m[i] = t
				}
			}
			return slotRe2.ReplaceAllStringFunc(p.out, func(x string) string {
				n, _ := strconv.Atoi(x[1:])
				if n > 0 && n < len(m) {
					return m[n]
				}
				return x
			})
		}
	}
	return s
}
