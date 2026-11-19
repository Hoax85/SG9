package ui

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestTranslations(t *testing.T) {
	dictOnce.Do(loadDicts)
	for _, l := range Languages[1:] {
		var d dict
		if err := json.Unmarshal(dicts[l], &d); err != nil {
			t.Fatal(err)
		}
		if len(d.Exact) < 400 {
			t.Errorf("%s: nur %d Einträge", l, len(d.Exact))
		}
		for _, p := range d.Patterns {
			if _, err := regexp.Compile(p[0]); err != nil {
				t.Errorf("%s: Muster %q: %v", l, p[0], err)
			}
		}
	}
	cases := map[string][2]string{
		"Speichern":                       {"en", "Save"},
		"Noch 3 Downloads":                {"fr", "Encore 3 téléchargements"},
		"5 von 10":                        {"it", "5 di 10"},
		"Benutzer anna existiert bereits": {"en", "User anna already exists"},
		"Nachricht von Anna":              {"en", "Nachricht von Anna"}, // kein Treffer: bleibt
		"Port 21 ist doppelt vergeben: FTP und SFTP": {"fr", "Le port 21 est attribué deux fois : FTP et SFTP"},
	}
	for in, want := range cases {
		if got := Translate(want[0], in); got != want[1] {
			t.Errorf("%s %q = %q, erwartet %q", want[0], in, got, want[1])
		}
	}
	// Jede Zeile muss vier Spalten haben, Platzhalter müssen übereinstimmen
	for i, line := range strings.Split(string(tsv), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) != len(Languages) {
			t.Errorf("Zeile %d: %d Spalten", i+1, len(c))
			continue
		}
		n := len(slotRe.FindAllString(c[0], -1))
		for j := 1; j < len(c); j++ {
			if m := len(slotRe.FindAllString(c[j], -1)); m != n {
				t.Errorf("Zeile %d (%s): Platzhalter %d statt %d in %q", i+1, Languages[j], m, n, c[j])
			}
		}
	}
}
