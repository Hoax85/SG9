# Mitmachen / Contributing

Beiträge sind willkommen, auf Deutsch oder Englisch. / Contributions are welcome, in German or English.

- **Fehler melden / bug reports:** Issue mit Version (`sg9 -version`), Betriebssystem und den passenden Zeilen aus dem Protokoll.
- **Übersetzungen / translations:** `internal/ui/i18n/sg9.tsv` – eine Zeile pro Text, Spalten Deutsch, English, Français, Italiano.
  Neue Sprache: Spalte anhängen und das Kürzel in `internal/ui/i18n.go` (`Languages`) eintragen.
- **Code:** `go vet ./...` und `go test ./...` müssen durchlaufen. Abhängigkeiten liegen in `vendor/` (`go mod vendor`).
- Die Oberfläche ist auf Deutsch geschrieben; neue Texte bitte gleich in `sg9.tsv` übersetzen.
  The UI source strings are German; please add new strings to `sg9.tsv` with translations.

Mit einem Beitrag bist du einverstanden, dass er unter der Lizenz des Projekts (AGPL-3.0) steht.
By contributing you agree that your contribution is licensed under the project license (AGPL-3.0).
