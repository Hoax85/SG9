// Package ui enthält die gemeinsamen Oberflächen (Admin, Browser-Client, Freigabe-Seite).
package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets pages
var files embed.FS

// Handler liefert /assets/… (CSS, Skripte, Logo).
func Handler() http.Handler {
	sub, _ := fs.Sub(files, "assets")
	fsrv := http.StripPrefix("/assets/", http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		fsrv.ServeHTTP(w, r)
	})
}

// ServePage liefert eine HTML-Seite aus pages/.
func ServePage(w http.ResponseWriter, name string) {
	b, err := files.ReadFile("pages/" + name)
	if err != nil {
		http.Error(w, "Seite fehlt", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}
