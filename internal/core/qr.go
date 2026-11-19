package core

import (
	"fmt"
	"net/http"
	"strings"

	"rsc.io/qr"
)

// ServeQR liefert einen QR-Code für ?text= als SVG-Bild.
func ServeQR(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("text")
	if t == "" || len(t) > 1500 {
		http.Error(w, "text fehlt oder zu lang", http.StatusBadRequest)
		return
	}
	svg, err := QRSVG(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Write([]byte(svg))
}

// QRSVG erzeugt einen QR-Code als SVG (für Authenticator-Apps und Freigabe-Links).
func QRSVG(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	n := code.Size
	const quiet = 4
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, n+2*quiet, n+2*quiet)
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" fill="#fff"/><path fill="#000" d="`)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if code.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}
