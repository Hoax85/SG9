package web

import "testing"

func TestSafeInline(t *testing.T) {
	for ct, want := range map[string]bool{
		"image/jpeg": true, "image/png": true, "video/mp4": true, "audio/mpeg": true, "application/pdf": true,
		"text/plain; charset=utf-8": true, "image/svg+xml": false, "text/html": false, "application/javascript": false,
		"application/xhtml+xml": false, "": false,
	} {
		if got := SafeInline(ct); got != want {
			t.Errorf("SafeInline(%q) = %v", ct, got)
		}
	}
}

func TestSenderName(t *testing.T) {
	for in, want := range map[string]string{
		"Anna Müller": "Anna Müller", "../../etc": "etc", "  a   b  ": "a b", "<script>": "script", "..": "", "Firma & Co.": "Firma & Co",
	} {
		if got := senderName(in); got != want {
			t.Errorf("senderName(%q) = %q, erwartet %q", in, got, want)
		}
	}
}
