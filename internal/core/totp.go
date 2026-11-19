package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Zwei-Faktor-Anmeldung nach RFC 6238 (TOTP): 6 Ziffern, 30 Sekunden, SHA-1.
// So funktioniert es mit Aegis, Google Authenticator, Bitwarden, 1Password usw.

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret erzeugt ein zufälliges Geheimnis (160 Bit).
func NewTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

// TOTPURI liefert die Adresse für den QR-Code der Authenticator-App.
func TOTPURI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func totpAt(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	h := m.Sum(nil)
	off := h[len(h)-1] & 0x0f
	v := binary.BigEndian.Uint32(h[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

// TOTPCode liefert den aktuellen Code (für Tests).
func TOTPCode(secret string, t time.Time) string {
	key, _ := b32.DecodeString(strings.ToUpper(secret))
	return totpAt(key, uint64(t.Unix()/30))
}

// CheckTOTP prüft einen Code mit ±1 Zeitfenster Toleranz und liefert das verwendete Fenster.
// lastUsed verhindert, dass derselbe Code zweimal benutzt wird.
func CheckTOTP(secret, code string, now time.Time, lastUsed int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	cur := now.Unix() / 30
	for _, d := range []int64{0, -1, 1} {
		c := cur + d
		if c <= lastUsed {
			continue
		}
		if hmac.Equal([]byte(totpAt(key, uint64(c))), []byte(code)) {
			return c, true
		}
	}
	return 0, false
}

// NewRecoveryCodes erzeugt Einmal-Codes für den Fall, dass das Handy weg ist.
func NewRecoveryCodes(n int) []string {
	const chars = "abcdefghjkmnpqrstuvwxyz23456789"
	out := make([]string, n)
	for i := range out {
		b := make([]byte, 10)
		_, _ = rand.Read(b)
		for j := range b {
			b[j] = chars[int(b[j])%len(chars)]
		}
		out[i] = string(b[:5]) + "-" + string(b[5:])
	}
	return out
}
