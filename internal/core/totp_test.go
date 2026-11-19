package core

import (
	"encoding/base32"
	"testing"
	"time"
)

// Prüfwerte aus RFC 6238, Anhang B (SHA-1), auf 6 Stellen gekürzt.
func TestTOTPRFC6238(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037", 20000000000: "353130"}
	for ts, want := range cases {
		if got := TOTPCode(secret, time.Unix(ts, 0)); got != want {
			t.Errorf("T=%d: %s, erwartet %s", ts, got, want)
		}
	}
}

func TestTOTPWindowAndReplay(t *testing.T) {
	s := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	prev := TOTPCode(s, now.Add(-30*time.Second))
	c, ok := CheckTOTP(s, prev, now, 0)
	if !ok {
		t.Fatal("Code aus dem vorigen Fenster sollte gelten")
	}
	if _, ok := CheckTOTP(s, prev, now, c); ok {
		t.Fatal("Derselbe Code darf nicht zweimal gelten")
	}
	if _, ok := CheckTOTP(s, TOTPCode(s, now.Add(-90*time.Second)), now, 0); ok {
		t.Fatal("Zu alter Code darf nicht gelten")
	}
	if _, ok := CheckTOTP(s, "12345", now, 0); ok {
		t.Fatal("Fünfstelliger Code darf nicht gelten")
	}
}
