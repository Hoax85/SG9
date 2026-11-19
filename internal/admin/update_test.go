package admin

import "testing"

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2.4.0", "2.3.1", true}, {"2.3.1", "2.3.1", false}, {"2.10.0", "2.9.9", true},
		{"v3.0.0", "2.9.0", true}, {"2.3.0", "2.3.1", false}, {"2.4.0-rc1", "2.3.9", true},
	}
	for _, c := range cases {
		if got := newerVersion(c.a, c.b); got != c.want {
			t.Errorf("newerVersion(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
