package target

import "testing"

func TestParseNormalises(t *testing.T) {
	cases := []struct {
		in, wsURL, httpURL, origin string
		secure                     bool
	}{
		{"https://x.test/ws", "wss://x.test/ws", "https://x.test/ws", "https://x.test", true},
		{"http://x.test/ws", "ws://x.test/ws", "http://x.test/ws", "http://x.test", false},
		{"wss://x.test/s?a=1", "wss://x.test/s?a=1", "https://x.test/s?a=1", "https://x.test", true},
		{"x.test:8080", "wss://x.test:8080/", "https://x.test:8080/", "https://x.test:8080", true},
	}
	for _, c := range cases {
		tg, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if tg.WSURL() != c.wsURL {
			t.Errorf("%q WSURL = %q, want %q", c.in, tg.WSURL(), c.wsURL)
		}
		if tg.HTTPURL() != c.httpURL {
			t.Errorf("%q HTTPURL = %q, want %q", c.in, tg.HTTPURL(), c.httpURL)
		}
		if tg.Origin() != c.origin {
			t.Errorf("%q Origin = %q, want %q", c.in, tg.Origin(), c.origin)
		}
		if tg.Secure() != c.secure {
			t.Errorf("%q Secure = %v, want %v", c.in, tg.Secure(), c.secure)
		}
	}
}

func TestWithPath(t *testing.T) {
	tg, _ := Parse("wss://x.test/a")
	if got := tg.WithPath("cable").WSURL(); got != "wss://x.test/cable" {
		t.Errorf("WithPath = %q", got)
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "ftp://x.test"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) should error", in)
		}
	}
}
