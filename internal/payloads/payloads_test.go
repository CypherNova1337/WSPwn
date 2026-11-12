package payloads

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestForStampsMarker(t *testing.T) {
	ps := For(XSS, "MARK")
	var sawMarker bool
	for _, p := range ps {
		if strings.Contains(p.Value, "MARK") {
			sawMarker = true
		}
	}
	if !sawMarker {
		t.Error("expected at least one XSS payload to embed the marker")
	}
}

func TestForSentinels(t *testing.T) {
	ps := For(JSONType, "M")
	for _, p := range ps {
		if p.Sentinel == "" {
			t.Errorf("jsontype payload %q should carry a sentinel", p.Value)
		}
	}
}

func TestEncode(t *testing.T) {
	if got := Encode("base64", "ab"); got != base64.StdEncoding.EncodeToString([]byte("ab")) {
		t.Errorf("base64 encode = %q", got)
	}
	if got := Encode("url", "a b"); got != "a+b" {
		t.Errorf("url encode = %q", got)
	}
	if got := Encode("none", "x<y"); got != "x<y" {
		t.Errorf("none encode changed value: %q", got)
	}
	if got := Encode("unicode", "<x>"); !strings.Contains(got, `\u003c`) {
		t.Errorf("unicode encode should escape angle brackets: %q", got)
	}
}

func TestFamiliesStable(t *testing.T) {
	if len(Families()) == 0 {
		t.Fatal("Families must not be empty")
	}
	seen := map[string]bool{}
	for _, f := range Families() {
		if seen[f] {
			t.Errorf("duplicate family %q", f)
		}
		seen[f] = true
		if len(base[f]) == 0 {
			t.Errorf("family %q has no payloads", f)
		}
	}
}
