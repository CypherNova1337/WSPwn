package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CypherNova1337/WSPwn/internal/finding"
	"github.com/CypherNova1337/WSPwn/internal/wsx"
	"github.com/gorilla/websocket"
)

// cswshServer authenticates with a cookie and accepts any Origin — the exact
// shape of a CSWSH-vulnerable endpoint.
func cswshServer() *httptest.Server {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c.Close()
	}))
}

func wsURL(s *httptest.Server) string { return "ws" + strings.TrimPrefix(s.URL, "http") }

func TestDetectsCSWSH(t *testing.T) {
	srv := cswshServer()
	defer srv.Close()
	url := wsURL(srv)

	rep := Run(context.Background(), url, Options{
		Cookies:    "session=victim",
		EvilOrigin: "https://evil.example",
		SameOrigin: strings.Replace(srv.URL, "http", "http", 1),
		Base:       wsx.Opts{Timeout: 3 * time.Second},
		Idle:       2 * time.Second,
	})

	if rep.AuthModel != AuthCookie {
		t.Fatalf("auth model = %v, want cookie", rep.AuthModel)
	}
	if !rep.OriginOpen {
		t.Fatal("expected origin to be accepted")
	}
	if !hasFinding(rep.Findings, "Cross-Site WebSocket Hijacking", finding.High) {
		t.Fatalf("CSWSH High finding not raised: %+v", rep.Findings)
	}
}

// strictServer validates Origin, so it must NOT be flagged for CSWSH.
func TestNoCSWSHWhenOriginChecked(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
		return r.Header.Get("Origin") == "" || strings.Contains(r.Header.Get("Origin"), "127.0.0.1")
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value == "" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c.Close()
	}))
	defer srv.Close()

	rep := Run(context.Background(), wsURL(srv), Options{
		Cookies: "session=victim", EvilOrigin: "https://evil.example",
		SameOrigin: "http://127.0.0.1", Base: wsx.Opts{Timeout: 3 * time.Second}, Idle: time.Second,
	})
	if hasFinding(rep.Findings, "Cross-Site WebSocket Hijacking", finding.High) {
		t.Fatalf("CSWSH should not be flagged when Origin is validated: %+v", rep.Findings)
	}
}

func hasFinding(fs []finding.Finding, titlePart string, sev finding.Severity) bool {
	for _, f := range fs {
		if strings.Contains(f.Title, titlePart) && f.Severity == sev {
			return true
		}
	}
	return false
}
