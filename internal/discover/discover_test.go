package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CypherNova1337/WSPwn/internal/target"
)

func TestCrawlFindsNamedEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><script>
			var a = new WebSocket("wss://other.example/live");
			var p = "/notifications";
			connect("/api/ws");
		</script></body></html>`))
	}))
	defer srv.Close()

	tg, _ := target.Parse(srv.URL)
	cands := Run(context.Background(), tg, Options{Crawl: true, Probe: false})

	urls := map[string]bool{}
	for _, c := range cands {
		urls[c.URL] = true
	}
	if !urls["wss://other.example/live"] {
		t.Error("explicit wss:// URL not discovered")
	}
	// Relative socket paths resolve against the target host.
	foundNotif := false
	for u := range urls {
		if u == tg.WithPath("/notifications").WSURL() {
			foundNotif = true
		}
	}
	if !foundNotif {
		t.Errorf("relative /notifications path not resolved; got %v", urls)
	}
}

func TestSeedAlwaysIncludedAndRanksFirst(t *testing.T) {
	tg, _ := target.Parse("wss://x.test/ws")
	cands := Run(context.Background(), tg, Options{Crawl: false, Probe: true})
	if len(cands) == 0 || cands[0].URL != tg.WSURL() {
		t.Fatalf("seed should rank first, got %+v", cands)
	}
	// Probe paths should be present but lower-scored than the seed.
	if cands[0].Score <= cands[len(cands)-1].Score {
		t.Error("seed should outscore blind probes")
	}
}
