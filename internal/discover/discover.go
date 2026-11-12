// Package discover finds the WebSocket endpoints a target actually uses rather
// than assuming them. It reads the landing page and the JavaScript it loads,
// pulls out every ws:// / wss:// URL and socket path the code refers to, and
// only then falls back to probing a curated list of conventional paths. The
// endpoints an app names in its own bundle are the ones that are really wired
// up — the probe list is the safety net, not the plan.
package discover

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/CypherNova1337/WSPwn/internal/target"
)

// Candidate is a discovered or probed endpoint and where it came from.
type Candidate struct {
	URL    string // ws:// or wss:// URL
	Source string // "page", "script:<url>", "probe"
	Score  int    // confidence: app-referenced beats blind probe
}

var (
	// Explicit ws/wss URLs anywhere in text.
	reWSURL = regexp.MustCompile(`(?i)\bwss?://[a-z0-9.\-]+(?::\d+)?(?:/[^\s"'` + "`" + `<>)\\]*)?`)
	// Path strings that look like socket endpoints, e.g. "/socket.io", "/cable".
	rePath = regexp.MustCompile(`["'` + "`" + `](/(?:[a-z0-9_\-./]*)?(?:ws|websocket|socket\.io|sockjs|signalr|hub|cable|graphql|subscriptions|stream|live|realtime|rt|mqtt|stomp|centrifugo|phoenix|notifications)[a-z0-9_\-./]*)["'` + "`" + `]`)
	// <script src="..."> references to pull and read in turn.
	reScript = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
)

// commonPaths are conventional WebSocket mount points, ordered roughly by how
// often they appear in the wild. Probed only when the app's own code is quiet.
var commonPaths = []string{
	"/ws", "/wss", "/websocket", "/socket", "/api/ws", "/api/websocket",
	"/socket.io/?EIO=4&transport=websocket", "/sockjs/websocket",
	"/cable", "/graphql", "/subscriptions", "/signalr", "/hub",
	"/ws/v1", "/v1/ws", "/live", "/stream", "/realtime", "/rt",
	"/notifications", "/chat", "/events", "/mqtt", "/stomp",
	"/centrifugo/connection/websocket", "/connection/websocket",
	"/app", "/phoenix", "/socket/websocket",
}

// Options tunes a discovery run.
type Options struct {
	Crawl     bool          // read page + scripts for named endpoints
	Probe     bool          // fall back to the common-path list
	MaxScript int           // how many <script src> files to fetch
	Insecure  bool          // skip TLS verification
	Proxy     string        // outbound proxy
	UserAgent string        //
	Timeout   time.Duration //
}

func (o Options) client() *http.Client {
	tr := &http.Transport{}
	if o.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // nolint:gosec
	}
	if o.Proxy != "" {
		if pu, err := url.Parse(o.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	to := o.Timeout
	if to <= 0 {
		to = 15 * time.Second
	}
	return &http.Client{Transport: tr, Timeout: to}
}

// Run returns the candidate endpoints for a target, highest-confidence first
// and de-duplicated. The seed target itself is always included.
func Run(ctx context.Context, t *target.Target, o Options) []Candidate {
	seen := map[string]*Candidate{}
	add := func(raw, source string, score int) {
		raw = strings.TrimRight(raw, "/.,);")
		if raw == "" {
			return
		}
		if c, ok := seen[raw]; ok {
			if score > c.Score {
				c.Score, c.Source = score, source
			}
			return
		}
		seen[raw] = &Candidate{URL: raw, Source: source, Score: score}
	}

	add(t.WSURL(), "seed", 100)

	if o.Crawl {
		cl := o.client()
		body := fetch(ctx, cl, t.HTTPURL(), o.UserAgent)
		harvest(body, t, "page", 60, add)

		// Follow a bounded number of same-interesting scripts.
		max := o.MaxScript
		if max <= 0 {
			max = 12
		}
		for i, src := range reScript.FindAllStringSubmatch(body, -1) {
			if i >= max {
				break
			}
			ju := absolute(t.HTTPURL(), src[1])
			if ju == "" {
				continue
			}
			js := fetch(ctx, cl, ju, o.UserAgent)
			harvest(js, t, "script:"+short(ju), 50, add)
		}
	}

	if o.Probe {
		for _, p := range commonPaths {
			add(t.WithPath(p).WSURL(), "probe", 10)
		}
	}

	out := make([]Candidate, 0, len(seen))
	for _, c := range seen {
		out = append(out, *c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].URL < out[j].URL
	})
	return out
}

// harvest extracts endpoints from one blob of text and feeds them to add. It
// resolves socket-looking paths against the target host so a relative "/cable"
// becomes a dialable wss:// URL.
func harvest(text string, t *target.Target, source string, score int, add func(raw, source string, score int)) {
	if text == "" {
		return
	}
	for _, m := range reWSURL.FindAllString(text, -1) {
		add(m, source, score+10)
	}
	for _, m := range rePath.FindAllStringSubmatch(text, -1) {
		add(t.WithPath(m[1]).WSURL(), source, score)
	}
}

func fetch(ctx context.Context, cl *http.Client, raw, ua string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return ""
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // cap at 4 MiB per asset
	return string(b)
}

func absolute(base, ref string) string {
	bu, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return bu.ResolveReference(ru).String()
}

func short(u string) string {
	if pu, err := url.Parse(u); err == nil {
		p := pu.Path
		if i := strings.LastIndex(p, "/"); i >= 0 {
			return p[i+1:]
		}
		return p
	}
	return u
}
