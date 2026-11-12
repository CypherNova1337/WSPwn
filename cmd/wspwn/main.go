// WSPwn drives a WebSocket assessment end to end: it discovers the endpoints a
// target really uses, fingerprints each one, runs the handshake-level security
// checks (CSWSH, auth model, transport), and — on request — learns each
// endpoint's normal behaviour and fuzzes it adaptively, getting sharper as it
// goes. Authorised testing only.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/CypherNova1337/WSPwn/internal/baseline"
	"github.com/CypherNova1337/WSPwn/internal/brain"
	"github.com/CypherNova1337/WSPwn/internal/discover"
	"github.com/CypherNova1337/WSPwn/internal/exploit"
	"github.com/CypherNova1337/WSPwn/internal/finding"
	"github.com/CypherNova1337/WSPwn/internal/fingerprint"
	"github.com/CypherNova1337/WSPwn/internal/recon"
	"github.com/CypherNova1337/WSPwn/internal/report"
	"github.com/CypherNova1337/WSPwn/internal/target"
	"github.com/CypherNova1337/WSPwn/internal/ui"
	"github.com/CypherNova1337/WSPwn/internal/wsx"
)

const version = "1.0.0"

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	var (
		url        = flag.String("u", "", "target URL (http(s):// or ws(s)://)")
		listFile   = flag.String("l", "", "file of targets, one per line")
		noCrawl    = flag.Bool("no-crawl", false, "don't read the page/JS for endpoints")
		noProbe    = flag.Bool("no-probe", false, "don't probe common WebSocket paths")
		cookie     = flag.String("cookie", "", "Cookie header for an authenticated session")
		evilOrigin = flag.String("origin", "https://wspwn-evil.example", "foreign Origin used for the CSWSH test")
		fuzz       = flag.Bool("fuzz", false, "learn each endpoint's baseline and fuzz it")
		seed       = flag.String("seed", "", "seed message to mutate (default: observed or framework greeting)")
		families   = flag.String("families", "", "restrict fuzzing to these families (csv)")
		budget     = flag.Int("budget", 400, "max fuzz sends per endpoint")
		noEscalate = flag.Bool("no-escalate", false, "don't spend extra budget where a field reacts")
		cswshDir   = flag.String("cswsh-poc", "", "write a CSWSH proof-of-concept HTML per hijackable endpoint into this dir")
		collector  = flag.String("collector", "", "URL the CSWSH PoC exfiltrates received frames to")
		memory     = flag.String("memory", "", "persist learned weights to this file and reuse them")
		proxy      = flag.String("proxy", "", "outbound proxy, e.g. http://127.0.0.1:8080")
		insecure   = flag.Bool("k", false, "skip TLS verification")
		timeout    = flag.Duration("timeout", 12*time.Second, "handshake timeout")
		idle       = flag.Duration("idle", 6*time.Second, "per-message read wait")
		jsonOut    = flag.String("json", "", "write the report as JSON to this file")
		noProgress = flag.Bool("no-progress", false, "disable the live status line")
		noColor    = flag.Bool("no-color", false, "disable colour")
		quiet      = flag.Bool("q", false, "quiet: findings only")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	var headers multiFlag
	var subprotos multiFlag
	flag.Var(&headers, "H", "extra handshake header 'Name: value' (repeatable)")
	flag.Var(&subprotos, "subproto", "Sec-WebSocket-Protocol to offer (repeatable)")
	flag.Parse()

	if *showVer {
		fmt.Printf("wspwn %s\n", version)
		return
	}
	if *noColor {
		ui.NoColor()
	}

	targets, err := gatherTargets(*url, *listFile)
	if err != nil || len(targets) == 0 {
		fmt.Fprintln(os.Stderr, ui.Red("error:"), "no target — pass -u URL or -l file")
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	kb, err := brain.Load(*memory)
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Yellow("warn:"), "could not load memory:", err)
		kb = brain.New()
	}

	base := wsx.Opts{
		Cookies:      *cookie,
		Headers:      parseHeaders(headers),
		Subprotocols: subprotos,
		Insecure:     *insecure,
		Proxy:        *proxy,
		UserAgent:    "WSPwn/" + version,
		Timeout:      *timeout,
	}

	cfg := runConfig{
		base: base, evilOrigin: *evilOrigin, cookie: *cookie,
		crawl: !*noCrawl, probe: !*noProbe, fuzz: *fuzz, seed: *seed,
		families: splitCSV(*families), budget: *budget, escalate: !*noEscalate,
		cswshDir: *cswshDir, collector: *collector, proxy: *proxy, insecure: *insecure,
		idle: *idle, timeout: *timeout, progress: !*noProgress && !*quiet,
	}

	var allFindings []finding.Finding
	for _, raw := range targets {
		t, err := target.Parse(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, ui.Red("skip:"), raw, "—", err)
			continue
		}
		run := assess(ctx, t, cfg, kb)
		allFindings = append(allFindings, run.Findings...)
		if !*quiet {
			report.Console(run)
		}
		if *jsonOut != "" {
			out := *jsonOut
			if len(targets) > 1 {
				out = numbered(*jsonOut, t.Host())
			}
			if err := report.JSON(run, out); err != nil {
				fmt.Fprintln(os.Stderr, ui.Yellow("warn:"), "json write:", err)
			} else if !*quiet {
				fmt.Fprintln(os.Stderr, ui.Dim("report → "+out))
			}
		}
	}

	if err := kb.Save(*memory); err != nil {
		fmt.Fprintln(os.Stderr, ui.Yellow("warn:"), "could not save memory:", err)
	}

	// Exit non-zero if anything High or above surfaced, for CI gating.
	for _, f := range allFindings {
		if f.Severity >= finding.High {
			os.Exit(1)
		}
	}
}

type runConfig struct {
	base               wsx.Opts
	evilOrigin, cookie string
	crawl, probe, fuzz bool
	seed               string
	families           []string
	budget             int
	escalate           bool
	cswshDir           string
	collector, proxy   string
	insecure           bool
	idle, timeout      time.Duration
	progress           bool
}

func assess(ctx context.Context, t *target.Target, cfg runConfig, kb *brain.Knowledge) report.Run {
	run := report.Run{Target: t.WSURL(), Started: time.Now()}
	prog := ui.NewProgress(cfg.progress)

	prog.Phase("Discovering endpoints")
	cands := discover.Run(ctx, t, discover.Options{
		Crawl: cfg.crawl, Probe: cfg.probe, Insecure: cfg.insecure,
		Proxy: cfg.proxy, UserAgent: cfg.base.UserAgent, Timeout: cfg.timeout,
	})

	for _, c := range cands {
		if ctx.Err() != nil {
			break
		}
		prog.Phase("Fingerprinting")
		prog.Tick(c.URL)

		// Baseline dial: same-origin, with any supplied cookie.
		ct, _ := target.Parse(c.URL)
		sameOrigin := ""
		if ct != nil {
			sameOrigin = ct.Origin()
		}
		o := cfg.base
		o.Origin = sameOrigin
		conn, hs, _ := wsx.Dial(ctx, c.URL, o)
		ep := report.Endpoint{URL: c.URL, Reachable: hs != nil && hs.Accepted}
		if !ep.Reachable {
			run.Endpoints = append(run.Endpoints, ep)
			continue
		}
		greet := wsx.Collect(conn, 4, 700*time.Millisecond)
		fp := fingerprint.Identify(pathOf(c.URL), hs.Subprotocol, greet)
		ep.Framework = string(fp.Framework)
		ep.Reason = fp.Reason
		ep.Subprotocol = hs.Subprotocol
		kb.NoteFramework(string(fp.Framework))
		if conn != nil {
			conn.Close()
		}

		// Recon checks.
		prog.Phase("Recon checks")
		fwGreeting := fingerprint.Greeting(fp.Framework)
		rr := recon.Run(ctx, c.URL, recon.Options{
			Cookies: cfg.cookie, EvilOrigin: cfg.evilOrigin, SameOrigin: sameOrigin,
			Greeting: fwGreeting, Base: cfg.base, Idle: cfg.idle,
		})
		ep.AuthModel = rr.AuthModel.String()
		run.Findings = append(run.Findings, rr.Findings...)
		for range rr.Findings {
			prog.Hit()
		}

		// CSWSH PoC generation.
		if cfg.cswshDir != "" && rr.OriginOpen && rr.AuthModel == recon.AuthCookie {
			if err := os.MkdirAll(cfg.cswshDir, 0o755); err == nil {
				pocPath := filepath.Join(cfg.cswshDir, "cswsh-"+safeName(c.URL)+".html")
				if err := exploit.WriteCSWSHPoC(pocPath, c.URL, fwGreeting, cfg.collector); err == nil && cfg.progress {
					fmt.Fprintln(os.Stderr, ui.Dim("\nPoC → "+pocPath))
				}
			}
		}

		// Adaptive fuzzing.
		if cfg.fuzz {
			fnd := fuzzEndpoint(ctx, c.URL, fp.Framework, cfg, kb, prog)
			run.Findings = append(run.Findings, fnd...)
		}

		run.Endpoints = append(run.Endpoints, ep)
	}

	prog.Clear()
	run.Finished = time.Now()
	run.Findings = dedupe(run.Findings)
	return run
}

func fuzzEndpoint(ctx context.Context, url string, fw fingerprint.Framework, cfg runConfig, kb *brain.Knowledge, prog *ui.Progress) []finding.Finding {
	prog.Phase("Learning baseline")
	o := cfg.base
	if ct, _ := target.Parse(url); ct != nil {
		o.Origin = ct.Origin()
	}
	greeting := fingerprint.Greeting(fw)
	sess := exploit.NewSession(url, o, greeting, cfg.idle)
	if err := sess.Connect(ctx); err != nil {
		return nil
	}
	defer sess.Close()

	prof := baseline.Learn(ctx, sess, cfg.idle)

	// Pick a seed message: explicit flag, else a sensible framework default.
	seed := cfg.seed
	if seed == "" {
		seed = seedFor(fw)
	}

	prog.Phase("Fuzzing")
	fz := &exploit.Fuzzer{
		Brain: kb, Profile: prof, Families: cfg.families,
		Budget: cfg.budget, Escalate: cfg.escalate, Idle: cfg.idle,
		OnSend: func(point, family, enc string) {
			prog.Tick(fmt.Sprintf("%s %s/%s", point, family, enc))
		},
	}
	fnd := fz.Run(ctx, sess, seed, url)
	for range fnd {
		prog.Hit()
	}
	return fnd
}

// seedFor is a minimal, framework-plausible message to mutate when the user
// didn't supply one and the server didn't volunteer a template.
func seedFor(fw fingerprint.Framework) string {
	switch fw {
	case fingerprint.GraphQLWS:
		return `{"id":"1","type":"subscribe","payload":{"query":"subscription{ping}"}}`
	case fingerprint.ActionCable:
		return `{"command":"message","identifier":"{\"channel\":\"Chat\"}","data":"{\"action\":\"speak\",\"id\":1,\"message\":\"hi\"}"}`
	case fingerprint.SocketIO:
		return `42["message",{"id":1,"text":"hi"}]`
	case fingerprint.Phoenix:
		return `["1","1","room:lobby","new_msg",{"id":1,"body":"hi"}]`
	default:
		return `{"id":1,"type":"message","action":"get","query":"hi"}`
	}
}

func gatherTargets(u, listFile string) ([]string, error) {
	var out []string
	if u != "" {
		out = append(out, u)
	}
	if listFile != "" {
		b, err := os.ReadFile(listFile)
		if err != nil {
			return nil, err
		}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln != "" && !strings.HasPrefix(ln, "#") {
				out = append(out, ln)
			}
		}
	}
	return out, nil
}

func parseHeaders(hs []string) http.Header {
	h := http.Header{}
	for _, raw := range hs {
		if i := strings.Index(raw, ":"); i > 0 {
			h.Add(strings.TrimSpace(raw[:i]), strings.TrimSpace(raw[i+1:]))
		}
	}
	return h
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func pathOf(wsurl string) string {
	if i := strings.Index(wsurl, "://"); i >= 0 {
		rest := wsurl[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			return rest[j:]
		}
	}
	return "/"
}

func safeName(u string) string {
	r := strings.NewReplacer("://", "_", "/", "_", ":", "_", "?", "_", "&", "_", "=", "_", ".", "-")
	s := r.Replace(u)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func numbered(base, host string) string {
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	return stem + "-" + strings.NewReplacer(":", "_", ".", "-").Replace(host) + ext
}

func dedupe(fs []finding.Finding) []finding.Finding {
	seen := map[string]bool{}
	var out []finding.Finding
	for _, f := range fs {
		k := f.Title + "|" + f.Endpoint + "|" + f.Severity.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
