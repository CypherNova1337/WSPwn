// Package recon runs the handshake-level security checks that decide whether an
// endpoint is worth attacking and how. The marquee check is Cross-Site
// WebSocket Hijacking, which this package reasons about rather than guesses at:
// an endpoint that simply accepts any Origin is only a problem if it also
// authenticates with cookies, so WSPwn establishes the auth model first and
// only then judges the Origin behaviour against it.
package recon

import (
	"context"
	"strings"
	"time"

	"github.com/CypherNova1337/WSPwn/internal/finding"
	"github.com/CypherNova1337/WSPwn/internal/wsx"
)

// AuthModel is what the endpoint appears to use to tell users apart.
type AuthModel int

const (
	AuthUnknown AuthModel = iota
	AuthNone              // accepts a connection with no credentials
	AuthCookie            // needs the cookie; rejected without it
	AuthToken             // needs a token header/param; cookie alone insufficient
)

func (a AuthModel) String() string {
	switch a {
	case AuthNone:
		return "none (open)"
	case AuthCookie:
		return "cookie"
	case AuthToken:
		return "token"
	default:
		return "unknown"
	}
}

// Report is the full recon picture for one endpoint.
type Report struct {
	Endpoint   string
	AuthModel  AuthModel
	OriginOpen bool // handshake accepted with a foreign Origin
	NullOrigin bool // handshake accepted with Origin: null
	Findings   []finding.Finding
}

// Options carries the credentials and knobs recon needs.
type Options struct {
	Cookies    string // the authenticated session, if the user supplied one
	EvilOrigin string // the attacker origin to test with (defaults applied by caller)
	SameOrigin string // the legitimate origin for this endpoint
	Greeting   string // framework opener, so a session actually establishes
	Base       wsx.Opts
	Idle       time.Duration
}

// Run performs the checks and returns a Report. It opens several short-lived
// connections with different credentials and compares the outcomes.
func Run(ctx context.Context, endpoint string, o Options) Report {
	r := Report{Endpoint: endpoint, AuthModel: AuthUnknown}

	// 1. Transport: is it encrypted at all?
	if strings.HasPrefix(endpoint, "ws://") {
		r.Findings = append(r.Findings, finding.Finding{
			Title: "Unencrypted WebSocket (ws://)", Severity: finding.Medium, Endpoint: endpoint,
			Detail:   "The endpoint is offered over plaintext ws://, so messages and any token or cookie in the handshake cross the network in the clear.",
			Evidence: endpoint,
			Remedy:   "Serve the socket over wss:// (TLS) only and redirect or refuse ws://.",
		})
	}

	// 2. Auth model: does it need credentials, and of what kind?
	anon := dialAccepts(ctx, endpoint, withOrigin(o.Base, o.SameOrigin, "")) // same origin, no cookie
	authed := true
	if o.Cookies != "" {
		authed = dialAccepts(ctx, endpoint, withOrigin(o.Base, o.SameOrigin, o.Cookies))
	}
	switch {
	case anon:
		r.AuthModel = AuthNone
		r.Findings = append(r.Findings, finding.Finding{
			Title: "Unauthenticated WebSocket access", Severity: finding.Medium, Endpoint: endpoint,
			Detail:   "The handshake succeeds with no session cookie or token. Any client on the internet can open this socket.",
			Evidence: "handshake accepted with no credentials",
			Remedy:   "Require and verify an authenticated session on the upgrade request; reject anonymous handshakes.",
		})
	case o.Cookies != "" && authed:
		r.AuthModel = AuthCookie
	case o.Cookies != "":
		r.AuthModel = AuthToken // cookie present but still rejected -> something else gates it
	}

	// 3. Origin handling, judged against the auth model.
	hsEvil := dialHS(ctx, endpoint, withOrigin(o.Base, o.EvilOrigin, o.Cookies))
	hsNull := dialHS(ctx, endpoint, withOrigin(o.Base, "null", o.Cookies))
	r.OriginOpen = hsEvil != nil && hsEvil.Accepted
	r.NullOrigin = hsNull != nil && hsNull.Accepted

	switch {
	case r.OriginOpen && r.AuthModel == AuthCookie:
		r.Findings = append(r.Findings, finding.Finding{
			Title: "Cross-Site WebSocket Hijacking (CSWSH)", Severity: finding.High, Endpoint: endpoint,
			Detail:   "Authentication rides on the cookie, which the browser attaches automatically, and the server accepts a handshake from a foreign Origin. A page on an attacker's site can therefore open this socket as a logged-in victim and read or drive their session.",
			Evidence: "handshake accepted with Origin: " + o.EvilOrigin + " and the victim cookie",
			Remedy:   "Validate the Origin header against an allowlist on the upgrade, and/or require a CSRF-style token in the first message that a cross-site page cannot read.",
		})
	case r.OriginOpen && r.AuthModel == AuthNone:
		r.Findings = append(r.Findings, finding.Finding{
			Title: "No Origin validation", Severity: finding.Low, Endpoint: endpoint,
			Detail:   "The server accepts handshakes from any Origin. On its own this is low risk because the endpoint is already unauthenticated, but it removes a defence-in-depth control and becomes serious the moment auth is added.",
			Evidence: "handshake accepted with Origin: " + o.EvilOrigin,
			Remedy:   "Validate Origin against an allowlist even on open endpoints.",
		})
	case r.OriginOpen:
		r.Findings = append(r.Findings, finding.Finding{
			Title: "Origin header not validated", Severity: finding.Medium, Endpoint: endpoint,
			Detail:   "A foreign Origin is accepted. If any request-borne credential (cookie, HTTP auth) authenticates the socket, this is cross-site hijackable.",
			Evidence: "handshake accepted with Origin: " + o.EvilOrigin,
			Remedy:   "Validate Origin against an allowlist on the upgrade request.",
		})
	}

	return r
}

func withOrigin(base wsx.Opts, origin, cookies string) wsx.Opts {
	o := base
	o.Origin = origin
	o.Cookies = cookies
	return o
}

func dialHS(ctx context.Context, url string, o wsx.Opts) *wsx.Handshake {
	conn, hs, _ := wsx.Dial(ctx, url, o)
	if conn != nil {
		conn.Close()
	}
	return hs
}

func dialAccepts(ctx context.Context, url string, o wsx.Opts) bool {
	hs := dialHS(ctx, url, o)
	return hs != nil && hs.Accepted
}
