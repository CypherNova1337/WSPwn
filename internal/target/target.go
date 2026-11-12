// Package target normalises whatever URL the user typed into the two views
// WSPwn needs: the ws:// form to dial and the http:// form to crawl. A target
// handed in as https://, wss:// or a bare host all resolve the same way.
package target

import (
	"fmt"
	"net/url"
	"strings"
)

// Target is one endpoint under test, kept in both schemes plus the origin the
// browser would send for it.
type Target struct {
	raw    string
	scheme string // ws or wss
	host   string // host[:port]
	path   string // path?query
}

// Parse accepts http(s)://, ws(s):// or a scheme-less host and returns a
// normalised Target. A scheme-less input is assumed TLS (wss).
func Parse(raw string) (*Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "wss://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", raw, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("no host in %q", raw)
	}
	t := &Target{raw: raw, host: u.Host}
	switch strings.ToLower(u.Scheme) {
	case "ws", "http":
		t.scheme = "ws"
	case "wss", "https":
		t.scheme = "wss"
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	t.path = u.EscapedPath()
	if t.path == "" {
		t.path = "/"
	}
	if u.RawQuery != "" {
		t.path += "?" + u.RawQuery
	}
	return t, nil
}

// WSURL is the ws:// or wss:// URL to hand to a WebSocket dialer.
func (t *Target) WSURL() string { return t.scheme + "://" + t.host + t.path }

// HTTPURL is the http:// or https:// URL to crawl for endpoint discovery.
func (t *Target) HTTPURL() string {
	s := "http"
	if t.scheme == "wss" {
		s = "https"
	}
	return s + "://" + t.host + t.path
}

// Host returns host[:port].
func (t *Target) Host() string { return t.host }

// Secure reports whether the transport is TLS (wss).
func (t *Target) Secure() bool { return t.scheme == "wss" }

// Origin is the same-site Origin header a legitimate page on this host would
// send during the handshake.
func (t *Target) Origin() string {
	s := "http"
	if t.scheme == "wss" {
		s = "https"
	}
	return s + "://" + t.host
}

// WithPath returns a copy of the target pointed at a different path (used by
// endpoint probing), leaving scheme and host intact.
func (t *Target) WithPath(path string) *Target {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return &Target{raw: t.raw, scheme: t.scheme, host: t.host, path: path}
}
