// Package wsx wraps the WebSocket dialer so the rest of WSPwn can open a
// connection and, win or lose, get back a structured record of what the
// handshake actually did — the HTTP status, the negotiated subprotocol,
// whether compression was agreed, and the server's response headers. The
// security checks lean on that record far more than on the live socket.
package wsx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Handshake is the outcome of a dial attempt, whether or not it upgraded.
type Handshake struct {
	URL         string      `json:"url"`
	Accepted    bool        `json:"accepted"`
	Status      int         `json:"status"`
	StatusText  string      `json:"status_text"`
	Subprotocol string      `json:"subprotocol,omitempty"`
	Compression bool        `json:"compression"`
	Server      string      `json:"server,omitempty"`
	Headers     http.Header `json:"-"`
	Err         string      `json:"error,omitempty"`
}

// Opts controls a single dial: who we claim to be and how we reach the host.
type Opts struct {
	Origin       string        // Origin header; empty sends none
	Cookies      string        // raw Cookie header value
	Headers      http.Header   // extra request headers
	Subprotocols []string      // Sec-WebSocket-Protocol offers
	Insecure     bool          // skip TLS verification
	Proxy        string        // outbound proxy (e.g. Burp)
	UserAgent    string        // User-Agent override
	Timeout      time.Duration // handshake deadline
}

func (o Opts) timeout() time.Duration {
	if o.Timeout <= 0 {
		return 12 * time.Second
	}
	return o.Timeout
}

// Dial attempts the WebSocket upgrade. On success it returns a live *Conn and a
// Handshake with Accepted true. On a handshake rejection it returns a nil conn,
// a Handshake describing the rejection (status, headers), and a nil error —
// a rejection is data, not a failure. Only transport-level problems (DNS, TLS,
// timeout) come back as a non-nil error.
func Dial(ctx context.Context, rawurl string, o Opts) (*websocket.Conn, *Handshake, error) {
	d := &websocket.Dialer{
		HandshakeTimeout:  o.timeout(),
		EnableCompression: true,
		Subprotocols:      o.Subprotocols,
	}
	if o.Insecure {
		d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // nolint:gosec // opt-in for self-signed test targets
	}
	if o.Proxy != "" {
		pu, err := url.Parse(o.Proxy)
		if err != nil {
			return nil, nil, fmt.Errorf("bad proxy %q: %w", o.Proxy, err)
		}
		d.Proxy = http.ProxyURL(pu)
	}

	h := http.Header{}
	if o.Origin != "" {
		h.Set("Origin", o.Origin)
	}
	if o.Cookies != "" {
		h.Set("Cookie", o.Cookies)
	}
	if o.UserAgent != "" {
		h.Set("User-Agent", o.UserAgent)
	}
	for k, vs := range o.Headers {
		for _, v := range vs {
			h.Add(k, v)
		}
	}

	hs := &Handshake{URL: rawurl}
	conn, resp, err := d.DialContext(ctx, rawurl, h)
	if resp != nil {
		hs.Status = resp.StatusCode
		hs.StatusText = resp.Status
		hs.Headers = resp.Header
		hs.Server = resp.Header.Get("Server")
	}
	if err != nil {
		// websocket.ErrBadHandshake means the server answered but declined the
		// upgrade — that is a result we want to keep, not a transport error.
		if err == websocket.ErrBadHandshake {
			hs.Err = fmt.Sprintf("handshake declined: %s", hs.StatusText)
			return nil, hs, nil
		}
		hs.Err = err.Error()
		return nil, hs, err
	}
	hs.Accepted = true
	hs.Subprotocol = conn.Subprotocol()
	// gorilla sets per-message deflate internally; reflect what the server
	// agreed to from the response header for an honest report.
	if ext := ""; resp != nil {
		ext = resp.Header.Get("Sec-WebSocket-Extensions")
		hs.Compression = strings.Contains(ext, "permessage-deflate")
	}
	return conn, hs, nil
}

// Collect reads up to max messages from a live connection, giving up after idle.
// WebSocket servers often push a greeting, a protocol handshake, or periodic
// pings the moment you connect; capturing those is what lets fingerprinting
// tell a socket.io server from an ActionCable one without sending a byte.
func Collect(conn *websocket.Conn, max int, idle time.Duration) []Message {
	var out []Message
	for i := 0; i < max; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		out = append(out, Message{Type: mt, Data: data})
	}
	return out
}

// Message is one frame read off the wire.
type Message struct {
	Type int    `json:"type"` // websocket.TextMessage / BinaryMessage
	Data []byte `json:"-"`
}

// Text renders a message as a string for display and matching.
func (m Message) Text() string { return string(m.Data) }
