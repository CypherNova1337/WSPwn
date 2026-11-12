// Package fingerprint names the technology behind a WebSocket endpoint from the
// cheap evidence we already have — the URL path, the negotiated subprotocol,
// the handshake headers, and whatever the server pushed on connect. Knowing it
// is socket.io versus raw STOMP changes which messages make sense to send next,
// so every later stage keys off this.
package fingerprint

import (
	"strings"

	"github.com/CypherNova1337/WSPwn/internal/wsx"
)

// Framework is a recognised WebSocket stack.
type Framework string

const (
	SocketIO    Framework = "socket.io"
	SockJS      Framework = "SockJS"
	SignalR     Framework = "SignalR"
	ActionCable Framework = "ActionCable"
	GraphQLWS   Framework = "graphql-ws"
	STOMP       Framework = "STOMP"
	Phoenix     Framework = "Phoenix Channels"
	MQTT        Framework = "MQTT-over-WS"
	Centrifugo  Framework = "Centrifugo"
	Raw         Framework = "raw WebSocket"
)

// Result is a guess plus the reason behind it, so a report can say why.
type Result struct {
	Framework Framework `json:"framework"`
	Reason    string    `json:"reason"`
}

// Identify weighs the available signals and returns the best-supported guess.
// path is the endpoint path, subprotocol the negotiated Sec-WebSocket-Protocol,
// and greeting the first few messages the server pushed (may be empty).
func Identify(path, subprotocol string, greeting []wsx.Message) Result {
	lp := strings.ToLower(path)
	sp := strings.ToLower(subprotocol)
	var first string
	if len(greeting) > 0 {
		first = strings.TrimSpace(greeting[0].Text())
	}

	switch {
	case strings.Contains(sp, "graphql-transport-ws") || strings.Contains(sp, "graphql-ws"):
		return Result{GraphQLWS, "graphql subprotocol negotiated: " + subprotocol}
	case strings.Contains(sp, "mqtt"):
		return Result{MQTT, "mqtt subprotocol negotiated"}
	case strings.Contains(sp, "stomp"):
		return Result{STOMP, "stomp subprotocol negotiated: " + subprotocol}
	case strings.Contains(sp, "centrifuge") || strings.Contains(sp, "centrifugo"):
		return Result{Centrifugo, "centrifugo subprotocol negotiated"}
	}

	switch {
	case strings.Contains(lp, "socket.io"):
		return Result{SocketIO, "socket.io endpoint path"}
	case strings.Contains(lp, "sockjs"):
		return Result{SockJS, "sockjs endpoint path"}
	case strings.Contains(lp, "signalr") || strings.Contains(lp, "/hub"):
		return Result{SignalR, "signalr/hub endpoint path"}
	case strings.Contains(lp, "cable"):
		return Result{ActionCable, "actioncable endpoint path"}
	case strings.Contains(lp, "graphql") || strings.Contains(lp, "subscriptions"):
		return Result{GraphQLWS, "graphql subscription endpoint path"}
	}

	// Fall back to reading the greeting.
	switch {
	case first == "o" || strings.HasPrefix(first, "a["):
		return Result{SockJS, "sockjs open/array frame on connect"}
	case strings.HasPrefix(first, "0{") && strings.Contains(first, "sid"):
		return Result{SocketIO, "engine.io open packet on connect"}
	case strings.HasPrefix(first, "40") || strings.HasPrefix(first, "42"):
		return Result{SocketIO, "socket.io packet prefix on connect"}
	case strings.Contains(first, `"type":"welcome"`):
		return Result{ActionCable, "actioncable welcome frame on connect"}
	case strings.HasPrefix(first, "CONNECTED") || strings.HasPrefix(first, "STOMP"):
		return Result{STOMP, "stomp CONNECTED frame on connect"}
	case strings.Contains(first, `"connection_ack"`):
		return Result{GraphQLWS, "graphql connection_ack on connect"}
	case strings.HasPrefix(first, `["`) && strings.Contains(first, "phx_"):
		return Result{Phoenix, "phoenix channel frame on connect"}
	case strings.Contains(first, `"connect"`) && strings.Contains(first, `"client"`):
		return Result{Centrifugo, "centrifugo connect reply on connect"}
	}

	return Result{Raw, "no framework signature matched"}
}

// Greeting is a convenience for probing a brand-new socket.io/engine.io style
// endpoint: the client payload expected to start a session for a given stack.
// It returns empty for stacks that speak first (the server greets).
func Greeting(f Framework) string {
	switch f {
	case GraphQLWS:
		return `{"type":"connection_init"}`
	case ActionCable:
		return `{"command":"subscribe","identifier":"{\"channel\":\"PingChannel\"}"}`
	case STOMP:
		return "CONNECT\naccept-version:1.2\nhost:localhost\n\n\x00"
	case SocketIO:
		return "40"
	default:
		return ""
	}
}
