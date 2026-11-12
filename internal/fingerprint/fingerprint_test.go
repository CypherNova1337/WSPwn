package fingerprint

import (
	"testing"

	"github.com/CypherNova1337/WSPwn/internal/wsx"
)

func msg(s string) []wsx.Message { return []wsx.Message{{Type: 1, Data: []byte(s)}} }

func TestIdentifyBySubprotocol(t *testing.T) {
	if r := Identify("/api", "graphql-transport-ws", nil); r.Framework != GraphQLWS {
		t.Errorf("graphql subprotocol → %s", r.Framework)
	}
	if r := Identify("/api", "mqtt", nil); r.Framework != MQTT {
		t.Errorf("mqtt subprotocol → %s", r.Framework)
	}
}

func TestIdentifyByPath(t *testing.T) {
	if r := Identify("/socket.io/?EIO=4", "", nil); r.Framework != SocketIO {
		t.Errorf("socket.io path → %s", r.Framework)
	}
	if r := Identify("/cable", "", nil); r.Framework != ActionCable {
		t.Errorf("cable path → %s", r.Framework)
	}
}

func TestIdentifyByGreeting(t *testing.T) {
	if r := Identify("/x", "", msg(`{"type":"welcome"}`)); r.Framework != ActionCable {
		t.Errorf("welcome frame → %s", r.Framework)
	}
	if r := Identify("/x", "", msg("CONNECTED\nversion:1.2")); r.Framework != STOMP {
		t.Errorf("stomp frame → %s", r.Framework)
	}
	if r := Identify("/x", "", msg(`0{"sid":"abc","upgrades":[]}`)); r.Framework != SocketIO {
		t.Errorf("engine.io open → %s", r.Framework)
	}
}

func TestIdentifyRawFallback(t *testing.T) {
	if r := Identify("/x", "", msg("hello there")); r.Framework != Raw {
		t.Errorf("unknown → %s, want raw", r.Framework)
	}
}
