package baseline

import (
	"context"
	"testing"
	"time"
)

func TestJudgeReflection(t *testing.T) {
	p := &Profile{MeanLen: 10, StdLen: 2, MeanRTT: time.Millisecond}
	a := p.Judge(`{"echo":"wspABCD"}`, "wspABCD", time.Millisecond, false)
	if !a.Reflected || !a.Interesting() {
		t.Fatalf("reflected marker should be interesting: %+v", a)
	}
}

func TestJudgeTimeDelay(t *testing.T) {
	p := &Profile{MeanLen: 10, StdLen: 2, MeanRTT: time.Millisecond}
	a := p.Judge(`{"ok":true}`, "m", 100*time.Millisecond, false)
	if a.SlowRatio < 4 || !a.Interesting() {
		t.Fatalf("a 100x slowdown should be interesting: %+v", a)
	}
}

func TestJudgeNewError(t *testing.T) {
	// Baseline never produced an error token; a later error is a change.
	p := &Profile{MeanLen: 10, StdLen: 2, MeanRTT: time.Millisecond, ErrorToken: ""}
	a := p.Judge(`{"error":"SQL syntax"}`, "m", time.Millisecond, false)
	if !a.ErrorLike || a.Note != "new-error" || !a.Interesting() {
		t.Fatalf("a fresh error should be interesting: %+v", a)
	}
}

func TestJudgeNormalIsQuiet(t *testing.T) {
	p := &Profile{MeanLen: 11, StdLen: 1, MeanRTT: time.Millisecond, ErrorToken: "error"}
	a := p.Judge(`{"ok":true}`, "m", time.Millisecond, false)
	if a.Interesting() {
		t.Fatalf("a baseline-shaped response should be quiet: %+v", a)
	}
}

func TestLearnWithFakeSender(t *testing.T) {
	// A sender that answers benign probes normally and malformed ones with an
	// error should yield a profile that captures the error token.
	fs := &fakeSender{}
	p := Learn(context.Background(), fs, time.Second)
	if p.Silent {
		t.Fatal("profile should not be silent")
	}
	if p.ErrorToken != "error" {
		t.Fatalf("error token not learned: %q", p.ErrorToken)
	}
}

type fakeSender struct{}

func (f *fakeSender) Send(payload string) (string, time.Duration, bool) {
	// Malformed probes contain "__wspwn" or start with "{" alone.
	if payload == "{" || payload == `{"type":` || containsAnyHint(payload) || payload == "__wspwn_not_a_real_message__" {
		return `{"error":"bad message"}`, time.Millisecond, false
	}
	if len(payload) >= 7 && payload[:1] == "{" && (payload == `{"type":"ping"}` || payload == `{"op":"ping"}` || payload == `{"id":1,"method":"ping"}`) {
		return `{"ok":true}`, time.Millisecond, false
	}
	return `{"ok":true}`, time.Millisecond, false
}
