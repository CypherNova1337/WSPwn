// Package baseline teaches WSPwn what an endpoint's normal behaviour looks like
// before it starts attacking it. A fuzzer that can't tell a routine error from
// an interesting one just prints noise; so, like a good tester, WSPwn watches
// the target answer a few harmless and a few deliberately-malformed messages,
// learns the shape of "fine" and the shape of "you sent garbage", and judges
// every later response against that. An anomaly is then a departure from what
// the server itself established as normal — not a hardcoded error string.
package baseline

import (
	"context"
	"math"
	"strings"
	"time"
)

// Sender is the minimal view of a message session the learner needs: write one
// payload, get back the reply, the round-trip time, and whether the socket
// closed. exploit.Session satisfies it, and so can a test double.
type Sender interface {
	Send(payload string) (resp string, rtt time.Duration, closed bool)
}

// Profile is what we learned about an endpoint's ordinary responses.
type Profile struct {
	Samples    int           // responses observed while learning
	Silent     bool          // endpoint rarely answers a message at all
	MeanLen    float64       // mean response length
	StdLen     float64       // stddev of response length
	MeanRTT    time.Duration // mean round-trip for a message
	ErrorToken string        // the server's own error marker, if it has one
}

// benignProbes are shaped like ordinary client traffic: valid-looking JSON and
// a ping. They should elicit the endpoint's "fine" response.
var benignProbes = []string{
	`{"type":"ping"}`,
	`{"op":"ping"}`,
	`ping`,
	`{"id":1,"method":"ping"}`,
}

// malformedProbes are plausibly-wrong: the endpoint's "you sent garbage"
// response is what tells us its error signature.
var malformedProbes = []string{
	`{`,
	`{"type":`,
	`__wspwn_not_a_real_message__`,
	`{"type":"__wspwn_unknown__","id":"__wspwn__"}`,
}

// errorHints are tokens that commonly appear in server error replies; we use
// them only to *pick out* the endpoint's own error token from its malformed
// response, not as the detection itself.
var errorHints = []string{"error", "invalid", "unknown", "unexpected", "bad", "fail", "denied", "malformed", "unauthorized", "exception"}

// Learn drives a session through benign and malformed probes and returns a
// Profile. It only sends; it never closes the session, which the caller owns.
func Learn(ctx context.Context, s Sender, idle time.Duration) *Profile {
	p := &Profile{}
	var lens []float64
	var rtts []time.Duration

	record := func(resp string, rtt time.Duration) {
		if resp == "" {
			return
		}
		lens = append(lens, float64(len(resp)))
		rtts = append(rtts, rtt)
		p.Samples++
	}

	for _, probe := range benignProbes {
		if ctx.Err() != nil {
			break
		}
		resp, rtt, _ := s.Send(probe)
		record(resp, rtt)
	}

	for _, probe := range malformedProbes {
		if ctx.Err() != nil {
			break
		}
		resp, rtt, _ := s.Send(probe)
		record(resp, rtt)
		if tok := pickErrorToken(resp); tok != "" && p.ErrorToken == "" {
			p.ErrorToken = tok
		}
	}

	p.Silent = p.Samples == 0
	p.MeanLen, p.StdLen = meanStd(lens)
	p.MeanRTT = meanDur(rtts)
	return p
}

// Anomaly describes how a response departed from the learned normal.
type Anomaly struct {
	Reflected bool    // our marker came back in the response
	ErrorLike bool    // response carries the endpoint's error signature
	Closed    bool    // the socket closed in response
	SizeZ     float64 // response-length z-score vs baseline
	SlowRatio float64 // RTT / mean RTT
	Note      string
}

// Interesting is the judgement call: did this response deserve a human's eye?
func (a Anomaly) Interesting() bool {
	return a.Reflected || a.Closed ||
		math.Abs(a.SizeZ) >= 3 || a.SlowRatio >= 4 ||
		(a.ErrorLike && a.Note == "new-error")
}

// Judge scores a response against the profile. marker is the unique string the
// fuzzer embedded in its payload; rtt is how long the response took; closed
// reports whether the socket dropped.
func (p *Profile) Judge(resp string, marker string, rtt time.Duration, closed bool) Anomaly {
	a := Anomaly{Closed: closed, SlowRatio: 1}
	if marker != "" && strings.Contains(resp, marker) {
		a.Reflected = true
	}
	if p.ErrorToken != "" && strings.Contains(strings.ToLower(resp), p.ErrorToken) {
		a.ErrorLike = true
	} else if p.ErrorToken == "" && containsAnyHint(resp) {
		// Endpoint had no baseline error token but this response looks like an
		// error — that itself is a change worth noting.
		a.ErrorLike = true
		a.Note = "new-error"
	}
	if p.StdLen > 0 {
		a.SizeZ = (float64(len(resp)) - p.MeanLen) / p.StdLen
	}
	if p.MeanRTT > 0 && rtt > 0 {
		a.SlowRatio = float64(rtt) / float64(p.MeanRTT)
	}
	return a
}

func pickErrorToken(resp string) string {
	low := strings.ToLower(resp)
	for _, h := range errorHints {
		if strings.Contains(low, h) {
			return h
		}
	}
	return ""
}

func containsAnyHint(resp string) bool { return pickErrorToken(resp) != "" }

func meanStd(xs []float64) (float64, float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	var v float64
	for _, x := range xs {
		v += (x - mean) * (x - mean)
	}
	return mean, math.Sqrt(v / float64(len(xs)))
}

func meanDur(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	return sum / time.Duration(len(ds))
}
