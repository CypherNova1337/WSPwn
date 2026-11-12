// Package ui handles everything the operator sees while a run is in flight:
// colour helpers that disable themselves when output isn't a terminal, and a
// single live status line that keeps a run from being a silent wait — it shows
// what WSPwn is doing right now, the way LFI-Machine's status line does.
package ui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/CypherNova1337/WSPwn/internal/finding"
	"golang.org/x/term"
)

var colorOn = term.IsTerminal(int(os.Stderr.Fd()))

// NoColor forces colour off (for --no-color or piped output).
func NoColor() { colorOn = false }

func paint(code, s string) string {
	if !colorOn {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func Bold(s string) string   { return paint("1", s) }
func Dim(s string) string    { return paint("2", s) }
func Red(s string) string    { return paint("31", s) }
func Green(s string) string  { return paint("32", s) }
func Yellow(s string) string { return paint("33", s) }
func Blue(s string) string   { return paint("34", s) }
func Cyan(s string) string   { return paint("36", s) }

// Sev colours a severity label.
func Sev(s finding.Severity) string {
	switch s {
	case finding.Critical:
		return paint("1;41", " CRIT ")
	case finding.High:
		return Red(s.String())
	case finding.Medium:
		return Yellow(s.String())
	case finding.Low:
		return Blue(s.String())
	default:
		return Dim(s.String())
	}
}

// Progress is a throttled single-line status indicator written to stderr.
type Progress struct {
	mu      sync.Mutex
	enabled bool
	start   time.Time
	last    time.Time
	sends   int
	hits    int
	phase   string
	detail  string
}

// NewProgress returns a status line; enabled false makes every call a no-op.
func NewProgress(enabled bool) *Progress {
	return &Progress{enabled: enabled && colorOn, start: time.Now()}
}

// Phase sets the headline activity (Discovering, Fingerprinting, Fuzzing…).
func (p *Progress) Phase(name string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	p.phase = name
	p.mu.Unlock()
	p.render(true)
}

// Tick records a send with an optional detail and refreshes the line.
func (p *Progress) Tick(detail string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	p.sends++
	if detail != "" {
		p.detail = detail
	}
	p.mu.Unlock()
	p.render(false)
}

// Hit bumps the finding counter.
func (p *Progress) Hit() {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	p.hits++
	p.mu.Unlock()
	p.render(true)
}

func (p *Progress) render(force bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled {
		return
	}
	if !force && time.Since(p.last) < 80*time.Millisecond {
		return
	}
	p.last = time.Now()
	el := time.Since(p.start).Truncate(time.Second)
	rate := 0.0
	if s := time.Since(p.start).Seconds(); s > 0 {
		rate = float64(p.sends) / s
	}
	line := fmt.Sprintf("%s %s  %s sends:%d hits:%s %.0f/s  %s",
		Cyan("▸"), Bold(p.phase), Dim(el.String()), p.sends, Green(fmt.Sprint(p.hits)), rate, Dim(clip(p.detail, 48)))
	fmt.Fprintf(os.Stderr, "\r\x1b[2K%s", line)
}

// Clear wipes the status line so final output starts clean.
func (p *Progress) Clear() {
	if p == nil || !p.enabled {
		return
	}
	fmt.Fprint(os.Stderr, "\r\x1b[2K")
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
