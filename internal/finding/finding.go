// Package finding is the shared vocabulary for everything WSPwn reports:
// a severity scale and a single Finding record the recon and exploit stages
// both emit, so the console and JSON writers only ever speak one language.
package finding

import "strings"

// Severity ranks a finding from informational to critical. It is ordered, so
// findings can be sorted and filtered by threshold.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

// String renders a severity as an uppercase label.
func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	default:
		return "INFO"
	}
}

// ParseSeverity turns a label back into a Severity, defaulting to Info.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return Critical
	case "HIGH":
		return High
	case "MEDIUM":
		return Medium
	case "LOW":
		return Low
	default:
		return Info
	}
}

// Finding is one observation about one endpoint. Evidence holds the concrete
// proof (a handshake status line, a reflected marker) and Remedy the fix, so a
// run is report-ready without a second pass by hand.
type Finding struct {
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Endpoint string   `json:"endpoint"`
	Detail   string   `json:"detail"`
	Evidence string   `json:"evidence,omitempty"`
	Remedy   string   `json:"remedy,omitempty"`
}

// MarshalJSON writes severity as its label rather than its integer so the JSON
// report reads the same as the console.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}
