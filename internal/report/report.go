// Package report renders a finished run two ways: a grouped, coloured console
// summary for the operator, and a machine-readable JSON file for pipelines and
// evidence. Both read from the same findings so they never disagree.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/CypherNova1337/WSPwn/internal/finding"
	"github.com/CypherNova1337/WSPwn/internal/ui"
)

// Endpoint is one tested endpoint's summary for the JSON report.
type Endpoint struct {
	URL         string `json:"url"`
	Framework   string `json:"framework"`
	Reason      string `json:"framework_reason,omitempty"`
	AuthModel   string `json:"auth_model,omitempty"`
	Subprotocol string `json:"subprotocol,omitempty"`
	Reachable   bool   `json:"reachable"`
}

// Run is the whole report.
type Run struct {
	Target    string            `json:"target"`
	Started   time.Time         `json:"started"`
	Finished  time.Time         `json:"finished"`
	Endpoints []Endpoint        `json:"endpoints"`
	Findings  []finding.Finding `json:"findings"`
}

// Console prints the grouped summary to stdout.
func Console(r Run) {
	fmt.Println()
	fmt.Printf("%s %s\n", ui.Bold("WSPwn"), ui.Dim("· "+r.Target))
	fmt.Printf("%s %d endpoint(s) examined in %s\n\n",
		ui.Dim("›"), len(r.Endpoints), r.Finished.Sub(r.Started).Truncate(time.Millisecond))

	for _, e := range r.Endpoints {
		mark := ui.Red("✗")
		if e.Reachable {
			mark = ui.Green("✓")
		}
		extra := e.Framework
		if e.AuthModel != "" {
			extra += ui.Dim(" · auth:" + e.AuthModel)
		}
		if e.Subprotocol != "" {
			extra += ui.Dim(" · " + e.Subprotocol)
		}
		fmt.Printf("  %s %s  %s\n", mark, e.URL, ui.Dim(extra))
	}

	if len(r.Findings) == 0 {
		fmt.Printf("\n%s no findings.\n", ui.Dim("—"))
		return
	}

	sorted := append([]finding.Finding(nil), r.Findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return sorted[i].Severity > sorted[j].Severity
		}
		return sorted[i].Endpoint < sorted[j].Endpoint
	})

	fmt.Printf("\n%s\n", ui.Bold(fmt.Sprintf("Findings (%d)", len(sorted))))
	for _, f := range sorted {
		fmt.Printf("\n  [%s] %s\n", ui.Sev(f.Severity), ui.Bold(f.Title))
		fmt.Printf("    %s %s\n", ui.Dim("endpoint"), f.Endpoint)
		fmt.Printf("    %s\n", f.Detail)
		if f.Evidence != "" {
			fmt.Printf("    %s %s\n", ui.Dim("evidence"), ui.Cyan(firstLine(f.Evidence)))
		}
		if f.Remedy != "" {
			fmt.Printf("    %s %s\n", ui.Dim("fix"), f.Remedy)
		}
	}
	fmt.Println()
	printTally(sorted)
}

func printTally(fs []finding.Finding) {
	by := map[finding.Severity]int{}
	for _, f := range fs {
		by[f.Severity]++
	}
	order := []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info}
	var parts string
	for _, s := range order {
		if by[s] > 0 {
			parts += fmt.Sprintf("  %s %d", ui.Sev(s), by[s])
		}
	}
	fmt.Printf("%s%s\n", ui.Dim("summary"), parts)
}

// JSON writes the report to path.
func JSON(r Run, path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
