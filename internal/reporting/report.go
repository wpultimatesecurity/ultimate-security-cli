// Package reporting renders scan results for humans (terminal), agents
// (JSON), and documents (markdown). Reporters never receive unsanitized
// data: the app redacts every finding before calling them.
package reporting

import (
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/platform"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/scoring"
)

// SchemaVersion is the version of the machine-readable output contract.
// It changes only when the JSON shape changes.
const SchemaVersion = "1.0"

// SiteReport is one scanned installation.
type SiteReport struct {
	Path       string           `json:"path"`
	WordPress  string           `json:"wordpress_version,omitempty"`
	PHP        string           `json:"php_version,omitempty"`
	PHPSource  string           `json:"php_version_source,omitempty"`
	Server     string           `json:"server,omitempty"`
	Score      int              `json:"score"`
	Categories map[string]int   `json:"category_scores,omitempty"`
	Findings   []checks.Finding `json:"findings"`
	Notes      []string         `json:"notes,omitempty"` // e.g. wpcli unavailable
}

// Summary aggregates the whole run.
type Summary struct {
	SitesScanned int `json:"sites_scanned"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	Info         int `json:"info"`
	Passed       int `json:"passed"`
	Skipped      int `json:"skipped"`
}

// Report is the full scan result.
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	Tool          ToolInfo          `json:"tool"`
	Environment   platform.Info     `json:"environment"`
	Scan          ScanInfo          `json:"scan"`
	Sites         []SiteReport      `json:"sites"`
	Summary       Summary           `json:"summary"`
	Meta          map[string]string `json:"meta,omitempty"`
}

// ToolInfo identifies the producing binary.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanInfo describes run parameters and timing.
type ScanInfo struct {
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
	Offline    bool      `json:"offline"`
	Deep       bool      `json:"deep"`
	ChecksRun  int       `json:"checks_run"`
}

// Tally returns severity counts across all sites plus pass/skip counts.
func Tally(sites []SiteReport) Summary {
	var s Summary
	s.SitesScanned = len(sites)
	for _, site := range sites {
		for _, f := range site.Findings {
			switch f.Status {
			case checks.StatusFailed:
				switch f.Severity {
				case checks.SevCritical:
					s.Critical++
				case checks.SevHigh:
					s.High++
				case checks.SevMedium:
					s.Medium++
				case checks.SevLow:
					s.Low++
				default:
					s.Info++
				}
			case checks.StatusPassed:
				s.Passed++
			case checks.StatusSkipped:
				s.Skipped++
			}
		}
	}
	return s
}

// SiteScore is a helper for building SiteReport values.
func SiteScore(findings []checks.Finding) (int, map[string]int) {
	res := scoring.Compute(findings)
	cats := make(map[string]int, len(res.Categories))
	for c, v := range res.Categories {
		cats[string(c)] = v
	}
	return res.Overall, cats
}
