// Package reporting renders scan results for humans (terminal), agents
// (JSON/SARIF), and documents (markdown). Reporters never receive raw site
// data: the app redacts secrets and sanitizes every target-controlled string
// before calling them, and each reporter applies the escaping its own output
// format requires.
package reporting

import (
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/platform"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/scoring"
)

// SchemaVersion is the version of the machine-readable output contract.
// It changes only when the JSON shape changes.
//
// 2.0 renamed `score` to `risk_score` and added `coverage_score`,
// `confidence`, `coverage`, per-finding `fingerprint`/`occurrences`, explicit
// `unknown`/`suppressed` summary counters, and the scan's effective policy.
const SchemaVersion = "2.0"

// SiteReport is one scanned installation.
type SiteReport struct {
	Path      string `json:"path"`
	WordPress string `json:"wordpress_version,omitempty"`
	PHP       string `json:"php_version,omitempty"`
	PHPSource string `json:"php_version_source,omitempty"`
	Server    string `json:"server,omitempty"`

	// RiskScore is the security score (0 = worst, 100 = no findings).
	RiskScore int `json:"risk_score"`
	// CoverageScore states how much of the audit actually ran. A high risk
	// score with a low coverage score means "not examined", not "clean".
	CoverageScore int `json:"coverage_score"`
	// Confidence summarizes the coverage score: high, medium, or low.
	Confidence string `json:"confidence"`
	// Coverage details what could not be determined and what was not walked.
	Coverage   scoring.Coverage `json:"coverage"`
	Categories map[string]int   `json:"category_scores,omitempty"`
	Findings   []checks.Finding `json:"findings"`
	Notes      []string         `json:"notes,omitempty"`
}

// Summary aggregates the whole run. Unknown and suppressed are counted
// separately from skipped: skipped means "not applicable by policy",
// unknown means "attempted but inconclusive", and both are different from a
// finding that was accepted as risk.
type Summary struct {
	SitesScanned int `json:"sites_scanned"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	Info         int `json:"info"`
	Passed       int `json:"passed"`
	Skipped      int `json:"skipped"`
	Unknown      int `json:"unknown"`
	Suppressed   int `json:"suppressed"`
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

// ScanInfo describes run parameters, the effective policy, and timing.
type ScanInfo struct {
	StartedAt  time.Time `json:"started_at"`
	DurationMs int64     `json:"duration_ms"`
	// Offline, Deep and Live describe the trust/coverage mode of the run.
	Offline bool `json:"offline"`
	Deep    bool `json:"deep"`
	// Live is true when the audited site's PHP was executed via WP-CLI.
	Live bool `json:"live"`
	// ConfigPath is the configuration file that governed this run ("" when
	// none was used) — a report must disclose the policy behind it.
	ConfigPath string `json:"config_path,omitempty"`
	// ProjectConfig is true when that file came from the scanned directory
	// tree and was trusted explicitly with --trust-project-config.
	ProjectConfig     bool              `json:"project_config,omitempty"`
	ChecksRun         int               `json:"checks_run"`
	DisabledChecks    []string          `json:"disabled_checks,omitempty"`
	SeverityOverrides map[string]string `json:"severity_overrides,omitempty"`
	Suppressions      []string          `json:"suppressions,omitempty"`
	// PluginChecksums is true when plugin file integrity verification ran.
	PluginChecksums bool `json:"verify_plugin_checksums,omitempty"`
	// Discovery records how the search for installations went; a truncated
	// search means "none found" may only mean "none found in what was
	// searched".
	Discovery *DiscoveryInfo `json:"discovery,omitempty"`
}

// DiscoveryInfo is the bounded-search accounting for automatic discovery.
type DiscoveryInfo struct {
	Roots              int    `json:"roots"`
	DirectoriesVisited int    `json:"directories_visited"`
	Truncated          bool   `json:"truncated,omitempty"`
	TruncationReason   string `json:"truncation_reason,omitempty"`
}

// Tally returns severity counts across all sites plus pass/skip/unknown and
// suppression counts. Suppressed findings are reported separately and never
// counted as active risk.
func Tally(sites []SiteReport) Summary {
	var s Summary
	s.SitesScanned = len(sites)
	for _, site := range sites {
		for _, f := range site.Findings {
			switch f.Status {
			case checks.StatusFailed:
				if f.Suppressed {
					s.Suppressed++
					continue
				}
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
			case checks.StatusUnknown:
				s.Unknown++
			}
		}
	}
	return s
}

// SiteScores derives the risk score, category scores, and the coverage score
// for one site's findings.
func SiteScores(findings []checks.Finding, walk checks.WalkStats) (int, scoring.Coverage, map[string]int) {
	res := scoring.Compute(findings)
	cats := make(map[string]int, len(res.Categories))
	for c, v := range res.Categories {
		cats[string(c)] = v
	}
	cov := scoring.ComputeCoverage(findings)
	cov.FilesWalked = walk.FilesVisited
	cov.WalkTruncated = walk.Truncated
	cov.WalkTruncationReason = walk.TruncationReason
	cov.UnreadableEntries = walk.Unreadable
	cov.SymlinksSkipped = walk.SymlinksSkipped
	return res.Overall, cov, cats
}
