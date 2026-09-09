// Package checks contains the security check framework and every individual
// check. Each check is an independent unit with a stable identifier,
// category, and structured result — no god-scanner.
//
// Result philosophy: a check that cannot determine its condition reports
// status "skipped" (not applicable / not determinable) or "unknown"
// (attempted, inconclusive). Checks never guess.
package checks

// Severity of a finding.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Weight returns the scoring weight of the severity.
func (s Severity) Weight() int {
	switch s {
	case SevCritical:
		return 40
	case SevHigh:
		return 20
	case SevMedium:
		return 10
	case SevLow:
		return 4
	default: // info and anything unrecognized
		return 0
	}
}

// Rank orders severities for filtering (critical=4 … info=0).
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

func ParseSeverity(s string) (Severity, bool) {
	switch Severity(s) {
	case SevCritical, SevHigh, SevMedium, SevLow, SevInfo:
		return Severity(s), true
	}
	return "", false
}

// Status of a check execution.
type Status string

const (
	StatusPassed  Status = "passed"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
	StatusUnknown Status = "unknown"
)

// Confidence expresses how sure the check is about its own result.
type Confidence string

const (
	ConfHigh   Confidence = "high"
	ConfMedium Confidence = "medium"
	ConfLow    Confidence = "low"
)

// Category groups checks; values are stable API for automation.
type Category string

const (
	CatCore     Category = "wordpress-core"
	CatConfig   Category = "wordpress-config"
	CatAuth     Category = "authentication"
	CatPlugins  Category = "plugins"
	CatThemes   Category = "themes"
	CatUsers    Category = "users"
	CatFS       Category = "filesystem"
	CatDatabase Category = "database"
	CatPHP      Category = "php"
	CatServer   Category = "web-server"
	CatNetwork  Category = "network"
	CatHardning Category = "hardening"
	CatExposure Category = "exposure"
)

// Finding is the standardized result of one check.
type Finding struct {
	ID             string            `json:"id"`
	Title          string            `json:"title"`
	Category       Category          `json:"category"`
	Severity       Severity          `json:"severity"`
	Status         Status            `json:"status"`
	Confidence     Confidence        `json:"confidence"`
	Description    string            `json:"description"`
	Evidence       map[string]string `json:"evidence,omitempty"`
	Recommendation string            `json:"recommendation,omitempty"`
	References     []string          `json:"references,omitempty"`
}
