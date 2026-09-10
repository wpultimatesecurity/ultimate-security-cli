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

// Determined reports whether the check reached a conclusion about the site.
// Passed and failed are conclusions; skipped and unknown are not, and are
// what the coverage score is made of.
func (s Status) Determined() bool {
	return s == StatusPassed || s == StatusFailed
}

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
	CatCore    Category = "wordpress-core"
	CatConfig  Category = "wordpress-config"
	CatAuth    Category = "authentication"
	CatPlugins Category = "plugins"
	CatThemes  Category = "themes"
	// CatUsers is reserved: administrator-account checks report under
	// CatAuth, and the category is kept so a future user-listing check has a
	// stable home.
	CatUsers     Category = "users"
	CatFS        Category = "filesystem"
	CatDatabase  Category = "database"
	CatPHP       Category = "php"
	CatServer    Category = "web-server"
	CatNetwork   Category = "network"
	CatHardening Category = "hardening"
	CatExposure  Category = "exposure"
)

// Importance weights a check for coverage scoring. Coverage answers "how much
// of the audit actually ran?", so the checks that carry the security signal
// must weigh more than context/policy checks. Without a weight a site whose
// vulnerability database was unavailable would look as well covered as one
// that had it.
type Importance int

const (
	// ImpContext marks advisory/policy checks (a public username, a default
	// table prefix). Useful context, not the security core.
	ImpContext Importance = 1
	// ImpStandard is the default weight.
	ImpStandard Importance = 2
	// ImpCore marks checks whose absence materially weakens the audit:
	// integrity, vulnerability data, authentication controls.
	ImpCore Importance = 3
)

// Weight returns the coverage weight, defaulting to standard when unset.
func (i Importance) Weight() int {
	if i <= 0 {
		return int(ImpStandard)
	}
	return int(i)
}

// String names the importance level for reports and the check registry.
func (i Importance) String() string {
	switch i {
	case ImpCore:
		return "core"
	case ImpContext:
		return "context"
	default:
		return "standard"
	}
}

// Occurrence is one structured instance of a finding. Aggregated findings
// (a vulnerability row covering many plugins, a file list) carry occurrences
// so that CI, agents, and diffing can address each item individually instead
// of parsing a joined string.
type Occurrence struct {
	// ResourceType is the kind of thing the occurrence is about: plugin,
	// theme, core, file, user, configuration.
	ResourceType string `json:"resource_type,omitempty"`
	// Slug is the stable identifier within its type (plugin slug, user login
	// — hashed in public privacy modes).
	Slug string `json:"slug,omitempty"`
	// Name is the human-facing name when it differs from the slug.
	Name string `json:"name,omitempty"`
	// Version of the affected resource when known.
	Version string `json:"version,omitempty"`
	// Location is a site-relative path when the occurrence is a file.
	Location string `json:"location,omitempty"`
	// AdvisoryID identifies the advisory inside its provider.
	AdvisoryID string `json:"advisory_id,omitempty"`
	// CVE identifier when the advisory has one.
	CVE string `json:"cve,omitempty"`
	// CVSSScore is the raw score from the provider (0 when unknown).
	CVSSScore float64 `json:"cvss_score,omitempty"`
	// Severity as rated by the provider (not our remapped severity).
	Severity string `json:"severity,omitempty"`
	// FixedIn lists versions that resolve the occurrence.
	FixedIn []string `json:"fixed_versions,omitempty"`
	// Patched reports whether a fix exists at all (nil = unknown).
	Patched *bool `json:"patched,omitempty"`
	// KnownExploited reports active exploitation in the wild (nil = unknown).
	KnownExploited *bool `json:"known_exploited,omitempty"`
	// Provider names the data source for this occurrence.
	Provider string `json:"provider,omitempty"`
	// Detail is a short human-readable note (remediation, reason).
	Detail string `json:"detail,omitempty"`
}

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
	Occurrences    []Occurrence      `json:"occurrences,omitempty"`
	Recommendation string            `json:"recommendation,omitempty"`
	References     []string          `json:"references,omitempty"`
	// Fingerprint is a stable identity for this finding independent of
	// wording or ordering, so consecutive scans can be diffed.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Suppressed marks an accepted risk: the finding is kept in the report
	// (never deleted) but excluded from scoring and the exit policy.
	Suppressed        bool   `json:"suppressed,omitempty"`
	SuppressionReason string `json:"suppression_reason,omitempty"`
}

// Suppression is one accepted-risk entry from the configuration.
type Suppression struct {
	CheckID string `json:"check_id"`
	Reason  string `json:"reason"`
}

// fingerprintInput builds a deterministic identity string for a finding.
// Only machine-stable fields participate: the check ID plus the sorted
// resource keys of its occurrences (or the title when it has none).
func (f Finding) ComputeFingerprint() string {
	parts := []string{f.ID}
	if len(f.Occurrences) == 0 {
		parts = append(parts, f.Title)
	}
	for _, o := range f.Occurrences {
		key := o.ResourceType + ":" + o.Slug + ":" + o.Version + ":" + o.Location + ":" + o.AdvisoryID
		parts = append(parts, key)
	}
	return HashFingerprint(parts)
}
