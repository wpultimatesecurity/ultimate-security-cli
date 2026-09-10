package checks

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/baseline"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/platform"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/probe"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/releases"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/vulnerability"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wpcli"
)

// ChecksumSource supplies authoritative file checksums from WordPress.org so
// that core and plugin integrity can be verified without loading WordPress or
// trusting anything on disk.
type ChecksumSource interface {
	// CoreChecksums returns path -> md5 for the given core version and
	// locale, relative to the WordPress root.
	CoreChecksums(ctx context.Context, version, locale string) (map[string]string, error)
	// PluginChecksums returns path -> md5 for one WordPress.org plugin
	// release, relative to the plugin directory.
	PluginChecksums(ctx context.Context, slug, version string) (map[string]string, error)
	// PluginsEnabled reports whether plugin checksum lookups are permitted.
	// Downloading one archive per installed plugin is heavy enough to be
	// opt-in, and a scan must say "not checked" rather than imply "clean".
	PluginsEnabled() bool
}

// Context carries everything a check may need for one site. Data is
// collected once per site and shared: checks must not re-run WP-CLI or
// re-walk the filesystem for what the context already knows.
type Context struct {
	Site *wordpress.Site

	// WP is the WP-CLI insight bundle. Nil fields mean "not determined".
	// It is only populated in --live mode: the static path never executes
	// the audited site's PHP.
	WP *wpcli.Siteenv
	// WPAvailable is true when WP-CLI ran and answered.
	WPAvailable bool

	// Vulns is the vulnerability data provider (never nil; may be the
	// Unavailable provider).
	Vulns vulnerability.Provider
	// Core is WordPress.org release data; nil when offline or unfetched.
	Core *releases.Core

	// Probe performs the scanner's own requests to the site. It is nil when
	// offline or when the site URL is unknown, and every probe it performs is
	// restricted to the site's own origin by policy — a compromised site URL
	// cannot redirect the scanner at an internal host.
	Probe *probe.Prober
	// BaseURL is the best-known site URL for HTTP checks ("" when unknown).
	BaseURL string
	// Checksums supplies authoritative WordPress.org file checksums. It is
	// nil when offline; plugin checksums additionally require an opt-in
	// because they download one archive per plugin.
	Checksums ChecksumSource
	// Ctx bounds the scanner's own network calls.
	Ctx context.Context

	// Baseline is the recorded inventory a scan compares this site against.
	// It is nil when no --baseline was given, and the drift check then skips.
	Baseline *baseline.Baseline

	// Findings holds the findings produced for this site so far. Drift is
	// relative: the drift check can only say what is new or resolved once the
	// rest of the audit for the site has finished, so the scan attaches its
	// results here for that final check. Nil means no finding set is
	// available (a standalone invocation) and the finding dimension is
	// reported as unchecked rather than guessed.
	Findings []Finding

	Offline  bool
	Deep     bool
	Platform platform.Info
	// Server names the detected web server software ("" when unknown).
	Server string

	// Log receives verbose progress lines when non-nil.
	Log func(string)

	// coverage accumulates what the audit could and could not examine.
	coverage coverageState

	// integrityOnce guards the shared integrity scan, which several checks
	// consume and which must therefore walk each tree exactly once.
	integrityOnce sync.Once
	integrity     *integrityScan

	// pluginOnce guards the shared plugin integrity scan for the same reason.
	pluginOnce sync.Once
	pluginScan *pluginIntegrityScan
}

// coverageState records the evidence behind the coverage score. Checks report
// through the Context so the report can state which parts of the tree were
// not examined instead of implying a clean result.
type coverageState struct {
	walks             []WalkStats
	gaps              []string
	filesWalked       int
	truncated         bool
	unreadable        int
	hiddenSkipped     int
	symlinksSkipped   int
	matchesDropped    int
	truncationReasons []string
}

// WalkStats summarizes one bounded filesystem traversal.
type WalkStats struct {
	// FilesVisited counts regular files the walker inspected.
	FilesVisited int `json:"files_visited"`
	// Truncated is true when a budget (time, file count, depth) cut the walk
	// short, so the result is a lower bound rather than a complete answer.
	Truncated bool `json:"truncated,omitempty"`
	// TruncationReason names the budget that stopped the walk.
	TruncationReason string `json:"truncation_reason,omitempty"`
	// Unreadable counts entries the walker could not stat or read.
	Unreadable int `json:"unreadable,omitempty"`
	// SymlinksSkipped counts symlinks deliberately not followed.
	SymlinksSkipped int `json:"symlinks_skipped,omitempty"`
}

// recordWalk folds one walk result into the site's coverage accounting.
func (c *Context) recordWalk(res walkResult) {
	st := WalkStats{
		FilesVisited:     res.Files,
		Truncated:        res.Truncated,
		TruncationReason: res.TruncationReason,
		Unreadable:       res.Unreadable,
		SymlinksSkipped:  res.SymlinksSkipped,
	}
	c.coverage.walks = append(c.coverage.walks, st)
	c.coverage.filesWalked += res.Files
	c.coverage.unreadable += res.Unreadable
	c.coverage.symlinksSkipped += res.SymlinksSkipped
	c.coverage.matchesDropped += res.MatchesDropped
	if res.Truncated {
		c.coverage.truncated = true
		if res.TruncationReason != "" {
			c.coverage.truncationReasons = append(c.coverage.truncationReasons, res.TruncationReason)
		}
	}
}

// WalkStats returns the aggregated traversal accounting for the site.
func (c *Context) WalkStats() WalkStats {
	stats := WalkStats{
		FilesVisited:    c.coverage.filesWalked,
		Truncated:       c.coverage.truncated,
		Unreadable:      c.coverage.unreadable,
		SymlinksSkipped: c.coverage.symlinksSkipped,
	}
	if len(c.coverage.truncationReasons) > 0 {
		stats.TruncationReason = joinReasons(c.coverage.truncationReasons)
	}
	return stats
}

// AddGap records a coverage gap: something the audit could not examine.
// Gaps surface as report notes so a clean score is never mistaken for a
// complete inspection.
func (c *Context) AddGap(reason string) {
	if reason == "" {
		return
	}
	for _, g := range c.coverage.gaps {
		if g == reason {
			return
		}
	}
	c.coverage.gaps = append(c.coverage.gaps, reason)
}

// CoverageGaps returns the recorded gaps in insertion order.
func (c *Context) CoverageGaps() []string {
	return append([]string{}, c.coverage.gaps...)
}

func joinReasons(reasons []string) string {
	seen := map[string]bool{}
	var out []string
	for _, r := range reasons {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Strings(out)
	return joinComma(out)
}

func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func (c *Context) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log(fmt.Sprintf(format, args...))
	}
}

// Skip builds a skipped finding with a reason.
func (m Meta) skipf(reason string) Finding {
	return Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Status: StatusSkipped, Confidence: ConfHigh,
		Description: m.Description,
		Evidence:    map[string]string{"reason": reason},
		References:  m.References,
	}
}

// Meta is the static identity of a check.
type Meta struct {
	ID          string
	Title       string
	Category    Category
	Description string
	References  []string
	// Importance weights this check in the coverage score. Zero means
	// ImpStandard.
	Importance Importance
}

// Simple pairs a check's identity with its run function. This struct is
// the uniform check contract: every check registers exactly one Simple.
type Simple struct {
	Meta
	Run func(*Context) []Finding
}

// registry holds all checks in stable registration order.
type registry struct {
	checks []*Simple
	byID   map[string]*Simple
}

var Registry = &registry{byID: map[string]*Simple{}}

// Register adds a check. Registration order defines default display order;
// duplicates panic (programmer error).
func Register(s Simple) {
	if _, dup := Registry.byID[s.ID]; dup {
		panic("checks: duplicate check id " + s.ID)
	}
	Registry.checks = append(Registry.checks, &Simple{Meta: s.Meta, Run: s.Run})
	Registry.byID[s.ID] = Registry.checks[len(Registry.checks)-1]
}

// All returns every registered check in stable order.
func All() []*Simple { return Registry.checks }

// Get returns a check by ID.
func Get(id string) (*Simple, bool) { c, ok := Registry.byID[id]; return c, ok }

// ImportanceOf returns the coverage importance of a check ID, defaulting to
// standard for unknown IDs (a check removed from the registry must not change
// the weight of historical findings).
func ImportanceOf(id string) Importance {
	if c, ok := Registry.byID[id]; ok {
		return c.Importance
	}
	return ImpStandard
}

// Options filters which checks run and how findings are reported.
type Options struct {
	Disabled          map[string]bool     // check IDs to skip entirely
	MinSeverity       Severity            // report findings at or above this severity ("" = all)
	SeverityOverrides map[string]Severity // per-check severity remapping
	Suppressions      []Suppression       // accepted risks with a reason
}

// Selected returns the checks that will run, in stable order.
func (o Options) Selected() []*Simple {
	var out []*Simple
	for _, c := range Registry.checks {
		if !o.Disabled[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

// ApplyPolicy rewrites findings according to the effective policy.
//
// Severity overrides come first so a project that downgrades an exposure
// signal to informational also excludes it from a --severity high run.
// Suppressed findings are annotated, never dropped: an accepted risk stays
// visible in every report, and it is excluded from scoring rather than from
// the record.
//
// This runs before the severity floor is applied, and before scoring, so a
// filtered report still has a complete picture of what ran.
func (o Options) ApplyPolicy(findings []Finding) []Finding {
	for i := range findings {
		f := &findings[i]
		if sev, ok := o.SeverityOverrides[f.ID]; ok {
			f.Severity = sev
		}
		for _, s := range o.Suppressions {
			if s.CheckID == f.ID && f.Status == StatusFailed {
				f.Suppressed = true
				f.SuppressionReason = s.Reason
			}
		}
		f.Fingerprint = f.ComputeFingerprint()
	}
	return findings
}

// FilterFindings applies the severity floor. When a floor is set the output is
// actionable-only: passed, skipped, and unknown rows are dropped because the
// caller asked for findings, not for a status report.
func (o Options) FilterFindings(findings []Finding) []Finding {
	if o.MinSeverity == "" {
		return findings
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.Status == StatusFailed && f.Severity.Rank() >= o.MinSeverity.Rank() {
			out = append(out, f)
		}
	}
	return out
}

// SortFindings orders findings for reporting: severity desc, then ID.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := fs[i].Severity.Rank(), fs[j].Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		return fs[i].ID < fs[j].ID
	})
}

// httpTimeout bounds a single HTTP probe a check performs itself.
func httpTimeout() time.Duration { return 6 * time.Second }

// probeGet performs one policy-checked request through the site prober.
// It returns nil when probing is unavailable (offline, unknown URL).
func probeGet(ctx *Context, rawURL string, header http.Header) (*probe.Response, error) {
	if ctx.Probe == nil {
		return nil, fmt.Errorf("probing unavailable")
	}
	cctx, cancel := context.WithTimeout(ctx.Ctx, httpTimeout())
	defer cancel()
	return ctx.Probe.Get(cctx, rawURL, header)
}
