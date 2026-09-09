package checks

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/platform"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/releases"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/vulnerability"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wpcli"
)

// Context carries everything a check may need for one site. Data is
// collected once per site and shared: checks must not re-run WP-CLI or
// re-walk the filesystem for what the context already knows.
type Context struct {
	Site *wordpress.Site

	// WP is the WP-CLI insight bundle. Nil fields mean "not determined".
	WP *wpcli.Siteenv
	// WPAvailable is true when WP-CLI ran and answered.
	WPAvailable bool

	// Vulns is the vulnerability data provider (never nil; may be the
	// Unavailable provider).
	Vulns vulnerability.Provider
	// Core is WordPress.org release data; nil when offline or unfetched.
	Core *releases.Core

	// HTTP performs the scanner's own limited requests; nil when offline.
	HTTP *http.Client
	// BaseURL is the best-known site URL for HTTP checks ("" when unknown).
	BaseURL string
	// Ctx bounds the scanner's own network calls.
	Ctx context.Context

	Offline  bool
	Deep     bool
	Platform platform.Info
	// Server names the detected web server software ("" when unknown).
	Server string

	// Log receives verbose progress lines when non-nil.
	Log func(string)
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

// Options filters which checks run and how findings are reported.
type Options struct {
	Disabled      map[string]bool // check IDs to skip entirely
	MinSeverity   Severity        // report findings at or above this severity ("" = all)
	ExcludedPaths []string        // site paths to exclude
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

// FilterFindings applies the severity floor and drops passed/skipped rows
// when a severity filter is active (a filtered run wants actionable output).
func (o Options) FilterFindings(findings []Finding) []Finding {
	if o.MinSeverity == "" {
		return findings
	}
	var out []Finding
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
