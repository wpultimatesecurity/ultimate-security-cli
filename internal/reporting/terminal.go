package reporting

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/sanitize"
)

// Color encodes a 24-bit-free SGR sequence; empty means "no color".
type Color string

// Severity palette (muted; degrade gracefully everywhere).
const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cDim    = "\x1b[2m"
	cRed    = "\x1b[31m"
	cYellow = "\x1b[33m"
	cGreen  = "\x1b[32m"
	cCyan   = "\x1b[36m"
	cGray   = "\x1b[90m"
	cWhite  = "\x1b[97m"
)

// TerminalOptions controls the human reporter.
type TerminalOptions struct {
	Color   bool // emit ANSI color
	Quiet   bool // one-line summary per site only
	Verbose bool // list passed/skipped checks and coverage gaps
}

// Terminal renders the default human-readable report.
type Terminal struct {
	Opts TerminalOptions
}

func (t Terminal) paint(c string, s string) string {
	if !t.Opts.Color || c == "" {
		return s
	}
	return c + s + cReset
}

func (t Terminal) sevColor(s checks.Severity) string {
	switch s {
	case checks.SevCritical, checks.SevHigh:
		return cRed
	case checks.SevMedium:
		return cYellow
	case checks.SevLow:
		return cCyan
	default:
		return cGray
	}
}

// Write renders the report for terminal users.
func (t Terminal) Write(w io.Writer, r *Report) error {
	var b strings.Builder
	if !t.Opts.Quiet {
		b.WriteString(t.paint(cBold+cWhite, "Ultimate Security CLI"))
		b.WriteString("\n")
		b.WriteString(t.paint(cDim, "WordPress Security Audit"))
		b.WriteString("\n\n")
	}

	for i, site := range r.Sites {
		if i > 0 && !t.Opts.Quiet {
			b.WriteString("\n")
		}
		t.writeSite(&b, r, site)
	}

	if !t.Opts.Quiet {
		t.writeSummary(&b, r.Summary)
	} else {
		t.writeQuietSummary(&b, r.Summary)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func (t Terminal) writeSite(b *strings.Builder, r *Report, site SiteReport) {
	if t.Opts.Quiet {
		sevSummary := fmt.Sprintf("critical %d, high %d, medium %d, low %d, info %d",
			countSev(site, checks.SevCritical), countSev(site, checks.SevHigh),
			countSev(site, checks.SevMedium), countSev(site, checks.SevLow),
			countSev(site, checks.SevInfo))
		fmt.Fprintf(b, "%s  risk %d/100  coverage %d%%  (%s)\n",
			site.Path, site.RiskScore, site.CoverageScore, sevSummary)
		return
	}
	b.WriteString(t.paint(cBold, "Site"))
	b.WriteString(t.paint(cDim, "\n────────────────────────────────────────\n"))
	row := func(k, v string) {
		fmt.Fprintf(b, "%-14s%s\n", k, v)
	}
	row("Path", sanitize.Raw(site.Path))
	if site.WordPress != "" {
		row("WordPress", sanitize.Raw(site.WordPress))
	}
	if site.PHP != "" {
		row("PHP", sanitize.Raw(site.PHP))
	}
	if site.Server != "" {
		row("Server", sanitize.Raw(site.Server))
	}
	row("Platform", r.Environment.DisplayName())
	row("Risk", t.score(site.RiskScore)+"/100  "+t.coverageLabel(site))
	b.WriteString("\n")

	if site.CoverageScore < 80 {
		fmt.Fprintf(b, "%s\n", t.paint(cYellow, fmt.Sprintf(
			"Incomplete: %d of %d checks could not be determined — a high risk score here does not mean the site was fully examined.",
			site.Coverage.Total-site.Coverage.Determined, site.Coverage.Total)))
	}
	if site.Coverage.WalkTruncated {
		fmt.Fprintf(b, "%s\n", t.paint(cDim,
			"Filesystem walk stopped early ("+site.Coverage.WalkTruncationReason+" budget): file-based results are partial — rerun with --deep."))
	}

	for _, n := range site.Notes {
		b.WriteString(t.paint(cDim, "note: "+sanitize.Raw(n)+"\n"))
	}

	failed := failedFindings(site.Findings)
	if len(failed) == 0 && !t.Opts.Verbose {
		b.WriteString(t.paint(cGreen, "No issues found.") + "\n")
		return
	}

	// Group findings by severity.
	for _, sev := range []checks.Severity{checks.SevCritical, checks.SevHigh, checks.SevMedium, checks.SevLow, checks.SevInfo} {
		group := groupBySeverity(failed, sev)
		if len(group) == 0 {
			continue
		}
		b.WriteString("\n")
		b.WriteString(t.paint(t.sevColor(sev)+cBold, strings.ToUpper(string(sev))))
		b.WriteString(t.paint(cDim, "\n────────────────────────────────────────\n"))
		for _, f := range group {
			t.writeFinding(b, f)
		}
	}

	if t.Opts.Verbose {
		t.writeCoverageGaps(b, site)
		other := otherFindings(site.Findings)
		if len(other) > 0 {
			b.WriteString("\n" + t.paint(cDim, "PASSED / SKIPPED / UNKNOWN") + "\n")
			for _, f := range other {
				status := string(f.Status)
				fmt.Fprintf(b, "  %-8s %-26s %s\n", status, f.ID, f.Title)
			}
		}
	}
}

// coverageLabel renders the coverage score with its confidence.
func (t Terminal) coverageLabel(site SiteReport) string {
	label := fmt.Sprintf("Coverage %d%% (%s confidence)", site.CoverageScore, site.Confidence)
	switch {
	case site.CoverageScore >= 90:
		return t.paint(cGreen, label)
	case site.CoverageScore >= 70:
		return t.paint(cYellow, label)
	default:
		return t.paint(cRed, label)
	}
}

func (t Terminal) score(v int) string {
	s := fmt.Sprint(v)
	switch {
	case v >= 80:
		return t.paint(cGreen, s)
	case v >= 50:
		return t.paint(cYellow, s)
	default:
		return t.paint(cRed, s)
	}
}

// writeCoverageGaps lists the checks that did not run or could not conclude,
// most important first: this is the evidence behind the coverage score.
func (t Terminal) writeCoverageGaps(b *strings.Builder, site SiteReport) {
	if len(site.Coverage.Gaps) == 0 {
		return
	}
	b.WriteString("\n" + t.paint(cDim, "NOT DETERMINED") + "\n")
	for _, g := range site.Coverage.Gaps {
		reason := g.Reason
		if reason == "" {
			reason = "no reason reported"
		}
		fmt.Fprintf(b, "  %-26s %-8s %s\n", sanitize.Raw(g.CheckID), sanitize.Raw(g.Status), sanitize.Raw(reason))
	}
}

func (t Terminal) writeFinding(b *strings.Builder, f checks.Finding) {
	b.WriteString("\n")
	b.WriteString(t.paint(cBold, sanitize.Raw(f.Title)))
	if f.Suppressed {
		b.WriteString(t.paint(cDim, "  [suppressed: "+sanitize.Raw(f.SuppressionReason)+"]"))
	}
	b.WriteString("\n")
	if f.Description != "" {
		b.WriteString(wrap(sanitize.Raw(f.Description), 76, 2) + "\n")
	}
	keys := make([]string, 0, len(f.Evidence))
	for k := range f.Evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Evidence keys come from checks but may embed target-controlled text, so
	// the column width is derived from the keys but capped: a hostile key must
	// not be able to push every value off the screen.
	width := 13
	for _, k := range keys {
		// +2 keeps at least one space between the colon and the value.
		if w := len(sanitize.Raw(k)) + 2; w > width {
			width = min(w, 32)
		}
	}
	for _, k := range keys {
		fmt.Fprintf(b, "  %-*s%s\n", width, sanitize.Raw(k)+":", sanitize.Raw(f.Evidence[k]))
	}
	if len(f.Occurrences) > 0 {
		b.WriteString(t.paint(cDim, "  occurrences:\n"))
		for _, o := range f.Occurrences {
			fmt.Fprintf(b, "    %s\n", sanitize.Raw(t.renderOccurrence(o)))
		}
	}
	if f.Recommendation != "" {
		b.WriteString("\n")
		b.WriteString(t.paint(cDim, "Recommendation"))
		b.WriteString("\n")
		b.WriteString(wrap(sanitize.Raw(f.Recommendation), 76, 2) + "\n")
	}
	if len(f.References) > 0 && len(f.References) <= 3 {
		for _, ref := range f.References {
			b.WriteString(t.paint(cDim, "  ref: "+sanitize.Raw(ref)+"\n"))
		}
	}
}

// renderOccurrence renders one structured occurrence on a single line.
func (t Terminal) renderOccurrence(o checks.Occurrence) string {
	parts := []string{}
	if o.ResourceType != "" {
		label := o.ResourceType
		if o.Slug != "" {
			label += " " + o.Slug
		}
		if o.Version != "" {
			label += " " + o.Version
		}
		parts = append(parts, label)
	} else if o.Location != "" {
		parts = append(parts, o.Location)
	}
	if o.AdvisoryID != "" {
		parts = append(parts, o.AdvisoryID)
	}
	if o.CVE != "" && o.CVE != o.AdvisoryID {
		parts = append(parts, o.CVE)
	}
	if o.Severity != "" {
		parts = append(parts, o.Severity)
	}
	if len(o.FixedIn) > 0 {
		parts = append(parts, "fixed in "+strings.Join(o.FixedIn, ", "))
	} else if o.Patched != nil && !*o.Patched {
		parts = append(parts, "no fix available")
	}
	if o.KnownExploited != nil && *o.KnownExploited {
		parts = append(parts, "exploited in the wild")
	}
	return strings.Join(parts, " — ")
}

// min is the integer minimum used for layout clamping.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (t Terminal) writeSummary(b *strings.Builder, s Summary) {
	b.WriteString("\n")
	b.WriteString(t.paint(cBold, "Summary"))
	b.WriteString(t.paint(cDim, "\n────────────────────────────────────────\n"))
	line := func(label string, n int, color string) {
		val := fmt.Sprint(n)
		if color != "" && t.Opts.Color && n > 0 {
			val = t.paint(color, val)
		}
		fmt.Fprintf(b, "%-12s%s\n", label, val)
	}
	line("Critical", s.Critical, cRed)
	line("High", s.High, cRed)
	line("Medium", s.Medium, cYellow)
	line("Low", s.Low, cCyan)
	line("Info", s.Info, "")
	line("Unknown", s.Unknown, cYellow)
	line("Suppressed", s.Suppressed, cGray)
	fmt.Fprintf(b, "%-12s%d site(s) scanned, %d passed, %d skipped\n", "Sites", s.SitesScanned, s.Passed, s.Skipped)
}

func (t Terminal) writeQuietSummary(b *strings.Builder, s Summary) {
	fmt.Fprintf(b, "scanned %d site(s): critical %d, high %d, medium %d, low %d, info %d, unknown %d, suppressed %d\n",
		s.SitesScanned, s.Critical, s.High, s.Medium, s.Low, s.Info, s.Unknown, s.Suppressed)
}

func countSev(site SiteReport, sev checks.Severity) int {
	n := 0
	for _, f := range site.Findings {
		if f.Status == checks.StatusFailed && !f.Suppressed && f.Severity == sev {
			n++
		}
	}
	return n
}

func groupBySeverity(fs []checks.Finding, sev checks.Severity) []checks.Finding {
	var out []checks.Finding
	for _, f := range fs {
		if f.Severity == sev && f.Status == checks.StatusFailed {
			out = append(out, f)
		}
	}
	return out
}

func otherFindings(fs []checks.Finding) []checks.Finding {
	var out []checks.Finding
	for _, f := range fs {
		if f.Status != checks.StatusFailed {
			out = append(out, f)
		}
	}
	checks.SortFindings(out)
	return out
}

// wrap wraps s at width with a hanging indent. Operates on runes; ANSI
// coloring is applied by callers outside wrapped strings.
func wrap(s string, width, indent int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return strings.Repeat(" ", indent) + s
	}
	var b strings.Builder
	line := indent
	pad := strings.Repeat(" ", indent)
	for i, word := range words {
		if i > 0 && line+1+len(word) > width {
			b.WriteString("\n" + pad)
			line = indent
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(word)
		line += len([]rune(word))
	}
	return pad + b.String()
}
