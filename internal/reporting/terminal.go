package reporting

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
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
	Verbose bool // list passed/skipped checks too
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
		fmt.Fprintf(b, "%s  score %d/100  (%s)\n", site.Path, site.Score, sevSummary)
		return
	}
	b.WriteString(t.paint(cBold, "Site"))
	b.WriteString(t.paint(cDim, "\n────────────────────────────────────────\n"))
	row := func(k, v string) {
		fmt.Fprintf(b, "%-14s%s\n", k, v)
	}
	row("Path", site.Path)
	if site.WordPress != "" {
		row("WordPress", site.WordPress)
	}
	if site.PHP != "" {
		row("PHP", site.PHP)
	}
	if site.Server != "" {
		row("Server", site.Server)
	}
	row("Platform", r.Environment.DisplayName())
	score := fmt.Sprint(site.Score)
	switch {
	case site.Score >= 80:
		score = t.paint(cGreen, score)
	case site.Score >= 50:
		score = t.paint(cYellow, score)
	default:
		score = t.paint(cRed, score)
	}
	row("Security", score+"/100")
	b.WriteString("\n")

	for _, n := range site.Notes {
		b.WriteString(t.paint(cDim, "note: "+n+"\n"))
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
		other := otherFindings(site.Findings)
		if len(other) > 0 {
			b.WriteString("\n" + t.paint(cDim, "PASSED / SKIPPED") + "\n")
			for _, f := range other {
				status := string(f.Status)
				fmt.Fprintf(b, "  %-8s %-26s %s\n", status, f.ID, f.Title)
			}
		}
	}
}

func (t Terminal) writeFinding(b *strings.Builder, f checks.Finding) {
	b.WriteString("\n")
	b.WriteString(t.paint(cBold, f.Title))
	b.WriteString("\n")
	if f.Description != "" {
		b.WriteString(wrap(f.Description, 76, 2) + "\n")
	}
	keys := make([]string, 0, len(f.Evidence))
	for k := range f.Evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(b, "  %-12s%s\n", k+":", f.Evidence[k])
	}
	if f.Recommendation != "" {
		b.WriteString("\n")
		b.WriteString(t.paint(cDim, "Recommendation"))
		b.WriteString("\n")
		b.WriteString(wrap(f.Recommendation, 76, 2) + "\n")
	}
	if len(f.References) > 0 && len(f.References) <= 3 {
		for _, ref := range f.References {
			b.WriteString(t.paint(cDim, "  ref: "+ref+"\n"))
		}
	}
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
	fmt.Fprintf(b, "%-12s%d site(s) scanned, %d passed, %d skipped\n", "Sites", s.SitesScanned, s.Passed, s.Skipped)
}

func (t Terminal) writeQuietSummary(b *strings.Builder, s Summary) {
	fmt.Fprintf(b, "scanned %d site(s): critical %d, high %d, medium %d, low %d, info %d\n",
		s.SitesScanned, s.Critical, s.High, s.Medium, s.Low, s.Info)
}

func countSev(site SiteReport, sev checks.Severity) int {
	n := 0
	for _, f := range site.Findings {
		if f.Status == checks.StatusFailed && f.Severity == sev {
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
