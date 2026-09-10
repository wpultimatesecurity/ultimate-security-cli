package reporting

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/sanitize"
)

// WriteMarkdown renders a GitHub-flavored report suitable for issues,
// pull requests, and AI-agent context.
//
// Every value that originates from the audited site is escaped for the exact
// Markdown context it lands in (table cell, code span, flowing text), so a
// hostile plugin name or path can neither restructure the document nor inject
// markup that an agent might follow as instructions.
func WriteMarkdown(w io.Writer, r *Report) error {
	var b strings.Builder
	b.WriteString("# Ultimate Security CLI — Security Report\n\n")
	b.WriteString(fmt.Sprintf("- **Tool:** %s %s\n", sanitize.MarkdownInline(r.Tool.Name), sanitize.MarkdownInline(r.Tool.Version)))
	b.WriteString(fmt.Sprintf("- **Schema:** %s\n", sanitize.MarkdownInline(r.SchemaVersion)))
	b.WriteString(fmt.Sprintf("- **Platform:** %s/%s\n", sanitize.MarkdownInline(r.Environment.OS), sanitize.MarkdownInline(r.Environment.Arch)))
	b.WriteString(fmt.Sprintf("- **Started:** %s\n", r.Scan.StartedAt.UTC().Format(timeFormat)))
	b.WriteString(fmt.Sprintf("- **Duration:** %d ms\n", r.Scan.DurationMs))
	b.WriteString("- **Mode:** " + scanMode(r.Scan) + "\n")
	if r.Scan.ConfigPath != "" {
		trust := ""
		if r.Scan.ProjectConfig {
			trust = " (project-local, trusted explicitly)"
		}
		b.WriteString(fmt.Sprintf("- **Policy:** `%s`%s\n", sanitize.MarkdownCode(r.Scan.ConfigPath), trust))
	}
	b.WriteString("\n## Summary\n\n")
	b.WriteString("| Severity | Findings |\n|---|---|\n")
	s := r.Summary
	fmt.Fprintf(&b, "| Critical | %d |\n| High | %d |\n| Medium | %d |\n| Low | %d |\n| Info | %d |\n| Unknown | %d |\n| Suppressed | %d |\n",
		s.Critical, s.High, s.Medium, s.Low, s.Info, s.Unknown, s.Suppressed)
	fmt.Fprintf(&b, "\n%d site(s) scanned · %d checks passed · %d skipped\n", s.SitesScanned, s.Passed, s.Skipped)

	for _, site := range r.Sites {
		fmt.Fprintf(&b, "\n## Site `%s`\n\n", sanitize.MarkdownCode(site.Path))
		b.WriteString("| | |\n|---|---|\n")
		if site.WordPress != "" {
			fmt.Fprintf(&b, "| WordPress | %s |\n", sanitize.MarkdownTableCell(site.WordPress))
		}
		if site.PHP != "" {
			fmt.Fprintf(&b, "| PHP | %s (%s) |\n", sanitize.MarkdownTableCell(site.PHP), sanitize.MarkdownTableCell(site.PHPSource))
		}
		if site.Server != "" {
			fmt.Fprintf(&b, "| Server | %s |\n", sanitize.MarkdownTableCell(site.Server))
		}
		fmt.Fprintf(&b, "| **Risk score** | **%d / 100** |\n", site.RiskScore)
		fmt.Fprintf(&b, "| **Coverage** | **%d%%** (%s confidence, %d of %d checks determined) |\n",
			site.CoverageScore, site.Confidence, site.Coverage.Determined, site.Coverage.Total)
		if site.Coverage.FilesWalked > 0 {
			walks := fmt.Sprintf("%d files examined", site.Coverage.FilesWalked)
			if site.Coverage.WalkTruncated {
				walks += " (walk stopped early: " + site.Coverage.WalkTruncationReason + " budget)"
			}
			fmt.Fprintf(&b, "| Filesystem | %s |\n", sanitize.MarkdownTableCell(walks))
		}
		if site.CoverageScore < 80 {
			fmt.Fprintf(&b, "\n> **Incomplete audit:** %d of %d checks could not be determined. A high risk score does not mean the site was fully examined; see the not-determined list below.\n",
				site.Coverage.Total-site.Coverage.Determined, site.Coverage.Total)
		}
		if len(site.Notes) > 0 {
			fmt.Fprintf(&b, "\n> %s\n", sanitize.MarkdownInline(strings.Join(site.Notes, " ")))
		}
		if len(site.Categories) > 0 {
			b.WriteString("\n### Category scores\n\n| Category | Score |\n|---|---|\n")
			keys := make([]string, 0, len(site.Categories))
			for c := range site.Categories {
				keys = append(keys, c)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "| %s | %d |\n", sanitize.MarkdownTableCell(k), site.Categories[k])
			}
		}
		if len(site.Coverage.Gaps) > 0 {
			b.WriteString("\n### Not determined\n\n| Check | Status | Reason |\n|---|---|---|\n")
			for _, g := range site.Coverage.Gaps {
				reason := g.Reason
				if reason == "" {
					reason = "no reason reported"
				}
				fmt.Fprintf(&b, "| `%s` | %s | %s |\n",
					sanitize.MarkdownCode(g.CheckID), sanitize.MarkdownTableCell(g.Status), sanitize.MarkdownTableCell(reason))
			}
		}

		findings := failedFindings(site.Findings)
		if len(findings) == 0 {
			b.WriteString("\nNo failed findings.\n")
			continue
		}
		for _, f := range findings {
			title := sanitize.MarkdownInline(f.Title)
			if f.Suppressed {
				title += " _(suppressed)_"
			}
			fmt.Fprintf(&b, "\n### [%s] %s\n\n", strings.ToUpper(string(f.Severity)), title)
			fmt.Fprintf(&b, "- **ID:** `%s`\n- **Category:** %s\n- **Confidence:** %s\n",
				sanitize.MarkdownCode(f.ID), sanitize.MarkdownTableCell(string(f.Category)), sanitize.MarkdownTableCell(string(f.Confidence)))
			if f.Fingerprint != "" {
				fmt.Fprintf(&b, "- **Fingerprint:** `%s`\n", sanitize.MarkdownCode(f.Fingerprint))
			}
			if f.Suppressed {
				fmt.Fprintf(&b, "- **Suppressed:** %s\n", sanitize.MarkdownInline(f.SuppressionReason))
			}
			if f.Description != "" {
				fmt.Fprintf(&b, "\n%s\n", sanitize.MarkdownInline(f.Description))
			}
			if len(f.Evidence) > 0 {
				b.WriteString("\n**Evidence**\n\n")
				for _, k := range sortedKeys(f.Evidence) {
					fmt.Fprintf(&b, "- %s: `%s`\n", sanitize.MarkdownInline(k), sanitize.MarkdownCode(f.Evidence[k]))
				}
			}
			if len(f.Occurrences) > 0 {
				b.WriteString("\n**Occurrences**\n\n| Resource | Version | Advisory | Severity | Fixed in | Notes |\n|---|---|---|---|---|---|\n")
				for _, o := range f.Occurrences {
					notes := occurrenceNotes(o)
					fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n",
						sanitize.MarkdownTableCell(strings.TrimSpace(o.ResourceType+" "+o.Slug)),
						sanitize.MarkdownTableCell(o.Version),
						sanitize.MarkdownTableCell(firstNonEmptyText(o.CVE, o.AdvisoryID)),
						sanitize.MarkdownTableCell(o.Severity),
						sanitize.MarkdownTableCell(strings.Join(o.FixedIn, ", ")),
						sanitize.MarkdownTableCell(notes))
				}
			}
			if f.Recommendation != "" {
				fmt.Fprintf(&b, "\n**Recommendation:** %s\n", sanitize.MarkdownInline(f.Recommendation))
			}
			if len(f.References) > 0 {
				b.WriteString("\n**References**\n\n")
				for _, ref := range f.References {
					fmt.Fprintf(&b, "- <%s>\n", sanitize.MarkdownInline(ref))
				}
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// scanMode describes the trust mode of the run in one phrase.
func scanMode(s ScanInfo) string {
	switch {
	case s.Live && s.Offline:
		return "live (WP-CLI loaded the site), offline"
	case s.Live:
		return "live (WP-CLI loaded the site)"
	case s.Offline:
		return "static, offline"
	default:
		return "static (the site's PHP was never executed)"
	}
}

// occurrenceNotes renders the short human notes for one occurrence.
func occurrenceNotes(o checks.Occurrence) string {
	var notes []string
	if o.KnownExploited != nil && *o.KnownExploited {
		notes = append(notes, "exploited in the wild")
	}
	if o.Patched != nil && !*o.Patched {
		notes = append(notes, "no fix available")
	}
	if o.Detail != "" {
		notes = append(notes, o.Detail)
	}
	return strings.Join(notes, "; ")
}

func firstNonEmptyText(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

const timeFormat = "2006-01-02 15:04:05 MST"

func failedFindings(fs []checks.Finding) []checks.Finding {
	var out []checks.Finding
	for _, f := range fs {
		if f.Status == checks.StatusFailed {
			out = append(out, f)
		}
	}
	checks.SortFindings(out)
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
