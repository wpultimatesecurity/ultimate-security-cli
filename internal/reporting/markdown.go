package reporting

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
)

// WriteMarkdown renders a GitHub-flavored report suitable for issues,
// pull requests, and AI-agent context.
func WriteMarkdown(w io.Writer, r *Report) error {
	var b strings.Builder
	b.WriteString("# Ultimate Security CLI — Security Report\n\n")
	b.WriteString(fmt.Sprintf("- **Tool:** %s %s\n", r.Tool.Name, r.Tool.Version))
	b.WriteString(fmt.Sprintf("- **Platform:** %s/%s\n", r.Environment.OS, r.Environment.Arch))
	b.WriteString(fmt.Sprintf("- **Started:** %s\n", r.Scan.StartedAt.UTC().Format(timeFormat)))
	b.WriteString(fmt.Sprintf("- **Duration:** %d ms\n", r.Scan.DurationMs))
	if r.Scan.Offline {
		b.WriteString("- **Mode:** offline\n")
	}
	if r.Scan.Deep {
		b.WriteString("- **Mode:** deep\n")
	}
	b.WriteString("\n## Summary\n\n")
	b.WriteString("| Severity | Findings |\n|---|---|\n")
	s := r.Summary
	fmt.Fprintf(&b, "| Critical | %d |\n| High | %d |\n| Medium | %d |\n| Low | %d |\n| Info | %d |\n",
		s.Critical, s.High, s.Medium, s.Low, s.Info)
	fmt.Fprintf(&b, "\n%d site(s) scanned · %d checks passed · %d skipped\n", s.SitesScanned, s.Passed, s.Skipped)

	cats := map[checks.Category]bool{}
	for _, site := range r.Sites {
		for c := range site.Categories {
			cats[checks.Category(c)] = true
		}
	}
	for _, site := range r.Sites {
		fmt.Fprintf(&b, "\n## Site `%s`\n\n", site.Path)
		fmt.Fprintf(&b, "| | |\n|---|---|\n")
		if site.WordPress != "" {
			fmt.Fprintf(&b, "| WordPress | %s |\n", site.WordPress)
		}
		if site.PHP != "" {
			fmt.Fprintf(&b, "| PHP | %s (%s) |\n", site.PHP, site.PHPSource)
		}
		if site.Server != "" {
			fmt.Fprintf(&b, "| Server | %s |\n", site.Server)
		}
		fmt.Fprintf(&b, "| **Score** | **%d / 100** |\n", site.Score)
		if len(site.Notes) > 0 {
			fmt.Fprintf(&b, "\n> %s\n", strings.Join(site.Notes, " "))
		}
		if len(site.Categories) > 0 {
			b.WriteString("\n### Category scores\n\n| Category | Score |\n|---|---|\n")
			keys := make([]string, 0, len(site.Categories))
			for c := range site.Categories {
				keys = append(keys, c)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "| %s | %d |\n", k, site.Categories[k])
			}
		}
		findings := failedFindings(site.Findings)
		if len(findings) == 0 {
			b.WriteString("\nNo failed findings.\n")
			continue
		}
		for _, f := range findings {
			fmt.Fprintf(&b, "\n### [%s] %s\n\n", strings.ToUpper(string(f.Severity)), f.Title)
			fmt.Fprintf(&b, "- **ID:** `%s`\n- **Category:** %s\n- **Confidence:** %s\n",
				f.ID, f.Category, f.Confidence)
			if f.Description != "" {
				fmt.Fprintf(&b, "\n%s\n", f.Description)
			}
			if len(f.Evidence) > 0 {
				b.WriteString("\n**Evidence**\n\n")
				for _, k := range sortedKeys(f.Evidence) {
					fmt.Fprintf(&b, "- %s: `%s`\n", k, f.Evidence[k])
				}
			}
			if f.Recommendation != "" {
				fmt.Fprintf(&b, "\n**Recommendation:** %s\n", f.Recommendation)
			}
			if len(f.References) > 0 {
				b.WriteString("\n**References**\n\n")
				for _, ref := range f.References {
					fmt.Fprintf(&b, "- <%s>\n", ref)
				}
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
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
