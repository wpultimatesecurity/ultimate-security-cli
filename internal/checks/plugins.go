package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/vulnerability"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wpcli"
)

// wpExtStatus aliases the WP-CLI row type.
type wpExtStatus = wpcli.ExtStatus

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "PLUGIN_OUTDATED",
			Title:       "Plugins with available updates",
			Category:    CatPlugins,
			Description: "Outdated plugins miss security fixes. Update status comes from WP-CLI (which asks the official WordPress.org update API); a filesystem-only scan skips this check.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/plugins/",
			},
		},
		Run: runPluginOutdated,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "PLUGIN_VULNERABILITY",
			Title:       "Plugins with known vulnerabilities",
			Category:    CatPlugins,
			Description: "Matches installed plugin versions against a vulnerability data provider. Findings only come from the provider — versions are never guessed to be vulnerable because they are old.",
			References: []string{
				"https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/",
			},
		},
		Run: runPluginVulns,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "INACTIVE_PLUGIN",
			Title:       "Inactive plugins installed",
			Category:    CatPlugins,
			Description: "Deactivated plugins keep their PHP loadable and exploitable even while unused. Delete plugins that are no longer needed.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/security/",
			},
		},
		Run: runInactivePlugins,
	})
}

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "THEME_OUTDATED",
			Title:       "Themes with available updates",
			Category:    CatThemes,
			Description: "Outdated themes miss security fixes. Update status comes from WP-CLI; a filesystem-only scan skips this check.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/appearance/",
			},
		},
		Run: runThemeOutdated,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "THEME_VULNERABILITY",
			Title:       "Themes with known vulnerabilities",
			Category:    CatThemes,
			Description: "Matches installed theme versions against a vulnerability data provider.",
			References: []string{
				"https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/",
			},
		},
		Run: runThemeVulns,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "INACTIVE_THEME",
			Title:       "Unused themes installed",
			Category:    CatThemes,
			Description: "Every installed theme is executable PHP regardless of activation. Keeping unused themes around enlarges the attack surface.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/security/",
			},
		},
		Run: runInactiveThemes,
	})
}

// extRows picks the WP-CLI extension rows, falling back to nothing.
func extRows(ctx *Context, kind string) []wpExtStatus {
	if ctx.WP == nil {
		return nil
	}
	if kind == "plugin" {
		return ctx.WP.Plugins
	}
	return ctx.WP.Themes
}

func runPluginOutdated(ctx *Context) []Finding {
	m := Meta{ID: "PLUGIN_OUTDATED", Title: "Plugins with available updates", Category: CatPlugins,
		References: []string{"https://developer.wordpress.org/advanced-administration/plugins/"}}
	rows := extRows(ctx, "plugin")
	if rows == nil {
		return []Finding{m.skipf("WP-CLI unavailable (update data requires it)")}
	}
	var outdated []string
	for _, r := range rows {
		if strings.EqualFold(r.Status, "inactive") {
			continue
		}
		if strings.EqualFold(r.Update, "available") {
			fixed := r.UpdateVersion
			if fixed == "" {
				fixed = "latest"
			}
			outdated = append(outdated, fmt.Sprintf("%s %s -> %s", r.Name, r.Version, fixed))
		}
	}
	if len(outdated) == 0 {
		return []Finding{Finding{ID: m.ID, Title: "All plugins up to date", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "WP-CLI reports no pending plugin updates."}}
	}
	if len(outdated) > 15 {
		outdated = append(outdated[:15], fmt.Sprintf("… and %d more", len(outdated)-15))
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d active plugin(s) have updates available. Updates frequently include security fixes.", len(outdated)),
		Evidence:       map[string]string{"updates": strings.Join(outdated, ", ")},
		Recommendation: "Review the changelogs and update the plugins (back up first).",
		References:     m.References,
	}}
}

// vulnSeverity picks the finding severity for a set of vulns.
func vulnSeverity(vulns []vulnerability.Vuln) (Severity, vulnerability.Vuln) {
	worst := vulnerability.Vuln{}
	sev := SevInfo
	for _, v := range vulns {
		s := severityOf(v)
		if s.Rank() > sev.Rank() {
			sev = s
			worst = v
		}
	}
	if sev == SevInfo {
		sev = SevHigh // affected with unknown rating: assume significant
	}
	return sev, worst
}

func severityOf(v vulnerability.Vuln) Severity {
	switch v.Rating {
	case vulnerability.SeverityCritical:
		return SevCritical
	case vulnerability.SeverityHigh:
		return SevHigh
	case vulnerability.SeverityMedium:
		return SevMedium
	case vulnerability.SeverityLow:
		return SevLow
	default:
		return SevInfo // triggers the assume-significant default
	}
}

func vulnLines(vulns []vulnerability.Vuln, limit int) []string {
	var out []string
	for _, v := range vulns {
		label := v.ID
		if v.CVE != "" {
			label = v.CVE
		}
		fixed := v.Patched
		if fixed == "" {
			fixed = "none listed"
		}
		out = append(out, fmt.Sprintf("%s (%s) fixed in: %s", label, v.Rating, fixed))
		if len(out) >= limit {
			out = append(out, fmt.Sprintf("… %d more", len(vulns)-limit))
			break
		}
	}
	return out
}

func runPluginVulns(ctx *Context) []Finding {
	m := Meta{ID: "PLUGIN_VULNERABILITY", Title: "Plugins with known vulnerabilities", Category: CatPlugins,
		References: []string{"https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/"}}
	installed := ctx.Site.Plugins
	if len(installed) == 0 && ctx.WP != nil {
		for _, r := range ctx.WP.Plugins {
			installed = append(installed, wordpress.Plugin{Slug: r.Name, Name: r.Name, Version: r.Version})
		}
	}
	if len(installed) == 0 {
		return []Finding{m.skipf("no plugins detected")}
	}
	var all []string
	affected := 0
	var worstSev Severity
	for _, p := range installed {
		vulns, err := ctx.Vulns.LookupPlugin(p.Slug, p.Version)
		if err != nil {
			if ctx.Vulns.Name() == "none" {
				return []Finding{m.skipf("vulnerability data unavailable — configure a provider (see docs/vulnerability-data.md)")}
			}
			return []Finding{m.skipf("vulnerability lookup failed: " + err.Error())}
		}
		if len(vulns) == 0 {
			continue
		}
		affected++
		lines := vulnLines(vulns, 10)
		all = append(all, fmt.Sprintf("%s %s:", p.Slug, orDash(p.Version)))
		all = append(all, lines...)
		if s, _ := vulnSeverity(vulns); s.Rank() > worstSev.Rank() {
			worstSev = s
		}
	}
	if affected == 0 {
		return []Finding{Finding{ID: m.ID, Title: "No known plugin vulnerabilities", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfMedium,
			Description: fmt.Sprintf("None of the %d installed plugins match known vulnerabilities in the configured data source.", len(installed))}}
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: worstSev, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d installed plugin(s) match known vulnerabilities.", affected),
		Evidence:       map[string]string{"matches": strings.Join(all, "; ")},
		Recommendation: "Update every affected plugin to the fixed version. If no fix exists, deactivate and remove the plugin.",
		References:     m.References,
	}}
}

func runInactivePlugins(ctx *Context) []Finding {
	m := Meta{ID: "INACTIVE_PLUGIN", Title: "Inactive plugins installed", Category: CatPlugins,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
	if ctx.WP == nil {
		return []Finding{m.skipf("WP-CLI unavailable (activation state requires it)")}
	}
	var inactive []string
	for _, r := range ctx.WP.Plugins {
		if strings.EqualFold(r.Status, "inactive") {
			inactive = append(inactive, r.Name)
		}
	}
	sort.Strings(inactive)
	if len(inactive) == 0 {
		return []Finding{Finding{ID: m.ID, Title: "No inactive plugins", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No deactivated plugins are installed."}}
	}
	if len(inactive) > 15 {
		inactive = append(inactive[:15], fmt.Sprintf("… and %d more", len(inactive)-15))
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d inactive plugin(s) are installed. Their PHP remains web-accessible and exploitable even while deactivated.", len(inactive)),
		Evidence:       map[string]string{"plugins": strings.Join(inactive, ", ")},
		Recommendation: "Delete inactive plugins you do not plan to re-enable.",
		References:     m.References,
	}}
}

func runThemeOutdated(ctx *Context) []Finding {
	m := Meta{ID: "THEME_OUTDATED", Title: "Themes with available updates", Category: CatThemes,
		References: []string{"https://developer.wordpress.org/advanced-administration/appearance/"}}
	rows := extRows(ctx, "theme")
	if rows == nil {
		return []Finding{m.skipf("WP-CLI unavailable (update data requires it)")}
	}
	var outdated []string
	for _, r := range rows {
		if strings.EqualFold(r.Update, "available") {
			fixed := r.UpdateVersion
			if fixed == "" {
				fixed = "latest"
			}
			outdated = append(outdated, fmt.Sprintf("%s %s -> %s", r.Name, r.Version, fixed))
		}
	}
	if len(outdated) == 0 {
		return []Finding{Finding{ID: m.ID, Title: "All themes up to date", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "WP-CLI reports no pending theme updates."}}
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d theme(s) have updates available.", len(outdated)),
		Evidence:       map[string]string{"updates": strings.Join(outdated, ", ")},
		Recommendation: "Update the themes (back up first; child themes survive parent updates).",
		References:     m.References,
	}}
}

func runThemeVulns(ctx *Context) []Finding {
	m := Meta{ID: "THEME_VULNERABILITY", Title: "Themes with known vulnerabilities", Category: CatThemes,
		References: []string{"https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/"}}
	installed := ctx.Site.Themes
	if len(installed) == 0 && ctx.WP != nil {
		for _, r := range ctx.WP.Themes {
			installed = append(installed, wordpress.Theme{Slug: r.Name, Name: r.Name, Version: r.Version})
		}
	}
	if len(installed) == 0 {
		return []Finding{m.skipf("no themes detected")}
	}
	var all []string
	affected := 0
	var worstSev Severity
	for _, t := range installed {
		vulns, err := ctx.Vulns.LookupTheme(t.Slug, t.Version)
		if err != nil {
			if ctx.Vulns.Name() == "none" {
				return []Finding{m.skipf("vulnerability data unavailable — configure a provider (see docs/vulnerability-data.md)")}
			}
			return []Finding{m.skipf("vulnerability lookup failed: " + err.Error())}
		}
		if len(vulns) == 0 {
			continue
		}
		affected++
		all = append(all, fmt.Sprintf("%s %s:", t.Slug, orDash(t.Version)))
		all = append(all, vulnLines(vulns, 10)...)
		if s, _ := vulnSeverity(vulns); s.Rank() > worstSev.Rank() {
			worstSev = s
		}
	}
	if affected == 0 {
		return []Finding{Finding{ID: m.ID, Title: "No known theme vulnerabilities", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfMedium,
			Description: fmt.Sprintf("None of the %d installed themes match known vulnerabilities in the configured data source.", len(installed))}}
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: worstSev, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d installed theme(s) match known vulnerabilities.", affected),
		Evidence:       map[string]string{"matches": strings.Join(all, "; ")},
		Recommendation: "Update every affected theme to the fixed version. If no fix exists, switch themes and remove the affected one.",
		References:     m.References,
	}}
}

func runInactiveThemes(ctx *Context) []Finding {
	m := Meta{ID: "INACTIVE_THEME", Title: "Unused themes installed", Category: CatThemes,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
	inactive := len(ctx.Site.Themes)
	if ctx.WP != nil {
		inactive = 0
		for _, r := range ctx.WP.Themes {
			if !strings.EqualFold(r.Status, "active") {
				inactive++
			}
		}
	}
	if inactive == 0 {
		return []Finding{Finding{ID: m.ID, Title: "Single theme installed", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No unused themes are installed."}}
	}
	if inactive == 1 && ctx.WP == nil {
		return []Finding{Finding{ID: m.ID, Title: "One additional theme", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfLow,
			Description: "One additional theme is installed (likely the active theme's fallback); activation state unknown without WP-CLI."}}
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevInfo, Status: StatusFailed, Confidence: ConfMedium,
		Description:    fmt.Sprintf("%d unused theme(s) are installed. Inactive themes remain executable attack surface.", inactive),
		Evidence:       map[string]string{"unused_count": fmt.Sprint(inactive)},
		Recommendation: "Remove themes you do not use, keeping only the active theme and a known-good fallback.",
		References:     m.References,
	}}
}

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
