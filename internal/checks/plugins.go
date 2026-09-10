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

// displayLimit caps how many items are rendered into one finding's evidence.
const displayLimit = 15

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "PLUGIN_OUTDATED",
			Title:       "Plugins with available updates",
			Category:    CatPlugins,
			Description: "Outdated plugins miss security fixes. Update status comes from WP-CLI (which asks the official WordPress.org update API); a static scan skips this check. Inactive plugins are still reported: their PHP remains web-accessible even while deactivated.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/plugins/",
			},
			Importance: ImpStandard,
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
			Importance: ImpCore,
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
			Importance: ImpStandard,
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
			Description: "Outdated themes miss security fixes. Update status comes from WP-CLI; a static scan skips this check.",
			References: []string{
				"https://developer.wordpress.org/appearance/",
			},
			Importance: ImpStandard,
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
			Importance: ImpCore,
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
			Importance: ImpStandard,
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
		return []Finding{m.skipf("WP-CLI unavailable (update data requires it; rerun with --live)")}
	}
	var outdated, inactiveOutdated []string
	occ := []Occurrence{}
	for _, r := range rows {
		if !strings.EqualFold(r.Update, "available") {
			continue
		}
		fixed := r.UpdateVersion
		if fixed == "" {
			fixed = "latest"
		}
		inactive := strings.EqualFold(r.Status, "inactive")
		line := fmt.Sprintf("%s %s -> %s", r.Name, r.Version, fixed)
		detail := ""
		if inactive {
			inactiveOutdated = append(inactiveOutdated, line)
			line += " (inactive)"
			detail = "inactive plugin; update or remove it"
		} else {
			outdated = append(outdated, line)
		}
		occ = append(occ, Occurrence{
			ResourceType: "plugin", Slug: r.Name, Version: r.Version,
			FixedIn: []string{fixed}, Detail: detail,
		})
	}
	total := len(occ)
	if total == 0 {
		return []Finding{{ID: m.ID, Title: "All plugins up to date", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "WP-CLI reports no pending plugin updates."}}
	}
	shown := append(append([]string{}, outdated...), inactiveOutdated...)
	ev := map[string]string{}
	if len(shown) > displayLimit {
		// Counts must describe the finding, not the truncated display list.
		shown = append(shown[:displayLimit], fmt.Sprintf("… and %d more", total-displayLimit))
	}
	ev["updates"] = strings.Join(shown, ", ")
	ev["update_count"] = itoa(total)
	if len(inactiveOutdated) > 0 {
		ev["inactive_with_updates"] = itoa(len(inactiveOutdated))
	}
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d plugin(s) have updates available (%d active, %d inactive). Updates frequently include security fixes, and inactive plugin code stays web-reachable.", total, len(outdated), len(inactiveOutdated)),
		Evidence:       ev,
		Occurrences:    occ,
		Recommendation: "Review the changelogs and update the plugins (back up first). Remove inactive plugins you do not plan to use.",
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

// vulnLines renders the human-readable lines for one component's advisories.
func vulnLines(vulns []vulnerability.Vuln, limit int) []string {
	var out []string
	for i, v := range vulns {
		if i >= limit {
			break
		}
		label := v.ID
		if v.CVE != "" {
			label = v.CVE
		}
		fixed := v.Patched
		if fixed == "" {
			fixed = "none listed"
		}
		out = append(out, fmt.Sprintf("%s (%s) fixed in: %s", label, v.Rating, fixed))
	}
	if len(vulns) > limit {
		out = append(out, fmt.Sprintf("… %d more", len(vulns)-limit))
	}
	return out
}

// occurrenceForVuln converts one provider advisory into a structured
// occurrence, so consumers never have to parse a joined evidence string.
func occurrenceForVuln(resourceType, slug, version string, v vulnerability.Vuln) Occurrence {
	occ := Occurrence{
		ResourceType:   resourceType,
		Slug:           slug,
		Version:        version,
		AdvisoryID:     v.ID,
		CVE:            v.CVE,
		CVSSScore:      v.CVSSScore,
		Severity:       string(v.Rating),
		Provider:       v.Source,
		KnownExploited: v.Exploited,
		Detail:         v.Remediation,
	}
	if len(v.PatchedRanges) > 0 {
		occ.FixedIn = v.PatchedRanges
	} else if v.Patched != "" {
		occ.FixedIn = []string{v.Patched}
	}
	if len(occ.FixedIn) == 0 && v.PatchedBool != nil {
		occ.Patched = v.PatchedBool
	}
	return occ
}

// vulnLookupError converts a provider failure into a skipped finding, keeping
// the two distinct cases (no provider vs. provider failure) separate.
func vulnLookupError(ctx *Context, m Meta, err error) []Finding {
	if ctx.Vulns.Name() == "none" {
		return []Finding{m.skipf("vulnerability data unavailable — configure a provider (see docs/vulnerability-data.md)")}
	}
	return []Finding{m.skipf("vulnerability lookup failed: " + err.Error())}
}

// vulnFindings runs the shared plugin/theme vulnerability logic.
func vulnFindings(ctx *Context, m Meta, kind string, installed []extRef) []Finding {
	if len(installed) == 0 {
		return []Finding{m.skipf("no " + kind + "s detected")}
	}
	var occurrences []Occurrence
	var summary []string
	affected := 0
	var worstSev Severity
	lookup := ctx.Vulns.LookupPlugin
	if kind == "theme" {
		lookup = ctx.Vulns.LookupTheme
	}
	for _, item := range installed {
		vulns, err := lookup(item.slug, item.version)
		if err != nil {
			return vulnLookupError(ctx, m, err)
		}
		if len(vulns) == 0 {
			continue
		}
		affected++
		summary = append(summary, fmt.Sprintf("%s %s:", item.slug, orDash(item.version)))
		summary = append(summary, vulnLines(vulns, 10)...)
		for _, v := range vulns {
			occurrences = append(occurrences, occurrenceForVuln(kind, item.slug, item.version, v))
		}
		if s, _ := vulnSeverity(vulns); s.Rank() > worstSev.Rank() {
			worstSev = s
		}
	}
	if affected == 0 {
		return []Finding{{ID: m.ID, Title: "No known " + kind + " vulnerabilities", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfMedium,
			Description: fmt.Sprintf("None of the %d installed %s(s) match known vulnerabilities in the configured data source.", len(installed), kind)}}
	}
	ev := map[string]string{
		"matches":             strings.Join(summary, "; "),
		"affected_components": itoa(affected),
		"advisory_count":      itoa(len(occurrences)),
	}
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: worstSev, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d installed %s(s) match %d known vulnerabilit(ies).", affected, kind, len(occurrences)),
		Evidence:       ev,
		Occurrences:    occurrences,
		Recommendation: "Update every affected " + kind + " to the fixed version. If no fix exists, deactivate and remove it.",
		References:     m.References,
	}}
}

// extRef is the minimal component identity the vulnerability lookups need.
type extRef struct {
	slug    string
	version string
}

// installedPlugins merges filesystem inventory with WP-CLI rows.
func installedPlugins(ctx *Context) []extRef {
	var out []extRef
	seen := map[string]bool{}
	for _, p := range ctx.Site.Plugins {
		out = append(out, extRef{slug: p.Slug, version: p.Version})
		seen[p.Slug] = true
	}
	if ctx.WP != nil {
		for _, r := range ctx.WP.Plugins {
			if seen[r.Name] {
				continue
			}
			out = append(out, extRef{slug: r.Name, version: r.Version})
		}
	}
	return out
}

// installedThemes merges filesystem inventory with WP-CLI rows.
func installedThemes(ctx *Context) []extRef {
	var out []extRef
	seen := map[string]bool{}
	for _, t := range ctx.Site.Themes {
		out = append(out, extRef{slug: t.Slug, version: t.Version})
		seen[t.Slug] = true
	}
	if ctx.WP != nil {
		for _, r := range ctx.WP.Themes {
			if seen[r.Name] {
				continue
			}
			out = append(out, extRef{slug: r.Name, version: r.Version})
		}
	}
	return out
}

func runPluginVulns(ctx *Context) []Finding {
	m := Meta{ID: "PLUGIN_VULNERABILITY", Title: "Plugins with known vulnerabilities", Category: CatPlugins,
		References: []string{"https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/"}}
	return vulnFindings(ctx, m, "plugin", installedPlugins(ctx))
}

func runThemeVulns(ctx *Context) []Finding {
	m := Meta{ID: "THEME_VULNERABILITY", Title: "Themes with known vulnerabilities", Category: CatThemes,
		References: []string{"https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/"}}
	return vulnFindings(ctx, m, "theme", installedThemes(ctx))
}

func runInactivePlugins(ctx *Context) []Finding {
	m := Meta{ID: "INACTIVE_PLUGIN", Title: "Inactive plugins installed", Category: CatPlugins,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
	if ctx.WP == nil {
		return []Finding{m.skipf("WP-CLI unavailable (activation state requires it; rerun with --live)")}
	}
	var inactive []string
	for _, r := range ctx.WP.Plugins {
		if strings.EqualFold(r.Status, "inactive") {
			inactive = append(inactive, r.Name)
		}
	}
	sort.Strings(inactive)
	if len(inactive) == 0 {
		return []Finding{{ID: m.ID, Title: "No inactive plugins", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No deactivated plugins are installed."}}
	}
	total := len(inactive)
	shown := inactive
	if len(shown) > displayLimit {
		shown = append(shown[:displayLimit], fmt.Sprintf("… and %d more", total-displayLimit))
	}
	occ := make([]Occurrence, 0, len(inactive))
	for _, slug := range inactive {
		occ = append(occ, Occurrence{ResourceType: "plugin", Slug: slug, Detail: "deactivated"})
	}
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d inactive plugin(s) are installed. Their PHP remains web-accessible and exploitable even while deactivated.", total),
		Evidence:       map[string]string{"plugins": strings.Join(shown, ", "), "inactive_count": itoa(total)},
		Occurrences:    occ,
		Recommendation: "Delete inactive plugins you do not plan to re-enable.",
		References:     m.References,
	}}
}

func runThemeOutdated(ctx *Context) []Finding {
	m := Meta{ID: "THEME_OUTDATED", Title: "Themes with available updates", Category: CatThemes,
		References: []string{"https://developer.wordpress.org/appearance/"}}
	rows := extRows(ctx, "theme")
	if rows == nil {
		return []Finding{m.skipf("WP-CLI unavailable (update data requires it; rerun with --live)")}
	}
	var outdated []string
	occ := []Occurrence{}
	for _, r := range rows {
		if !strings.EqualFold(r.Update, "available") {
			continue
		}
		fixed := r.UpdateVersion
		if fixed == "" {
			fixed = "latest"
		}
		outdated = append(outdated, fmt.Sprintf("%s %s -> %s", r.Name, r.Version, fixed))
		occ = append(occ, Occurrence{ResourceType: "theme", Slug: r.Name, Version: r.Version, FixedIn: []string{fixed}})
	}
	if len(outdated) == 0 {
		return []Finding{{ID: m.ID, Title: "All themes up to date", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "WP-CLI reports no pending theme updates."}}
	}
	total := len(outdated)
	shown := outdated
	if len(shown) > displayLimit {
		shown = append(shown[:displayLimit], fmt.Sprintf("… and %d more", total-displayLimit))
	}
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d theme(s) have updates available.", total),
		Evidence:       map[string]string{"updates": strings.Join(shown, ", "), "update_count": itoa(total)},
		Occurrences:    occ,
		Recommendation: "Update the themes (back up first; child themes survive parent updates).",
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
		return []Finding{{ID: m.ID, Title: "Single theme installed", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No unused themes are installed."}}
	}
	if inactive == 1 && ctx.WP == nil {
		return []Finding{{ID: m.ID, Title: "One additional theme", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfLow,
			Description: "One additional theme is installed (likely the active theme's fallback); activation state unknown without WP-CLI."}}
	}
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevInfo, Status: StatusFailed, Confidence: ConfMedium,
		Description:    fmt.Sprintf("%d unused theme(s) are installed. Inactive themes remain executable attack surface.", inactive),
		Evidence:       map[string]string{"unused_count": itoa(inactive)},
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

// wordpress import guard: the theme/plugin inventory types are used by the
// helpers above.
var _ = wordpress.Theme{}
