package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/vulnerability"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
)

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "WP_CORE_OUTDATED",
			Title:       "WordPress core is not current",
			Category:    CatCore,
			Description: "Compares the installed WordPress version against the official WordPress.org release feed. Versions the feed marks insecure are high severity; merely outdated versions medium.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/",
				"https://api.wordpress.org/core/stable-check/1.7/",
			},
			Importance: ImpStandard,
		},
		Run: runCoreOutdated,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "WP_CORE_AUTO_UPDATES_DISABLED",
			Title:       "WordPress automatic background updates are disabled",
			Category:    CatCore,
			Description: "WordPress applies minor (security/maintenance) core updates automatically by default. AUTOMATIC_UPDATER_DISABLED=true or WP_AUTO_UPDATE_CORE=false turns that off, leaving known-patched holes open between releases.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/upgrade/updating-wordpress/",
			},
			Importance: ImpContext,
		},
		Run: runCoreAutoUpdates,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "WP_CORE_VULNERABILITY",
			Title:       "WordPress core has known vulnerabilities",
			Category:    CatCore,
			Description: "Matches the installed core version against a vulnerability data provider. Distinct from WP_CORE_OUTDATED (maintenance state) and CORE_INTEGRITY_MODIFIED (local file tampering): this reports advisories that affect this exact version. Requires a configured vulnerability provider.",
			References: []string{
				"https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/",
			},
			Importance: ImpCore,
		},
		Run: runCoreVulnerability,
	})
}

func siteVersion(ctx *Context) string {
	if ctx.Site.Version != "" {
		return ctx.Site.Version
	}
	if ctx.WP != nil && ctx.WP.Version != "" {
		return ctx.WP.Version
	}
	return ""
}

func runCoreOutdated(ctx *Context) []Finding {
	m := Meta{
		ID: "WP_CORE_OUTDATED", Title: "WordPress core is not current", Category: CatCore,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/"},
	}
	installed := siteVersion(ctx)
	if installed == "" {
		return []Finding{m.skipf("WordPress version could not be determined")}
	}
	if ctx.Core == nil {
		return []Finding{m.skipf("WordPress.org release data unavailable (offline or fetch failed)")}
	}
	class := ctx.Core.Classify(installed)
	ev := map[string]string{"installed": installed, "latest": ctx.Core.Latest}
	switch class {
	case "insecure":
		return []Finding{Finding{
			ID: m.ID, Title: "WordPress core is insecure", Category: m.Category,
			Severity: SevHigh, Status: StatusFailed, Confidence: ConfHigh,
			Description:    fmt.Sprintf("WordPress %s is marked insecure by WordPress.org. Known vulnerabilities are fixed in newer releases.", installed),
			Evidence:       ev,
			Recommendation: fmt.Sprintf("Update WordPress to %s or the newest available release (back up first).", ctx.Core.Latest),
			References:     m.References,
		}}
	case "outdated":
		return []Finding{Finding{
			ID: m.ID, Title: "WordPress core is outdated", Category: m.Category,
			Severity: SevMedium, Status: StatusFailed, Confidence: ConfHigh,
			Description:    fmt.Sprintf("WordPress %s is not the current release (%s). Older releases miss security fixes.", installed, ctx.Core.Latest),
			Evidence:       ev,
			Recommendation: fmt.Sprintf("Update WordPress to %s.", ctx.Core.Latest),
			References:     m.References,
		}}
	case "latest", "stable":
		return []Finding{Finding{
			ID: m.ID, Title: "WordPress core is up to date", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: fmt.Sprintf("WordPress %s is a current release.", installed),
			Evidence:    ev,
		}}
	default:
		return []Finding{Finding{
			ID: m.ID, Title: "WordPress version not recognized by the release feed", Category: m.Category,
			Severity: SevInfo, Status: StatusUnknown, Confidence: ConfLow,
			Description: fmt.Sprintf("Version %s was not found in the WordPress.org release feed; it may be a development or prerelease build.", installed),
			Evidence:    ev,
		}}
	}
}

// runCoreVulnerability reports advisories that affect the installed core
// version itself, which is a different question from "is it current".
func runCoreVulnerability(ctx *Context) []Finding {
	m := Meta{ID: "WP_CORE_VULNERABILITY", Title: "WordPress core has known vulnerabilities", Category: CatCore,
		References: []string{"https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/"}}
	installed := siteVersion(ctx)
	if installed == "" {
		return []Finding{m.skipf("WordPress version could not be determined")}
	}
	if ctx.Vulns.Name() == "none" {
		return []Finding{m.skipf("vulnerability data unavailable — configure a provider (see docs/vulnerability-data.md)")}
	}
	vulns, err := ctx.Vulns.LookupCore(installed)
	if err != nil {
		return []Finding{m.skipf("vulnerability lookup failed: " + err.Error())}
	}
	if len(vulns) == 0 {
		return []Finding{{ID: m.ID, Title: "No known core vulnerabilities", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfMedium,
			Description: fmt.Sprintf("WordPress %s does not match any advisory in the configured data source.", installed)}}
	}
	sev, _ := vulnSeverity(vulns)
	occ := make([]Occurrence, 0, len(vulns))
	for _, v := range vulns {
		occ = append(occ, occurrenceForVuln("core", "wordpress", installed, v))
	}
	var lines []string
	for i, v := range vulns {
		if i >= 10 {
			lines = append(lines, fmt.Sprintf("… %d more", len(vulns)-10))
			break
		}
		lines = append(lines, strings.Join(vulnLines([]vulnerability.Vuln{v}, 1), ""))
	}
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: sev, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("WordPress %s matches %d known vulnerabilit(ies) in the configured data source.", installed, len(vulns)),
		Evidence:       map[string]string{"installed": installed, "advisories": strings.Join(lines, "; ")},
		Occurrences:    occ,
		Recommendation: "Update WordPress to a release that fixes these advisories; if the site cannot be updated immediately, apply the provider's mitigation.",
		References:     m.References,
	}}
}

func runCoreAutoUpdates(ctx *Context) []Finding {
	m := Meta{
		ID: "WP_CORE_AUTO_UPDATES_DISABLED", Title: "Automatic background updates are disabled", Category: CatCore,
		References: []string{"https://developer.wordpress.org/advanced-administration/upgrade/updating-wordpress/"},
	}
	cfg := ctx.Site.Config
	if cfg == nil || !cfg.Exists {
		return []Finding{m.skipf("wp-config.php not readable")}
	}
	if v, ok := cfg.Bool("AUTOMATIC_UPDATER_DISABLED"); ok && v {
		return []Finding{Finding{
			ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
			Description:    "wp-config.php defines AUTOMATIC_UPDATER_DISABLED as true, disabling all automatic background updates.",
			Evidence:       map[string]string{"file": "wp-config.php", "constant": "AUTOMATIC_UPDATER_DISABLED"},
			Recommendation: "Remove the AUTOMATIC_UPDATER_DISABLED definition so security updates apply automatically.",
			References:     m.References,
		}}
	}
	if raw, ok := cfg.Defines["WP_AUTO_UPDATE_CORE"]; ok && strings.EqualFold(strings.TrimSpace(raw), "false") {
		return []Finding{Finding{
			ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
			Description:    "wp-config.php defines WP_AUTO_UPDATE_CORE as false, disabling automatic core updates.",
			Evidence:       map[string]string{"file": "wp-config.php", "constant": "WP_AUTO_UPDATE_CORE"},
			Recommendation: "Set WP_AUTO_UPDATE_CORE to 'minor' (the default) or true so security releases install automatically.",
			References:     m.References,
		}}
	}
	return []Finding{Finding{
		ID: m.ID, Title: "Automatic core minor updates enabled", Category: m.Category,
		Severity: SevInfo, Status: StatusPassed, Confidence: ConfMedium,
		Description: "No configuration disabling automatic minor updates was found; WordPress applies them by default.",
	}}
}

// devEnv reports whether the site declares a non-production environment.
func devEnv(ctx *Context) bool {
	if ctx.Site.Config == nil {
		return false
	}
	v, ok := ctx.Site.Config.String("WP_ENVIRONMENT_TYPE")
	if !ok {
		return false
	}
	switch strings.ToLower(v) {
	case "local", "development", "staging":
		return true
	}
	return false
}

// envSeverity downgrades production-severity findings on declared dev sites.
func envSeverity(ctx *Context, prod Severity) Severity {
	if devEnv(ctx) {
		return SevLow
	}
	return prod
}

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "WP_DEBUG_ENABLED",
			Title:       "WP_DEBUG is enabled",
			Category:    CatConfig,
			Description: "WP_DEBUG writes diagnostics that can leak paths and internal details. On production it should stay off.",
			References:  []string{"https://developer.wordpress.org/debugging-in-wordpress/"},
			Importance:  ImpContext,
		},
		Run: runDebug,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "WP_DEBUG_DISPLAY_ENABLED",
			Title:       "WP_DEBUG_DISPLAY shows errors to visitors",
			Category:    CatConfig,
			Description: "With WP_DEBUG_DISPLAY on (the WordPress default when WP_DEBUG is enabled and it is not defined), PHP errors are printed in page output and can disclose paths, SQL, and secrets.",
			References:  []string{"https://developer.wordpress.org/debugging-in-wordpress/"},
			Importance:  ImpContext,
		},
		Run: runDebugDisplay,
	})
}

func runDebug(ctx *Context) []Finding {
	m := Meta{ID: "WP_DEBUG_ENABLED", Title: "WP_DEBUG is enabled", Category: CatConfig,
		References: []string{"https://developer.wordpress.org/debugging-in-wordpress/"}}
	cfg := ctx.Site.Config
	if cfg == nil || !cfg.Exists {
		return []Finding{m.skipf("wp-config.php not readable")}
	}
	v, ok := cfg.Bool("WP_DEBUG")
	if !ok || !v {
		return []Finding{Finding{ID: m.ID, Title: "WP_DEBUG disabled", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "WP_DEBUG is not enabled."}}
	}
	sev := envSeverity(ctx, SevMedium)
	desc := "wp-config.php enables WP_DEBUG."
	if sev == SevLow {
		desc += " WP_ENVIRONMENT_TYPE declares a non-production environment, so this is expected in development."
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: sev, Status: StatusFailed, Confidence: ConfHigh,
		Description:    desc,
		Evidence:       map[string]string{"file": "wp-config.php", "constant": "WP_DEBUG"},
		Recommendation: "Disable WP_DEBUG on production. If diagnostics are needed, enable WP_DEBUG_LOG and keep WP_DEBUG_DISPLAY off.",
		References:     m.References,
	}}
}

func runDebugDisplay(ctx *Context) []Finding {
	m := Meta{ID: "WP_DEBUG_DISPLAY_ENABLED", Title: "WP_DEBUG_DISPLAY shows errors to visitors", Category: CatConfig,
		References: []string{"https://developer.wordpress.org/debugging-in-wordpress/"}}
	cfg := ctx.Site.Config
	if cfg == nil || !cfg.Exists {
		return []Finding{m.skipf("wp-config.php not readable")}
	}
	debug, _ := cfg.Bool("WP_DEBUG")
	if !debug {
		return []Finding{m.skipf("WP_DEBUG is off; WP_DEBUG_DISPLAY has no effect")}
	}
	v, defined := cfg.Bool("WP_DEBUG_DISPLAY")
	if defined && !v {
		return []Finding{Finding{ID: m.ID, Title: "Error display disabled", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "WP_DEBUG_DISPLAY is explicitly disabled."}}
	}
	sev := envSeverity(ctx, SevMedium)
	desc := "WP_DEBUG is on and WP_DEBUG_DISPLAY is not explicitly disabled, so PHP errors are rendered to site visitors (the WordPress default)."
	if defined {
		desc = "WP_DEBUG_DISPLAY is explicitly enabled; PHP errors are rendered to site visitors."
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: sev, Status: StatusFailed, Confidence: ConfHigh,
		Description:    desc,
		Evidence:       map[string]string{"file": "wp-config.php"},
		Recommendation: "Set define( 'WP_DEBUG_DISPLAY', false ); and log errors with WP_DEBUG_LOG instead.",
		References:     m.References,
	}}
}

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "FILE_EDITOR_ENABLED",
			Title:       "Built-in plugin/theme file editor is enabled",
			Category:    CatConfig,
			Description: "WordPress ships a code editor in the admin. Once an admin account is compromised it becomes direct code execution; a typo can also take the site down.",
			References:  []string{"https://developer.wordpress.org/advanced-administration/security/security/"},
		},
		Run: runFileEditor,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "FILE_MODS_ALLOWED",
			Title:       "Admin file modifications are allowed",
			Category:    CatConfig,
			Description: "DISALLOW_FILE_MODS blocks plugin/theme installs and edits through the admin — useful hardening on sites managed by WP-CLI or deployment pipelines.",
			References:  []string{"https://developer.wordpress.org/advanced-administration/security/security/"},
			Importance:  ImpContext,
		},
		Run: runFileMods,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "SECURITY_KEYS_MISSING",
			Title:       "Authentication keys and salts are missing or default",
			Category:    CatConfig,
			Description: "The eight AUTH_KEY/LOGGED_IN_KEY/NONCE_KEY values and salts sign WordPress cookies. Missing or placeholder values make cookie forgery materially easier.",
			References:  []string{"https://developer.wordpress.org/advanced-administration/security/keys/"},
			Importance:  ImpCore,
		},
		Run: runSecurityKeys,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "FORCE_SSL_ADMIN_DISABLED",
			Title:       "FORCE_SSL_ADMIN is not enabled",
			Category:    CatHardening,
			Description: "FORCE_SSL_ADMIN pins all admin traffic to HTTPS. Modern WordPress forces HTTPS when the site URL uses it, so this is a gap only when the configuration is ambiguous or mixed.",
			References:  []string{"https://developer.wordpress.org/advanced-administration/security/https/"},
			Importance:  ImpContext,
		},
		Run: runForceSSLAdmin,
	})
}

func runFileEditor(ctx *Context) []Finding {
	m := Meta{ID: "FILE_EDITOR_ENABLED", Title: "Built-in file editor is enabled", Category: CatConfig,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
	cfg := ctx.Site.Config
	if cfg == nil || !cfg.Exists {
		return []Finding{m.skipf("wp-config.php not readable")}
	}
	if v, ok := cfg.Bool("DISALLOW_FILE_EDIT"); ok && v {
		return []Finding{Finding{ID: m.ID, Title: "File editor disabled", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "DISALLOW_FILE_EDIT is set to true."}}
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevMedium, Status: StatusFailed, Confidence: ConfHigh,
		Description:    "No DISALLOW_FILE_EDIT definition was found, so wp-admin can edit plugin and theme PHP directly.",
		Evidence:       map[string]string{"file": "wp-config.php"},
		Recommendation: "Add define( 'DISALLOW_FILE_EDIT', true ); to wp-config.php.",
		References:     m.References,
	}}
}

func runFileMods(ctx *Context) []Finding {
	m := Meta{ID: "FILE_MODS_ALLOWED", Title: "Admin file modifications are allowed", Category: CatConfig,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/security/"}}
	cfg := ctx.Site.Config
	if cfg == nil || !cfg.Exists {
		return []Finding{m.skipf("wp-config.php not readable")}
	}
	if v, ok := cfg.Bool("DISALLOW_FILE_MODS"); ok && v {
		return []Finding{Finding{ID: m.ID, Title: "File modifications disallowed", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "DISALLOW_FILE_MODS is set to true."}}
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		// Informational: DISALLOW_FILE_MODS is correct for immutable or
		// deployment-managed sites and wrong for others, so it is reported as
		// a policy signal rather than a universal deduction.
		Severity: SevInfo, Status: StatusFailed, Confidence: ConfHigh,
		Description:    "DISALLOW_FILE_MODS is not set; compromised admin credentials can install arbitrary plugin or theme code.",
		Evidence:       map[string]string{"file": "wp-config.php"},
		Recommendation: "On production sites managed outside wp-admin, add define( 'DISALLOW_FILE_MODS', true );.",
		References:     m.References,
	}}
}

func runSecurityKeys(ctx *Context) []Finding {
	m := Meta{ID: "SECURITY_KEYS_MISSING", Title: "Authentication keys and salts are missing or default", Category: CatConfig,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/keys/"}}
	cfg := ctx.Site.Config
	if cfg == nil || !cfg.Exists {
		return []Finding{m.skipf("wp-config.php not readable")}
	}
	states := cfg.KeyStates()
	var missing, placeholder []string
	for k, st := range states {
		switch st {
		case wordpress.KeyMissing:
			missing = append(missing, k)
		case wordpress.KeyPlaceholder:
			placeholder = append(placeholder, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(placeholder)
	if len(missing) == 0 && len(placeholder) == 0 {
		return []Finding{Finding{ID: m.ID, Title: "Authentication keys configured", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "All eight authentication keys and salts are defined."}}
	}
	ev := map[string]string{"file": "wp-config.php"}
	if len(missing) > 0 {
		ev["missing"] = strings.Join(missing, ", ")
	}
	if len(placeholder) > 0 {
		ev["placeholder_values"] = strings.Join(placeholder, ", ")
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevHigh, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d of 8 authentication key/salt constants are missing or still hold the installer placeholder; cookie signing degrades without them.", len(missing)+len(placeholder)),
		Evidence:       ev,
		Recommendation: "Generate fresh values with the WordPress.org salt service and define all eight constants in wp-config.php.",
		References:     m.References,
	}}
}

func runForceSSLAdmin(ctx *Context) []Finding {
	m := Meta{ID: "FORCE_SSL_ADMIN_DISABLED", Title: "FORCE_SSL_ADMIN is not enabled", Category: CatHardening,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/https/"}}
	cfg := ctx.Site.Config
	if cfg == nil || !cfg.Exists {
		return []Finding{m.skipf("wp-config.php not readable")}
	}
	if ctx.BaseURL == "" || !strings.HasPrefix(strings.ToLower(ctx.BaseURL), "https://") {
		// Non-HTTPS or unknown site URL: the HTTPS_DISABLED check owns it.
		return []Finding{m.skipf("site URL is not HTTPS (see HTTPS_DISABLED) or unknown")}
	}
	if v, ok := cfg.Bool("FORCE_SSL_ADMIN"); ok && v {
		return []Finding{Finding{ID: m.ID, Title: "Admin HTTPS enforced", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "FORCE_SSL_ADMIN is enabled."}}
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		// Informational: modern WordPress already forces HTTPS for admin when
		// the site URL is HTTPS, so this is a policy preference, not a gap.
		Severity: SevInfo, Status: StatusFailed, Confidence: ConfMedium,
		Description:    "The site serves HTTPS but FORCE_SSL_ADMIN is not defined; wp-admin requests over plain HTTP are not redirected by WordPress configuration.",
		Evidence:       map[string]string{"file": "wp-config.php"},
		Recommendation: "Add define( 'FORCE_SSL_ADMIN', true ); to pin admin traffic to HTTPS.",
		References:     m.References,
	}}
}
