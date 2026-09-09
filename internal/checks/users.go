package checks

import (
	"fmt"
	"strings"
	"time"
)

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "ADMIN_USERNAME",
			Title:       "Administrator account named 'admin'",
			Category:    CatAuth,
			Description: "An administrator with the username 'admin' is the first credential every brute-force and credential-stuffing campaign tries. Rename it or use a distinct login name.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/",
			},
		},
		Run: runAdminUsername,
	})
}

func runAdminUsername(ctx *Context) []Finding {
	m := Meta{ID: "ADMIN_USERNAME", Title: "Administrator account named 'admin'", Category: CatAuth,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/"}}
	if ctx.WP == nil || ctx.WP.Admins == nil {
		return []Finding{m.skipf("WP-CLI unavailable (user data requires it)")}
	}
	var hits []string
	for _, u := range ctx.WP.Admins {
		if strings.EqualFold(u.Login, "admin") {
			hits = append(hits, fmt.Sprintf("user #%d", u.ID))
		}
	}
	if len(hits) == 0 {
		return []Finding{Finding{ID: m.ID, Title: "No default admin username", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: fmt.Sprintf("None of the %d administrator account(s) use the username 'admin'.", len(ctx.WP.Admins))}}
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevMedium, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d administrator account uses the username 'admin' (%s), the most targeted username in automated attacks.", len(hits), strings.Join(hits, ", ")),
		Recommendation: "Create a new administrator with a unique username, confirm it works, then delete the 'admin' account (attribute existing posts to the new user).",
		References:     m.References,
	}}
}

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "DEFAULT_DATABASE_PREFIX",
			Title:       "Default database table prefix in use",
			Category:    CatDatabase,
			Description: "The default wp_ table prefix makes SQL-injection payloads marginally easier and marks the install as default-configured. Low impact; changing it on an existing site is invasive, so this matters most at setup time.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/before-install/creation/",
			},
		},
		Run: runDBPrefix,
	})
}

func runDBPrefix(ctx *Context) []Finding {
	m := Meta{ID: "DEFAULT_DATABASE_PREFIX", Title: "Default database table prefix in use", Category: CatDatabase,
		References: []string{"https://developer.wordpress.org/advanced-administration/before-install/creation/"}}
	prefix := ctx.Site.Prefix
	if ctx.WP != nil && ctx.WP.SiteURL != "" {
		// WP-CLI confirmed the site is live; config prefix is authoritative.
		_ = ctx.WP.SiteURL
	}
	if prefix == "" {
		return []Finding{m.skipf("table prefix could not be determined")}
	}
	if prefix == "wp_" {
		return []Finding{Finding{
			ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
			Description:    "The database uses the default 'wp_' table prefix.",
			Evidence:       map[string]string{"prefix": prefix},
			Recommendation: "Consider a unique prefix for new installations. Existing sites should only change it with a careful migration (or leave as is — this is low-impact hardening).",
			References:     m.References,
		}}
	}
	return []Finding{Finding{ID: m.ID, Title: "Custom table prefix", Category: m.Category,
		Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
		Description: "A non-default table prefix is configured.",
		Evidence:    map[string]string{"prefix": prefix}}}
}

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "PHP_OUTDATED",
			Title:       "PHP runtime is end-of-life or near end-of-life",
			Category:    CatPHP,
			Description: "End-of-life PHP versions receive no security fixes. Version detection uses the PHP runtime that WP-CLI runs on; when that cannot be determined the check is skipped rather than guessed.",
			References: []string{
				"https://www.php.net/supported-versions.php",
				"https://developer.wordpress.org/advanced-administration/server/php/",
			},
		},
		Run: runPHPOutdated,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "PHP_DISPLAY_ERRORS",
			Title:       "PHP display_errors is enabled",
			Category:    CatPHP,
			Description: "display_errors prints PHP errors to responses, leaking paths and internals. Detected via the WP-CLI runtime ini, so web-SAPI overrides may differ (confidence is low by design).",
			References: []string{
				"https://www.php.net/manual/en/errorfunc.configuration.php",
			},
		},
		Run: runPHPDisplayErrors,
	})
}

// phpLifecycle holds the official php.net release lifecycle dates.
type phpLifecycle struct {
	activeUntil time.Time // bug fixes end
	eol         time.Time // security support ends
}

// phpLifecycles is derived from php.net/supported-versions.php.
// Versions not present are treated as supported (no false positives for
// future releases).
var phpLifecycles = map[string]phpLifecycle{
	"5.6": {eol: time.Date(2018, 12, 31, 0, 0, 0, 0, time.UTC)},
	"7.0": {eol: time.Date(2019, 12, 3, 0, 0, 0, 0, time.UTC)},
	"7.1": {eol: time.Date(2019, 12, 31, 0, 0, 0, 0, time.UTC)},
	"7.2": {eol: time.Date(2020, 11, 30, 0, 0, 0, 0, time.UTC)},
	"7.3": {eol: time.Date(2021, 12, 6, 0, 0, 0, 0, time.UTC)},
	"7.4": {eol: time.Date(2022, 11, 28, 0, 0, 0, 0, time.UTC)},
	"8.0": {eol: time.Date(2023, 11, 26, 0, 0, 0, 0, time.UTC)},
	"8.1": {eol: time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)},
	"8.2": {activeUntil: time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC), eol: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)},
	"8.3": {activeUntil: time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC), eol: time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)},
	"8.4": {activeUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), eol: time.Date(2028, 12, 31, 0, 0, 0, 0, time.UTC)},
	"8.5": {activeUntil: time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC), eol: time.Date(2029, 12, 31, 0, 0, 0, 0, time.UTC)},
}

func runPHPOutdated(ctx *Context) []Finding {
	m := Meta{ID: "PHP_OUTDATED", Title: "PHP runtime is end-of-life or near end-of-life", Category: CatPHP,
		References: []string{"https://www.php.net/supported-versions.php"}}
	if ctx.WP == nil || ctx.WP.PHP == "" {
		return []Finding{m.skipf("PHP runtime version not determinable (WP-CLI unavailable)")}
	}
	version := ctx.WP.PHP
	key := version
	if i := strings.IndexAny(version, "-+"); i > 0 {
		key = version[:i]
	}
	parts := strings.SplitN(key, ".", 3)
	if len(parts) < 2 {
		return []Finding{Finding{ID: m.ID, Title: "PHP version not parseable", Category: m.Category,
			Severity: SevInfo, Status: StatusUnknown, Confidence: ConfLow,
			Description: "The reported PHP version could not be parsed: " + version,
			Evidence:    map[string]string{"version": version, "source": "wp-cli runtime"}}}
	}
	line := parts[0] + "." + parts[1]
	lc, known := phpLifecycles[line]
	ev := map[string]string{"version": version, "source": "wp-cli runtime (may differ from the web SAPI)"}
	switch {
	case !known:
		return []Finding{Finding{ID: m.ID, Title: "PHP version actively supported", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfMedium,
			Description: "PHP " + line + " has no end-of-life date recorded; treated as supported.",
			Evidence:    ev}}
	case lc.eol.Before(time.Now()):
		return []Finding{Finding{
			ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevHigh, Status: StatusFailed, Confidence: ConfMedium,
			Description:    fmt.Sprintf("PHP %s reached end of life on %s and no longer receives security fixes.", line, lc.eol.Format("2006-01-02")),
			Evidence:       ev,
			Recommendation: "Upgrade the site's PHP runtime to a supported major.minor version (test in staging first).",
			References:     m.References,
		}}
	case lc.activeUntil.Before(time.Now()):
		return []Finding{Finding{
			ID: m.ID, Title: "PHP security-only support ends " + lc.eol.Format("January 2006"), Category: m.Category,
			Severity: SevLow, Status: StatusFailed, Confidence: ConfMedium,
			Description:    fmt.Sprintf("PHP %s is in security-only support until %s. Plan the upgrade now.", line, lc.eol.Format("2006-01-02")),
			Evidence:       ev,
			Recommendation: "Schedule an upgrade to the newest supported PHP line.",
			References:     m.References,
		}}
	default:
		return []Finding{Finding{ID: m.ID, Title: "PHP version actively supported", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfMedium,
			Description: "PHP " + line + " receives active security support.",
			Evidence:    ev}}
	}
}

func runPHPDisplayErrors(ctx *Context) []Finding {
	m := Meta{ID: "PHP_DISPLAY_ERRORS", Title: "PHP display_errors is enabled", Category: CatPHP,
		References: []string{"https://www.php.net/manual/en/errorfunc.configuration.php"}}
	if ctx.WP == nil {
		return []Finding{m.skipf("WP-CLI unavailable (ini inspection requires it)")}
	}
	v := strings.TrimSpace(ctx.WP.DispErrs)
	if v == "" {
		return []Finding{Finding{ID: m.ID, Title: "display_errors disabled", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfLow,
			Description: "display_errors is empty (disabled) in the WP-CLI PHP runtime."}}
	}
	if v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "off") {
		return []Finding{Finding{ID: m.ID, Title: "display_errors disabled", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfLow,
			Description: "display_errors is disabled in the WP-CLI PHP runtime."}}
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevLow, Status: StatusFailed, Confidence: ConfLow,
		Description:    "display_errors is enabled (" + v + ") in the inspected PHP runtime. The web SAPI may override this, so treat as a lead, not a certainty.",
		Evidence:       map[string]string{"value": v, "source": "wp-cli runtime ini_get"},
		Recommendation: "Set display_errors=Off in php.ini for production and log errors to a file instead.",
		References:     m.References,
	}}
}
