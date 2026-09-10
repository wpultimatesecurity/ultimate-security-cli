package checks

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Must-use plugins, drop-ins, and moved directories are the blind spots of a
// scanner that only understands the default wp-content layout. MU plugins load
// without ever appearing in the plugin list, and drop-ins run before plugins —
// both are prime persistence locations, and both were previously invisible.

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "MU_PLUGIN_PRESENT",
			Title:       "Must-use plugins are installed",
			Category:    CatPlugins,
			Description: "Must-use plugins in wp-content/mu-plugins are auto-loaded on every request and never appear in the admin plugin list, so they are easy to overlook and a favoured persistence location. Presence is not a problem by itself; unattributed files are.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/plugins/mu-plugins/",
			},
			Importance: ImpCore,
		},
		Run: runMUPlugins,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "DROPIN_PRESENT",
			Title:       "WordPress drop-in files are installed",
			Category:    CatHardening,
			Description: "Drop-ins (object-cache.php, advanced-cache.php, db.php, sunrise.php, ...) execute at privileged points in the WordPress bootstrap, sometimes before the database is available. They must be attributable to a known plugin or host.",
			References: []string{
				"https://developer.wordpress.org/reference/functions/get_dropins/",
			},
			Importance: ImpCore,
		},
		Run: runDropins,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "CUSTOM_CONTENT_PATH",
			Title:       "WordPress directories are relocated",
			Category:    CatFS,
			Description: "The site moves wp-content, plugins, MU plugins, or uploads away from the WordPress defaults. This is legitimate hardening; the check reports the resolved layout so a scan can be trusted to have looked in the right places, and fails when a configured path could not be resolved statically (that would be a coverage gap).",
			References: []string{
				"https://developer.wordpress.org/plugins/plugin-basics/determining-plugin-and-content-directories/",
			},
			Importance: ImpCore,
		},
		Run: runCustomContentPath,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "WP_CONFIG_PARENT_LOCATION",
			Title:       "wp-config.php sits above the web root",
			Category:    CatConfig,
			Description: "WordPress supports keeping wp-config.php one directory above the installation, which keeps credentials out of the served tree. Reported as information so the layout is visible in the report.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/wordpress/wp-config/",
			},
			Importance: ImpContext,
		},
		Run: runWpConfigLocation,
	})
}

func runMUPlugins(ctx *Context) []Finding {
	m := Meta{ID: "MU_PLUGIN_PRESENT", Title: "Must-use plugins are installed", Category: CatPlugins,
		References: []string{"https://developer.wordpress.org/advanced-administration/plugins/mu-plugins/"}}
	site := ctx.Site
	if site == nil {
		return []Finding{m.skipf("no site loaded")}
	}
	if !fileExists(site.MuPluginsPath) {
		return []Finding{{ID: m.ID, Title: "No MU-plugin directory", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "The site has no must-use plugin directory, so nothing is auto-loaded outside the plugin list.",
			Evidence:    map[string]string{"path": site.MuPluginsPath}}}
	}
	if len(site.MuPlugins) == 0 {
		return []Finding{{ID: m.ID, Title: "No MU plugins", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "The MU-plugin directory exists but contains no top-level plugin files.",
			Evidence:    map[string]string{"path": site.MuPluginsPath}}}
	}
	var names []string
	occ := make([]Occurrence, 0, len(site.MuPlugins))
	for _, p := range site.MuPlugins {
		label := p.Slug
		if p.Version != "" {
			label += " " + p.Version
		}
		names = append(names, label)
		occ = append(occ, Occurrence{
			ResourceType: "mu-plugin", Slug: p.Slug, Name: p.Name, Version: p.Version,
			Location: "mu-plugins/" + p.Slug + ".php",
		})
	}
	sort.Strings(names)
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevInfo, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d must-use plugin(s) load on every request without appearing in the admin plugin list. Confirm each one is intentional: they are a common persistence location after a compromise.", len(site.MuPlugins)),
		Evidence:       map[string]string{"path": site.MuPluginsPath, "mu_plugins": strings.Join(names, ", ")},
		Occurrences:    occ,
		Recommendation: "Review each MU plugin; remove anything you cannot attribute to a known host, plugin, or your own deployment.",
		References:     m.References,
	}}
}

func runDropins(ctx *Context) []Finding {
	m := Meta{ID: "DROPIN_PRESENT", Title: "WordPress drop-in files are installed", Category: CatHardening,
		References: []string{"https://developer.wordpress.org/reference/functions/get_dropins/"}}
	site := ctx.Site
	if site == nil {
		return []Finding{m.skipf("no site loaded")}
	}
	if len(site.Dropins) == 0 {
		return []Finding{{ID: m.ID, Title: "No drop-in files", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "No WordPress drop-in files were found in the content directory.",
			Evidence:    map[string]string{"content_dir": site.ContentPath}}}
	}
	var names []string
	recent := []string{}
	occ := make([]Occurrence, 0, len(site.Dropins))
	for _, d := range site.Dropins {
		names = append(names, d.File)
		detail := d.Purpose
		if st, err := os.Stat(d.Path); err == nil && time.Since(st.ModTime()) < 14*24*time.Hour {
			recent = append(recent, d.File)
			detail += "; modified in the last 14 days"
		}
		occ = append(occ, Occurrence{ResourceType: "dropin", Slug: d.File, Location: "content/" + d.File, Detail: detail})
	}
	sort.Strings(names)
	ev := map[string]string{"dropins": strings.Join(names, ", ")}
	if len(recent) > 0 {
		ev["recently_modified"] = strings.Join(recent, ", ")
	}
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevInfo, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d drop-in file(s) run at fixed, privileged points in the WordPress bootstrap. Verify each one belongs to a known caching, database, or host integration.", len(site.Dropins)),
		Evidence:       ev,
		Occurrences:    occ,
		Recommendation: "Confirm every drop-in is provided by an installed plugin or your host. Drop-ins with no owner should be inspected and removed.",
		References:     m.References,
	}}
}

func runCustomContentPath(ctx *Context) []Finding {
	m := Meta{ID: "CUSTOM_CONTENT_PATH", Title: "WordPress directories are relocated", Category: CatFS,
		References: []string{"https://developer.wordpress.org/plugins/plugin-basics/determining-plugin-and-content-directories/"}}
	site := ctx.Site
	if site == nil {
		return []Finding{m.skipf("no site loaded")}
	}
	layout := site.Layout
	ev := map[string]string{
		"content_dir":    layout.ContentPath,
		"plugins_dir":    layout.PluginsPath,
		"mu_plugins":     layout.MuPluginsPath,
		"uploads_dir":    layout.UploadsPath,
		"content_source": layout.ContentSource,
		"plugins_source": layout.PluginsSource,
		"uploads_source": layout.UploadsSource,
	}
	if len(layout.Unresolved) > 0 {
		ctx.AddGap("configured path constant(s) could not be resolved statically: " + strings.Join(layout.Unresolved, ", "))
		ev["unresolved"] = strings.Join(layout.Unresolved, ", ")
		return []Finding{{
			ID: m.ID, Title: "Configured directory path could not be resolved", Category: m.Category,
			Severity: SevInfo, Status: StatusUnknown, Confidence: ConfLow,
			Description:    fmt.Sprintf("wp-config.php points at custom directories through expressions this static scan cannot evaluate (%s). The default locations were inventoried instead, so parts of the installation may not have been examined.", strings.Join(layout.Unresolved, ", ")),
			Evidence:       ev,
			Recommendation: "Run the scan in an environment where those expressions are plain paths, or extend the scan's static path resolution.",
			References:     m.References,
		}}
	}
	if !layout.Custom() {
		return []Finding{{ID: m.ID, Title: "Standard WordPress layout", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "wp-content, plugins, MU plugins and uploads all use the WordPress default locations.",
			Evidence:    ev}}
	}
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
		Description:    "The installation relocates one or more WordPress directories. The report uses the resolved locations, so plugin, theme, uploads and MU-plugin coverage still applies.",
		Evidence:       ev,
		Recommendation: "No action required. Relocating directories is a legitimate hardening measure.",
		References:     m.References,
	}}
}

func runWpConfigLocation(ctx *Context) []Finding {
	m := Meta{ID: "WP_CONFIG_PARENT_LOCATION", Title: "wp-config.php sits above the web root", Category: CatConfig,
		References: []string{"https://developer.wordpress.org/advanced-administration/wordpress/wp-config/"}}
	site := ctx.Site
	if site == nil || site.Config == nil || !site.Config.Exists {
		return []Finding{m.skipf("wp-config.php not found in the installation root or one level above")}
	}
	if site.Layout.ConfigParent {
		return []Finding{{ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "wp-config.php was found one directory above the installation, outside the served tree.",
			Evidence:    map[string]string{"location": "parent of the WordPress root", "parsed": "true"}}}
	}
	return []Finding{{ID: m.ID, Title: "wp-config.php is in the installation root", Category: m.Category,
		Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
		Description: "wp-config.php is inside the web root. This is the WordPress default; a hardened install may move it one level up.",
		Evidence:    map[string]string{"location": "WordPress root", "parsed": "true"}}}
}
