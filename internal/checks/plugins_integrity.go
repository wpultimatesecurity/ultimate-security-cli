package checks

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Plugin file integrity against the official WordPress.org release archives.
//
// Custom and premium plugins have no public checksums, so they are reported as
// unverifiable — never as modified. That distinction matters: "we could not
// check this" and "this was changed" are different answers, and conflating
// them trains operators to ignore the scanner.
//
// Each plugin verification downloads one release archive, so the capability is
// opt-in (--verify-plugin-checksums) and the scan says so when it is off.

const (
	// maxPluginVerifications bounds how many plugins are verified per site.
	maxPluginVerifications = 40
	// maxPluginFiles bounds the files hashed inside one plugin.
	maxPluginFiles = 20_000
)

// pluginMismatch is one plugin file whose digest differs from the release.
type pluginMismatch struct {
	Slug string
	Path string
	Want string
	Got  string
}

// pluginIntegrityScan is the once-per-site plugin integrity result.
type pluginIntegrityScan struct {
	// Enabled is false when plugin checksum verification was not requested.
	Enabled bool
	// Note explains why nothing was verified.
	Note string
	// Verified lists plugin slugs whose files matched their release.
	Verified []string
	// Unverifiable lists plugins with no WordPress.org release (custom or
	// premium) — reported as unknown, never as a failure.
	Unverifiable []string
	// Unversioned lists plugins whose version could not be read.
	Unversioned []string
	Modified    []pluginMismatch
	Missing     []pluginMismatch
	Extra       []pluginMismatch
	Truncated   bool
}

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "PLUGIN_INTEGRITY_MODIFIED",
			Title:       "Plugin files differ from the WordPress.org release",
			Category:    CatPlugins,
			Description: "Compares plugin files against the official release archive for the installed version (requires --verify-plugin-checksums). Requires no WordPress bootstrap. Plugins without a WordPress.org release are reported as unverifiable, never as modified.",
			References: []string{
				"https://developer.wordpress.org/cli/commands/plugin/verify-checksums/",
			},
			Importance: ImpCore,
		},
		Run: runPluginIntegrityModified,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "PLUGIN_INTEGRITY_MISSING_FILE",
			Title:       "Plugin files missing from the installed copy",
			Category:    CatPlugins,
			Description: "Files shipped in the official plugin release are absent on disk. Missing code breaks the plugin and is a frequent aftermath of partial malware cleanup.",
			References: []string{
				"https://developer.wordpress.org/cli/commands/plugin/verify-checksums/",
			},
			Importance: ImpStandard,
		},
		Run: runPluginIntegrityMissing,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "PLUGIN_INTEGRITY_EXTRA_FILE",
			Title:       "Plugin contains files that are not in the official release",
			Category:    CatPlugins,
			Description: "Extra files inside a plugin directory are not automatically malicious — caches, compiled translations, and editor leftovers are common — but they are also where injected backdoors live. Version control metadata is excluded.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/hardening/",
			},
			Importance: ImpStandard,
		},
		Run: runPluginIntegrityExtra,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "PLUGIN_CHECKSUM_UNAVAILABLE",
			Title:       "Plugins that cannot be integrity-checked",
			Category:    CatPlugins,
			Description: "Custom and premium plugins have no public release archive, so no checksum comparison is possible. This is a coverage statement, not a security failure: it records that part of the plugin tree was not verifiable.",
			References: []string{
				"https://developer.wordpress.org/plugins/wordpress-org/",
			},
			Importance: ImpContext,
		},
		Run: runPluginChecksumUnavailable,
	})
}

// pluginIntegrity returns the shared plugin integrity scan for the site.
func (c *Context) pluginIntegrity() *pluginIntegrityScan {
	c.pluginOnce.Do(func() { c.pluginScan = computePluginIntegrity(c) })
	return c.pluginScan
}

func computePluginIntegrity(ctx *Context) *pluginIntegrityScan {
	scan := &pluginIntegrityScan{}
	if ctx.Site == nil {
		scan.Note = "no site loaded"
		return scan
	}
	if ctx.Checksums == nil {
		scan.Note = "checksum source unavailable (offline scan)"
		return scan
	}
	if !ctx.Checksums.PluginsEnabled() {
		scan.Note = "plugin checksum verification not requested (--verify-plugin-checksums)"
		ctx.AddGap("plugin file integrity not verified: rerun with --verify-plugin-checksums")
		return scan
	}
	plugins := ctx.Site.Plugins
	if len(plugins) == 0 {
		scan.Note = "no plugins installed"
		return scan
	}
	scan.Enabled = true

	checked := 0
	for _, p := range plugins {
		if checked >= maxPluginVerifications {
			scan.Truncated = true
			ctx.AddGap(fmt.Sprintf("plugin integrity verification stopped at %d plugins (budget)", maxPluginVerifications))
			break
		}
		if p.Version == "" {
			scan.Unversioned = append(scan.Unversioned, p.Slug)
			continue
		}
		dir := filepath.Join(ctx.Site.PluginsPath, p.Slug)
		if !fileExists(dir) {
			scan.Unversioned = append(scan.Unversioned, p.Slug)
			continue
		}
		manifest, err := ctx.Checksums.PluginChecksums(ctx.Ctx, p.Slug, p.Version)
		if err != nil || len(manifest) == 0 {
			scan.Unverifiable = append(scan.Unverifiable, p.Slug)
			continue
		}
		checked++
		comparePluginTree(ctx, scan, p.Slug, dir, manifest)
	}

	sort.Strings(scan.Verified)
	sort.Strings(scan.Unverifiable)
	sort.Strings(scan.Unversioned)
	sortMismatches(scan.Modified)
	sortMismatches(scan.Missing)
	sortMismatches(scan.Extra)
	return scan
}

// comparePluginTree hashes every file in one plugin directory and compares it
// with the release manifest.
func comparePluginTree(ctx *Context, scan *pluginIntegrityScan, slug, dir string, manifest map[string]string) {
	caps := defaultCaps(ctx.Deep)
	caps.MaxMatches = maxPluginFiles
	files, reason := walkAllFiles(dir, caps, time.Now().Add(integrityDeadline))
	if reason != "" {
		scan.Truncated = true
	}
	clean := true
	seen := make(map[string]bool, len(files))
	for _, rel := range files {
		seen[rel] = true
		want, ok := manifest[rel]
		if !ok {
			if isIgnorableExtra(rel) {
				continue
			}
			scan.Extra = append(scan.Extra, pluginMismatch{Slug: slug, Path: rel})
			clean = false
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(rel))
		got, err := md5File(full)
		if err != nil {
			ctx.AddGap("plugin file unreadable during integrity check: " + slug + "/" + rel)
			continue
		}
		if !strings.EqualFold(got, want) {
			scan.Modified = append(scan.Modified, pluginMismatch{Slug: slug, Path: rel, Want: strings.ToLower(want), Got: got})
			clean = false
		}
	}
	for rel, want := range manifest {
		if seen[rel] {
			continue
		}
		scan.Missing = append(scan.Missing, pluginMismatch{Slug: slug, Path: rel, Want: strings.ToLower(want)})
		clean = false
	}
	if clean {
		scan.Verified = append(scan.Verified, slug)
	}
}

// isIgnorableExtra reports whether an extra file is explainable by normal
// operation, so it never inflates the finding.
func isIgnorableExtra(rel string) bool {
	base := filepath.Base(rel)
	if base == ".DS_Store" {
		return true
	}
	for _, prefix := range []string{".git/", ".svn/", ".hg/", "node_modules/", ".github/"} {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
}

func sortMismatches(in []pluginMismatch) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Slug != in[j].Slug {
			return in[i].Slug < in[j].Slug
		}
		return in[i].Path < in[j].Path
	})
}

func runPluginIntegrityModified(ctx *Context) []Finding {
	m := Meta{ID: "PLUGIN_INTEGRITY_MODIFIED", Title: "Plugin files differ from the WordPress.org release", Category: CatPlugins,
		References: []string{"https://developer.wordpress.org/cli/commands/plugin/verify-checksums/"}}
	scan := ctx.pluginIntegrity()
	if !scan.Enabled {
		return []Finding{m.skipf(scan.Note)}
	}
	if len(scan.Modified) == 0 {
		return []Finding{{ID: m.ID, Title: "Plugin files match their releases", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: fmt.Sprintf("%d WordPress.org plugin(s) verified against their official release archives.", len(scan.Verified)),
			Evidence:    pluginIntegrityEvidence(scan)}}
	}
	occ := make([]Occurrence, 0, min(len(scan.Modified), maxIntegrityFindings))
	var listed []string
	for i, mm := range scan.Modified {
		if i < maxIntegrityFindings {
			listed = append(listed, mm.Slug+"/"+mm.Path)
		}
		occ = append(occ, Occurrence{
			ResourceType: "plugin", Slug: mm.Slug, Location: mm.Path,
			Detail: "expected md5 " + mm.Want + ", found " + mm.Got,
		})
	}
	ev := pluginIntegrityEvidence(scan)
	ev["modified_count"] = itoa(len(scan.Modified))
	ev["modified_files"] = strings.Join(listed, ", ")
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevHigh, Status: StatusFailed, Confidence: ConfMedium,
		Description:    fmt.Sprintf("%d file(s) across the installed plugins do not match their official WordPress.org release.", len(scan.Modified)),
		Evidence:       ev,
		Occurrences:    occ,
		Recommendation: "Reinstall each affected plugin from WordPress.org for the exact installed version, and investigate the change (host-side patching is uncommon for plugins).",
		References:     m.References,
	}}
}

func runPluginIntegrityMissing(ctx *Context) []Finding {
	m := Meta{ID: "PLUGIN_INTEGRITY_MISSING_FILE", Title: "Plugin files missing from the installed copy", Category: CatPlugins,
		References: []string{"https://developer.wordpress.org/cli/commands/plugin/verify-checksums/"}}
	scan := ctx.pluginIntegrity()
	if !scan.Enabled {
		return []Finding{m.skipf(scan.Note)}
	}
	if len(scan.Missing) == 0 {
		return []Finding{{ID: m.ID, Title: "No plugin files missing", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "Every file in the verified plugins' releases is present.",
			Evidence:    pluginIntegrityEvidence(scan)}}
	}
	occ := make([]Occurrence, 0, min(len(scan.Missing), maxIntegrityFindings))
	var listed []string
	for i, mm := range scan.Missing {
		if i < maxIntegrityFindings {
			listed = append(listed, mm.Slug+"/"+mm.Path)
		}
		occ = append(occ, Occurrence{ResourceType: "plugin", Slug: mm.Slug, Location: mm.Path, Detail: "missing from disk"})
	}
	ev := pluginIntegrityEvidence(scan)
	ev["missing_count"] = itoa(len(scan.Missing))
	ev["missing_files"] = strings.Join(listed, ", ")
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevMedium, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d file(s) shipped in the official plugin releases are missing on disk.", len(scan.Missing)),
		Evidence:       ev,
		Occurrences:    occ,
		Recommendation: "Reinstall the affected plugins from WordPress.org; missing files usually mean an incomplete update or a partial cleanup.",
		References:     m.References,
	}}
}

func runPluginIntegrityExtra(ctx *Context) []Finding {
	m := Meta{ID: "PLUGIN_INTEGRITY_EXTRA_FILE", Title: "Plugin contains files that are not in the official release", Category: CatPlugins,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/hardening/"}}
	scan := ctx.pluginIntegrity()
	if !scan.Enabled {
		return []Finding{m.skipf(scan.Note)}
	}
	if len(scan.Extra) == 0 {
		return []Finding{{ID: m.ID, Title: "No unexpected plugin files", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "Verified plugins contain no files beyond their official releases.",
			Evidence:    pluginIntegrityEvidence(scan)}}
	}
	occ := make([]Occurrence, 0, min(len(scan.Extra), maxIntegrityFindings))
	var listed []string
	phpExtra := 0
	for i, mm := range scan.Extra {
		if i < maxIntegrityFindings {
			listed = append(listed, mm.Slug+"/"+mm.Path)
		}
		if hasExtension(mm.Path, ".php", ".phtml", ".phar") {
			phpExtra++
		}
		occ = append(occ, Occurrence{ResourceType: "plugin", Slug: mm.Slug, Location: mm.Path, Detail: "not in the official release"})
	}
	sev := SevLow
	desc := fmt.Sprintf("%d file(s) present inside verified plugins are not part of their official releases.", len(scan.Extra))
	if phpExtra > 0 {
		sev = SevMedium
		desc += fmt.Sprintf(" %d of them are PHP files, which is where injected code hides.", phpExtra)
	}
	ev := pluginIntegrityEvidence(scan)
	ev["extra_count"] = itoa(len(scan.Extra))
	ev["extra_files"] = strings.Join(listed, ", ")
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: sev, Status: StatusFailed, Confidence: ConfMedium,
		Description:    desc,
		Evidence:       ev,
		Occurrences:    occ,
		Recommendation: "Review each extra file. Runtime caches and compiled translations are normal; unrecognised PHP is not.",
		References:     m.References,
	}}
}

func runPluginChecksumUnavailable(ctx *Context) []Finding {
	m := Meta{ID: "PLUGIN_CHECKSUM_UNAVAILABLE", Title: "Plugins that cannot be integrity-checked", Category: CatPlugins,
		References: []string{"https://developer.wordpress.org/plugins/wordpress-org/"}}
	scan := ctx.pluginIntegrity()
	if !scan.Enabled {
		return []Finding{m.skipf(scan.Note)}
	}
	var unverifiable []string
	unverifiable = append(unverifiable, scan.Unverifiable...)
	for _, slug := range scan.Unversioned {
		unverifiable = append(unverifiable, slug+" (version unknown)")
	}
	sort.Strings(unverifiable)
	if len(unverifiable) == 0 {
		return []Finding{{ID: m.ID, Title: "All plugins are integrity-checked", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "Every installed plugin has a WordPress.org release that could be compared.",
			Evidence:    pluginIntegrityEvidence(scan)}}
	}
	ev := pluginIntegrityEvidence(scan)
	ev["unverifiable"] = strings.Join(capList(unverifiable, maxIntegrityFindings), ", ")
	ev["unverifiable_count"] = itoa(len(unverifiable))
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevInfo, Status: StatusUnknown, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d plugin(s) have no WordPress.org release to compare against (custom, premium, or version not readable). Their files were not verified — this is a coverage gap, not a finding.", len(unverifiable)),
		Evidence:       ev,
		Recommendation: "Vendor-provided checksums or a file-integrity baseline are the only ways to verify these plugins.",
		References:     m.References,
	}}
}

// pluginIntegrityEvidence is the evidence shared by the plugin integrity
// checks so each states what was actually verified.
func pluginIntegrityEvidence(scan *pluginIntegrityScan) map[string]string {
	ev := map[string]string{
		"verified_against": "WordPress.org plugin release archives",
		"verified_plugins": itoa(len(scan.Verified)),
	}
	if len(scan.Verified) > 0 {
		ev["clean"] = strings.Join(capList(scan.Verified, maxIntegrityFindings), ", ")
	}
	if scan.Truncated {
		ev["note"] = "verification stopped early (budget); results are partial"
	}
	return ev
}
