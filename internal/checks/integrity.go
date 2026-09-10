package checks

import (
	"crypto/md5" //nolint:gosec // WordPress.org publishes md5 digests; this verifies their manifest, not a hash we chose
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Core file integrity verification against the official WordPress.org
// checksum manifest.
//
// This is the highest-value static check available: it detects altered,
// removed, and injected core files without executing a single line of the
// site's PHP, and it works on a site whose database is unreachable. WP-CLI's
// `wp core verify-checksums` is the behavioural reference; the difference is
// that wpus never bootstraps WordPress to do it.
//
// Hashing every core file is expensive, so the scan runs once per site and is
// shared by the three checks that report different aspects of it.

const (
	// maxIntegrityFiles bounds how many files are hashed per tree.
	maxIntegrityFiles = 20_000
	// integrityDeadline bounds hashing wall time; a slow disk must not turn
	// one check into an unbounded scan.
	integrityDeadline = 45 * time.Second
	// defaultLocale is the checksum locale used when the site declares none.
	defaultLocale = "en_US"
)

// integrityMismatch is one core file whose digest differs from the manifest.
type integrityMismatch struct {
	Path string
	Want string
	Got  string
}

// integrityScan is the once-per-site core integrity result.
type integrityScan struct {
	// Available is true when a manifest was obtained and the trees walked.
	Available bool
	Version   string
	Locale    string
	// Modified lists files whose content differs from the manifest.
	Modified []integrityMismatch
	// Missing lists manifest files absent from disk.
	Missing []string
	// Unexpected lists files present in wp-admin/ or wp-includes/ that the
	// manifest does not contain — the shape of injected code.
	Unexpected []string
	// RootExtra lists unrecognised site-root files. Custom root files are
	// ordinary on real sites (deploy scripts, CLI config, .user.ini), so they
	// are context, not a finding on their own.
	RootExtra []string
	// Note explains why the scan is unavailable, when it is.
	Note string
	// Truncated is true when a bound cut the comparison short.
	Truncated bool
}

// maxIntegrityFindings caps the per-finding evidence lists.
const maxIntegrityFindings = 25

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "CORE_INTEGRITY_MODIFIED",
			Title:       "WordPress core files differ from the official release",
			Category:    CatCore,
			Description: "Compares every core file against the WordPress.org checksum manifest for the installed version. Modified core files are either tampering or a host-side patch; either way they must be explainable. The site's PHP is never executed to perform this check.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/hardening/",
				"https://developer.wordpress.org/cli/commands/core/verify-checksums/",
			},
			Importance: ImpCore,
		},
		Run: runCoreIntegrityModified,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "CORE_FILE_MISSING",
			Title:       "Core files are missing",
			Category:    CatCore,
			Description: "Core files listed in the WordPress.org checksum manifest are absent on disk. Deleted core files break updates and are a common side effect of malware removal that did not restore the originals.",
			References: []string{
				"https://developer.wordpress.org/cli/commands/core/verify-checksums/",
			},
			Importance: ImpCore,
		},
		Run: runCoreFileMissing,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "CORE_UNEXPECTED_FILE",
			Title:       "Unrecognised files inside core directories",
			Category:    CatCore,
			Description: "Files that are not part of the official release found in wp-admin/ or wp-includes/. WordPress never writes custom code there, so such files are either leftovers from a removed plugin or injected code.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/hardening/",
			},
			Importance: ImpCore,
		},
		Run: runCoreUnexpectedFile,
	})
}

// coreIntegrity returns the shared integrity scan for the site.
func (c *Context) coreIntegrity() *integrityScan {
	c.integrityOnce.Do(func() { c.integrity = computeCoreIntegrity(c) })
	return c.integrity
}

func computeCoreIntegrity(ctx *Context) *integrityScan {
	scan := &integrityScan{}
	if ctx.Site == nil {
		scan.Note = "no site loaded"
		return scan
	}
	version := siteVersion(ctx)
	if version == "" {
		scan.Note = "WordPress version could not be determined"
		return scan
	}
	if ctx.Checksums == nil {
		scan.Note = "checksum source unavailable (offline scan)"
		return scan
	}
	locale := siteLocale(ctx)
	manifest, err := ctx.Checksums.CoreChecksums(ctx.Ctx, version, locale)
	if err != nil && locale != defaultLocale {
		// A localized manifest can be unavailable for a version that is
		// otherwise covered; fall back rather than reporting nothing.
		if fallback, ferr := ctx.Checksums.CoreChecksums(ctx.Ctx, version, defaultLocale); ferr == nil {
			manifest, err, locale = fallback, nil, defaultLocale
			ctx.AddGap("core integrity verified against the " + defaultLocale + " manifest; the site's own locale manifest was unavailable")
		}
	}
	if err != nil {
		scan.Note = "no usable checksum manifest for WordPress " + version + " (" + locale + "): " + err.Error()
		ctx.AddGap("core file integrity not verified: " + scan.Note)
		return scan
	}
	scan.Available = true
	scan.Version = version
	scan.Locale = locale

	caps := defaultCaps(ctx.Deep)
	caps.MaxMatches = maxIntegrityFiles
	caps.IncludeHidden = true
	deadline := time.Now().Add(integrityDeadline)

	// 1. Every manifest entry that lives in core directories must exist and
	//    hash to the published digest.
	for rel, want := range manifest {
		if !isCorePath(rel) {
			continue
		}
		if time.Now().After(deadline) {
			scan.Truncated = true
			ctx.AddGap("core integrity comparison hit its time budget; results are partial")
			break
		}
		full := filepath.Join(ctx.Site.Path, filepath.FromSlash(rel))
		st, err := os.Stat(full)
		if err != nil || st.IsDir() {
			scan.Missing = append(scan.Missing, rel)
			continue
		}
		got, err := md5File(full)
		if err != nil {
			ctx.AddGap("core file unreadable during integrity check: " + rel)
			continue
		}
		if !strings.EqualFold(got, want) {
			scan.Modified = append(scan.Modified, integrityMismatch{Path: rel, Want: strings.ToLower(want), Got: got})
		}
	}

	// 2. Anything on disk inside a core directory the manifest does not list
	//    is unexpected by construction.
	for _, dir := range []string{"wp-admin", "wp-includes"} {
		root := filepath.Join(ctx.Site.Path, dir)
		if !fileExists(root) {
			continue
		}
		files, reason := walkAllFiles(root, caps, deadline)
		if reason != "" {
			scan.Truncated = true
			ctx.recordWalk(walkResult{Files: len(files), Truncated: true, TruncationReason: reason})
		} else {
			ctx.recordWalk(walkResult{Files: len(files)})
		}
		for _, rel := range files {
			full := filepath.ToSlash(filepath.Join(dir, rel))
			if _, ok := manifest[full]; ok {
				continue
			}
			if manifestExempt[full] {
				continue
			}
			scan.Unexpected = append(scan.Unexpected, full)
		}
	}

	// 3. Root-level files are reported as context only: real sites carry
	//    deploy scripts and server config next to WordPress.
	entries, err := os.ReadDir(ctx.Site.Path)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if _, ok := manifest[e.Name()]; ok {
				continue
			}
			scan.RootExtra = append(scan.RootExtra, e.Name())
		}
	}

	sort.Slice(scan.Modified, func(i, j int) bool { return scan.Modified[i].Path < scan.Modified[j].Path })
	sort.Strings(scan.Missing)
	sort.Strings(scan.Unexpected)
	sort.Strings(scan.RootExtra)
	if scan.Truncated {
		ctx.AddGap("core directory inventory was truncated by a walk budget")
	}
	return scan
}

// walkAllFiles lists every file below root, honouring the caps. It is
// separate from Context.walk because it must visit hidden entries, which that
// walker deliberately skips when looking for user content. The returned
// reason is "" when the traversal completed, or the budget that stopped it.
func walkAllFiles(root string, caps walkCaps, deadline time.Time) (files []string, reason string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			reason = "time"
			return filepath.SkipAll
		}
		if len(files) >= caps.MaxMatches {
			reason = "max_files"
			return filepath.SkipAll
		}
		if d.IsDir() {
			if d.Type()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	return files, reason
}

// manifestExempt lists files that live in core directories but are
// deliberately excluded from verification: WordPress rewrites them on update,
// so a digest difference there is not a tamper signal.
var manifestExempt = map[string]bool{
	"wp-includes/version.php": true,
}

// isCorePath reports whether a manifest path belongs to the shipped core
// rather than to wp-content (whose files legitimately change on a live site).
func isCorePath(rel string) bool {
	if manifestExempt[rel] {
		return false
	}
	if strings.HasPrefix(rel, "wp-admin/") || strings.HasPrefix(rel, "wp-includes/") {
		return true
	}
	// Root-level core files, but never wp-config.php (absent from the
	// manifest anyway) or anything inside wp-content.
	return !strings.Contains(rel, "/") && rel != "wp-config.php"
}

// siteLocale returns the locale whose manifest matches the installation.
func siteLocale(ctx *Context) string {
	if ctx.Site != nil && ctx.Site.Config != nil {
		for _, key := range []string{"WPLANG", "WP_LANG"} {
			if v, ok := ctx.Site.Config.String(key); ok && v != "" {
				return v
			}
		}
	}
	return defaultLocale
}

// md5File returns the lowercase hex md5 of a file.
func md5File(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path is a core file inside the site under audit
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck
	h := md5.New()  //nolint:gosec // verifying a published md5 manifest
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runCoreIntegrityModified(ctx *Context) []Finding {
	m := Meta{ID: "CORE_INTEGRITY_MODIFIED", Title: "WordPress core files differ from the official release", Category: CatCore,
		References: []string{"https://developer.wordpress.org/cli/commands/core/verify-checksums/"}}
	scan := ctx.coreIntegrity()
	if !scan.Available {
		return []Finding{m.skipf(scan.Note)}
	}
	if len(scan.Modified) == 0 {
		return []Finding{{ID: m.ID, Title: "Core files match the official release", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: fmt.Sprintf("All core files verified against the WordPress.org manifest for %s (%s).", scan.Version, scan.Locale),
			Evidence:    integrityEvidence(scan)}}
	}
	occ := make([]Occurrence, 0, min(len(scan.Modified), maxIntegrityFindings))
	var listed []string
	for i, mm := range scan.Modified {
		if i < maxIntegrityFindings {
			listed = append(listed, mm.Path)
		}
		occ = append(occ, Occurrence{
			ResourceType: "file", Location: mm.Path,
			Detail: "expected md5 " + mm.Want + ", found " + mm.Got,
		})
	}
	ev := integrityEvidence(scan)
	ev["modified_count"] = itoa(len(scan.Modified))
	ev["modified_files"] = strings.Join(listed, ", ")
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevHigh, Status: StatusFailed, Confidence: ConfMedium,
		Description:    fmt.Sprintf("%d core file(s) do not match the official WordPress %s release. This is either injected/altered code or a host-side patch; both require explanation.", len(scan.Modified), scan.Version),
		Evidence:       ev,
		Occurrences:    occ,
		Recommendation: "Compare each listed file with the official release (WordPress.org or WP-CLI) and restore the original unless a host patch is documented. Investigate how the change was made.",
		References:     m.References,
	}}
}

func runCoreFileMissing(ctx *Context) []Finding {
	m := Meta{ID: "CORE_FILE_MISSING", Title: "Core files are missing", Category: CatCore,
		References: []string{"https://developer.wordpress.org/cli/commands/core/verify-checksums/"}}
	scan := ctx.coreIntegrity()
	if !scan.Available {
		return []Finding{m.skipf(scan.Note)}
	}
	if len(scan.Missing) == 0 {
		return []Finding{{ID: m.ID, Title: "No core files missing", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "Every file in the WordPress.org manifest for the installed version is present.",
			Evidence:    integrityEvidence(scan)}}
	}
	var listed []string
	occ := make([]Occurrence, 0, min(len(scan.Missing), maxIntegrityFindings))
	for i, p := range scan.Missing {
		if i < maxIntegrityFindings {
			listed = append(listed, p)
		}
		occ = append(occ, Occurrence{ResourceType: "file", Location: p, Detail: "missing from disk"})
	}
	ev := integrityEvidence(scan)
	ev["missing_count"] = itoa(len(scan.Missing))
	ev["missing_files"] = strings.Join(listed, ", ")
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevMedium, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d core file(s) listed in the WordPress %s manifest are missing from disk. Updates and repairs may fail, and missing files are a common aftermath of incomplete malware cleanup.", len(scan.Missing), scan.Version),
		Evidence:       ev,
		Occurrences:    occ,
		Recommendation: "Reinstall the WordPress core files for this version (WP-CLI `wp core download --force` or a fresh download), keeping wp-config.php and wp-content.",
		References:     m.References,
	}}
}

func runCoreUnexpectedFile(ctx *Context) []Finding {
	m := Meta{ID: "CORE_UNEXPECTED_FILE", Title: "Unrecognised files inside core directories", Category: CatCore,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/hardening/"}}
	scan := ctx.coreIntegrity()
	if !scan.Available {
		return []Finding{m.skipf(scan.Note)}
	}
	ev := integrityEvidence(scan)
	if len(scan.RootExtra) > 0 {
		ev["site_root_files"] = strings.Join(capList(scan.RootExtra, maxIntegrityFindings), ", ")
		ev["site_root_note"] = "root-level files are often intentional (deploy scripts, server config); listed for context only"
	}
	if len(scan.Unexpected) == 0 {
		return []Finding{{ID: m.ID, Title: "No unrecognised files in core directories", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "wp-admin/ and wp-includes/ contain only files from the official release.",
			Evidence:    ev}}
	}
	occ := make([]Occurrence, 0, min(len(scan.Unexpected), maxIntegrityFindings))
	for _, p := range scan.Unexpected {
		occ = append(occ, Occurrence{ResourceType: "file", Location: p, Detail: "not part of the official release"})
	}
	ev["unexpected_count"] = itoa(len(scan.Unexpected))
	ev["unexpected_files"] = strings.Join(capList(scan.Unexpected, maxIntegrityFindings), ", ")
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevMedium, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d file(s) that are not part of the official WordPress release were found in wp-admin/ or wp-includes/. Nothing in WordPress writes custom code there.", len(scan.Unexpected)),
		Evidence:       ev,
		Occurrences:    occ,
		Recommendation: "Inspect each file's contents. Remove anything you cannot attribute to a documented host patch, then reinstall core to restore the original tree.",
		References:     m.References,
	}}
}

// integrityEvidence is the evidence shared by the three core integrity
// checks, so each finding states the manifest it was verified against.
func integrityEvidence(scan *integrityScan) map[string]string {
	ev := map[string]string{
		"verified_against": "WordPress.org core checksum manifest",
		"core_version":     scan.Version,
		"locale":           scan.Locale,
	}
	if scan.Truncated {
		ev["note"] = "integrity comparison stopped early (budget); results are partial"
	}
	return ev
}

func capList(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}
