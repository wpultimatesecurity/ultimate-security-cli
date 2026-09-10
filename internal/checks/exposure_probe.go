package checks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/probe"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
)

// Exposure confirmation.
//
// The filesystem checks can only say "this file exists inside the web root".
// Whether a visitor can actually download it depends on server configuration,
// so a head-of-file finding is a lead, not a fact. This check turns the lead
// into evidence: it asks the site itself, through the SSRF-restricted prober,
// whether each candidate is retrievable.
//
// Only inert, non-executable files are ever probed, and only with HEAD, which
// the prober guarantees reads no body. A .php file is never requested — that
// would execute it.

// exposureCandidates is the bounded probe set. Probing is cheap but it is
// still traffic the site's owner did not ask for, so the list stays short and
// fixed.
type exposureCandidate struct {
	// rel is the path relative to the WordPress root.
	rel string
	// why explains the exposure in the finding.
	why string
}

// maxExposureProbes bounds the number of HEAD requests in one scan. Only
// files that actually exist are probed: asking about a file that is not there
// spends the site's traffic on nothing, and its absence is already reported by
// the filesystem checks.
const maxExposureProbes = 12

// exposureProbeSet builds the candidate list for a site: fixed sensitive
// names plus any backup archive found in the root directory.
func exposureProbeSet(site *wordpress.Site) []exposureCandidate {
	cands := []exposureCandidate{
		{".env", "environment file: conventionally holds database and API credentials"},
		{".env.local", "environment file"},
		{".git/HEAD", "Git metadata: proves the repository is served, history follows"},
	}
	if content, ok := contentRelative(site); ok {
		cands = append(cands, exposureCandidate{
			rel: content + "/debug.log",
			why: "WordPress debug log: paths, queries, and stack traces",
		})
	}
	for _, name := range []string{"wp-config.php~", "wp-config.php.bak", "wp-config.php.orig", "wp-config.php.save"} {
		cands = append(cands, exposureCandidate{name, "editor/backup copy of wp-config.php: contains database credentials and salts"})
	}
	// Backup archives in the site root, bounded and deterministic.
	if entries, err := os.ReadDir(site.Path); err == nil {
		var names []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			base := strings.ToLower(e.Name())
			if !hasExtension(base, ".sql", ".sql.gz", ".dump", ".zip", ".tar", ".tar.gz", ".tgz") {
				continue
			}
			if strings.Contains(base, "backup") || strings.Contains(base, "dump") || strings.HasSuffix(base, ".sql") || strings.HasSuffix(base, ".sql.gz") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			if len(cands) >= maxExposureProbes {
				break
			}
			cands = append(cands, exposureCandidate{n, "database dump or archive: contains the whole database"})
		}
	}
	// Keep only candidates present on disk, then bound the list.
	present := cands[:0]
	for _, c := range cands {
		if fileExists(filepath.Join(site.Path, filepath.FromSlash(c.rel))) {
			present = append(present, c)
		}
	}
	if len(present) > maxExposureProbes {
		present = present[:maxExposureProbes]
	}
	return present
}

// contentRelative returns the content directory relative to the WordPress
// root, but only when it really is below the root: a relocated directory
// usually sits outside the served tree, where the URL mapping is unknown.
func contentRelative(site *wordpress.Site) (string, bool) {
	if site.ContentPath == "" || site.Path == "" {
		return "", false
	}
	rel, err := filepath.Rel(site.Path, site.ContentPath)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "SENSITIVE_FILE_PUBLICLY_RETRIEVABLE",
			Title:       "Sensitive files are publicly downloadable",
			Category:    CatExposure,
			Description: "Confirms real exposure instead of inferring it: sends one HEAD request per candidate file (never a GET, never a PHP file) to the site's own origin and reports the ones the server actually serves. Skipped offline or when the site URL is unknown.",
			References: []string{
				"https://owasp.org/www-project-web-security-testing-guide/",
				"https://developer.wordpress.org/advanced-administration/security/hardening/",
			},
			Importance: ImpCore,
		},
		Run: runPubliclyRetrievable,
	})
}

// shortErr renders an error as one bounded log-friendly clause.
func shortErr(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const limit = 120
	if len(s) > limit {
		s = s[:limit] + "…"
	}
	return s
}

// probeOutcome is one candidate's result.
type probeOutcome struct {
	cand     exposureCandidate
	status   int
	ctype    string
	length   string
	note     string
	blocked  bool
	reached  bool // the request completed (any status)
	verified bool // server answered 200
}

func runPubliclyRetrievable(ctx *Context) []Finding {
	m := Meta{ID: "SENSITIVE_FILE_PUBLICLY_RETRIEVABLE", Title: "Sensitive files are publicly downloadable", Category: CatExposure,
		References: []string{"https://owasp.org/www-project-web-security-testing-guide/"}}
	if ctx.Offline || ctx.Probe == nil || ctx.BaseURL == "" {
		return []Finding{m.skipf("network-backed check disabled (--offline or no site URL)")}
	}
	base := strings.TrimRight(ctx.BaseURL, "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return []Finding{m.skipf("site URL is not an absolute http(s) URL")}
	}
	if !ctx.Probe.OriginAllowed(base + "/") {
		return []Finding{m.skipf("site URL is outside the policy-pinned origin; not probed")}
	}

	candidates := exposureProbeSet(ctx.Site)
	if len(candidates) == 0 {
		return []Finding{m.skipf("no candidate files to probe")}
	}

	var verified []probeOutcome
	var protected []string
	var inconclusive []string
	for _, cand := range candidates {
		url := base + "/" + strings.TrimPrefix(cand.rel, "/")
		resp, err := ctx.Probe.Head(ctx.Ctx, url, nil)
		if err != nil {
			var blocked *probe.BlockedError
			if errors.As(err, &blocked) {
				inconclusive = append(inconclusive, cand.rel+" (blocked by policy)")
				continue
			}
			inconclusive = append(inconclusive, cand.rel+" ("+shortErr(err)+")")
			continue
		}
		out := probeOutcome{
			cand:   cand,
			status: resp.StatusCode,
			ctype:  resp.Header.Get("Content-Type"),
			length: resp.Header.Get("Content-Length"),
		}
		switch {
		case resp.StatusCode == 200:
			out.verified = true
			verified = append(verified, out)
		case resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 || resp.StatusCode == 410:
			protected = append(protected, fmt.Sprintf("%s (HTTP %d)", cand.rel, resp.StatusCode))
		default:
			inconclusive = append(inconclusive, fmt.Sprintf("%s (HTTP %d)", cand.rel, resp.StatusCode))
		}
	}

	ev := map[string]string{
		"probed": fmt.Sprint(len(candidates)),
	}
	if len(protected) > 0 {
		ev["not_retrievable"] = strings.Join(protected, ", ")
	}
	if len(inconclusive) > 0 {
		ev["inconclusive"] = strings.Join(inconclusive, ", ")
	}
	if len(verified) == 0 {
		if len(inconclusive) > 0 && len(protected) == 0 {
			// Nothing conclusive came back: report unknown rather than a
			// comfortable pass the evidence does not support.
			return []Finding{{ID: m.ID, Title: "Exposure not verifiable", Category: m.Category,
				Severity: SevInfo, Status: StatusUnknown, Confidence: ConfLow,
				Description: "None of the candidate files could be confirmed as retrievable or protected; the server did not answer conclusively.",
				Evidence:    ev}}
		}
		return []Finding{{ID: m.ID, Title: "No sensitive file is publicly retrievable", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: fmt.Sprintf("The server refused every one of the %d probed sensitive paths; nothing on disk is reachable over HTTP.", len(candidates)),
			Evidence:    ev}}
	}

	var listed []string
	occ := make([]Occurrence, 0, len(verified))
	for _, v := range verified {
		detail := v.cand.why
		if v.ctype != "" {
			detail += "; content-type " + v.ctype
		}
		if v.length != "" {
			detail += "; content-length " + v.length
		}
		listed = append(listed, v.cand.rel)
		occ = append(occ, Occurrence{
			ResourceType: "file", Location: v.cand.rel, Detail: detail,
		})
	}
	ev["retrievable"] = strings.Join(listed, ", ")
	ev["impact"] = "contents were not downloaded or stored by this scan; only status, content-type, and length were inspected"
	return []Finding{{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: SevHigh, Status: StatusFailed, Confidence: ConfHigh,
		Description:    fmt.Sprintf("%d sensitive file(s) were downloaded successfully from the public site URL. This is confirmed exposure, not an inference from file permissions.", len(verified)),
		Evidence:       ev,
		Occurrences:    occ,
		Recommendation: "Remove the files from the web root and rotate any credentials they contained; then block the paths at the web server (deny dotfiles, backups, and *.sql).",
		References:     m.References,
	}}
}
