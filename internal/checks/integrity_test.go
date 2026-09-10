package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/vulnerability"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
)

// stubChecksums is an in-memory ChecksumSource so integrity checks can be
// tested without touching the network.
type stubChecksums struct {
	core           map[string]string
	coreErr        error
	plugins        map[string]map[string]string
	pluginsEnabled bool
	calls          int
}

func (s *stubChecksums) CoreChecksums(_ context.Context, _, _ string) (map[string]string, error) {
	s.calls++
	if s.coreErr != nil {
		return nil, s.coreErr
	}
	return s.core, nil
}

func (s *stubChecksums) PluginChecksums(_ context.Context, slug, version string) (map[string]string, error) {
	s.calls++
	m, ok := s.plugins[slug+"@"+version]
	if !ok {
		return nil, errors.New("checksums: unavailable")
	}
	return m, nil
}

func (s *stubChecksums) PluginsEnabled() bool { return s.pluginsEnabled }

// integrityFixture builds a site whose core files hash to a known manifest.
func integrityFixture(t *testing.T, extra map[string]string) (*wordpress.Site, map[string]string) {
	t.Helper()
	files := map[string]string{
		"wp-includes/version.php": "<?php\n$wp_version = '6.4.1';\n",
		"wp-settings.php":         "<?php\n",
		"wp-load.php":             "<?php\n",
		"wp-admin/admin.php":      "<?php\n// admin\n",
		"wp-admin/includes/x.php": "<?php\n// helper\n",
		"wp-includes/load.php":    "<?php\n// load\n",
	}
	for k, v := range extra {
		files[k] = v
	}
	site := testSite(t, files)
	manifest := map[string]string{}
	for _, rel := range []string{
		"wp-settings.php", "wp-load.php",
		"wp-admin/admin.php", "wp-admin/includes/x.php",
		"wp-includes/load.php",
	} {
		sum, err := md5File(filepath.Join(site.Path, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		manifest[rel] = sum
	}
	return site, manifest
}

func TestCoreIntegrityClean(t *testing.T) {
	site, manifest := integrityFixture(t, nil)
	ctx := ctxFor(site)
	ctx.Checksums = &stubChecksums{core: manifest}

	for _, id := range []string{"CORE_INTEGRITY_MODIFIED", "CORE_FILE_MISSING", "CORE_UNEXPECTED_FILE"} {
		if s := statusOf(t, runByID(t, id, ctx), id); s != StatusPassed {
			t.Errorf("%s should pass on an untouched core, got %s", id, s)
		}
	}
}

// TestCoreIntegrityDetectsTampering is the core property of the flagship
// check: a single altered byte in a core file must be reported with the
// affected path.
func TestCoreIntegrityDetectsTampering(t *testing.T) {
	site, manifest := integrityFixture(t, nil)
	if err := os.WriteFile(filepath.Join(site.Path, "wp-includes", "load.php"),
		[]byte("<?php\n// backdoor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := ctxFor(site)
	ctx.Checksums = &stubChecksums{core: manifest}

	f := findingByID(t, runByID(t, "CORE_INTEGRITY_MODIFIED", ctx), "CORE_INTEGRITY_MODIFIED")
	if f.Status != StatusFailed || f.Severity != SevHigh {
		t.Fatalf("tampered core file must fail high, got %+v", f)
	}
	if len(f.Occurrences) != 1 || f.Occurrences[0].Location != "wp-includes/load.php" {
		t.Errorf("occurrence should name the tampered file: %+v", f.Occurrences)
	}
}

func TestCoreIntegrityDetectsMissingAndUnexpected(t *testing.T) {
	site, manifest := integrityFixture(t, map[string]string{
		"wp-includes/evil.php": "<?php\n// injected\n",
	})
	if err := os.Remove(filepath.Join(site.Path, "wp-admin", "includes", "x.php")); err != nil {
		t.Fatal(err)
	}
	ctx := ctxFor(site)
	ctx.Checksums = &stubChecksums{core: manifest}

	mf := findingByID(t, runByID(t, "CORE_FILE_MISSING", ctx), "CORE_FILE_MISSING")
	if mf.Status != StatusFailed || mf.Severity != SevMedium {
		t.Errorf("missing core file must fail medium, got %+v", mf)
	}
	if len(mf.Occurrences) != 1 || mf.Occurrences[0].Location != "wp-admin/includes/x.php" {
		t.Errorf("missing-file occurrence wrong: %+v", mf.Occurrences)
	}

	uf := findingByID(t, runByID(t, "CORE_UNEXPECTED_FILE", ctx), "CORE_UNEXPECTED_FILE")
	if uf.Status != StatusFailed {
		t.Errorf("injected file in a core directory must fail, got %+v", uf)
	}
	if len(uf.Occurrences) != 1 || uf.Occurrences[0].Location != "wp-includes/evil.php" {
		t.Errorf("unexpected-file occurrence wrong: %+v", uf.Occurrences)
	}
	// The site root is full of legitimate custom files; they must be context,
	// not a failure.
	if _, ok := uf.Evidence["site_root_files"]; ok && uf.Severity == SevHigh {
		t.Error("root-level extra files must not escalate the finding")
	}
}

func TestCoreIntegrityWithoutChecksumSource(t *testing.T) {
	site, _ := integrityFixture(t, nil)
	ctx := ctxFor(site)
	ctx.Checksums = nil
	f := findingByID(t, runByID(t, "CORE_INTEGRITY_MODIFIED", ctx), "CORE_INTEGRITY_MODIFIED")
	if f.Status != StatusSkipped {
		t.Fatalf("no checksum source must skip, got %+v", f)
	}
	if f.Evidence["reason"] == "" {
		t.Error("a skip must state why")
	}
}

func TestPluginIntegrity(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-settings.php":                        "<?php\n",
		"wp-content/plugins/good/good.php":       "<?php\n/*\nPlugin Name: Good\nVersion: 1.0\n*/\n",
		"wp-content/plugins/good/includes/h.php": "<?php\n// helper\n",
		"wp-content/plugins/bad/bad.php":         "<?php\n/*\nPlugin Name: Bad\nVersion: 2.0\n*/\n",
		"wp-content/plugins/premium/premium.php": "<?php\n/*\nPlugin Name: Premium\nVersion: 3.0\n*/\n",
	})
	sum := func(rel string) string {
		s, err := md5File(filepath.Join(site.Path, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	stub := &stubChecksums{
		pluginsEnabled: true,
		plugins: map[string]map[string]string{
			"good@1.0": {
				"good.php":       sum("wp-content/plugins/good/good.php"),
				"includes/h.php": sum("wp-content/plugins/good/includes/h.php"),
			},
			"bad@2.0": {"bad.php": "00000000000000000000000000000000"},
		},
	}
	ctx := ctxFor(site)
	ctx.Checksums = stub

	f := findingByID(t, runByID(t, "PLUGIN_INTEGRITY_MODIFIED", ctx), "PLUGIN_INTEGRITY_MODIFIED")
	if f.Status != StatusFailed || len(f.Occurrences) != 1 || f.Occurrences[0].Slug != "bad" {
		t.Fatalf("modified plugin files must fail with an occurrence: %+v", f)
	}

	un := findingByID(t, runByID(t, "PLUGIN_CHECKSUM_UNAVAILABLE", ctx), "PLUGIN_CHECKSUM_UNAVAILABLE")
	if un.Status != StatusUnknown {
		t.Fatalf("a plugin with no release must be unknown, never a failure: %+v", un)
	}
	if !contains(un.Evidence["unverifiable"], "premium") {
		t.Errorf("unverifiable list should name the premium plugin: %+v", un.Evidence)
	}
}

func TestPluginIntegrityExtraFilesAndBudget(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-settings.php":                     "<?php\n",
		"wp-content/plugins/one/one.php":      "<?php\n/*\nPlugin Name: One\nVersion: 1.0\n*/\n",
		"wp-content/plugins/one/.DS_Store":    "junk",
		"wp-content/plugins/one/.git/config":  "[core]",
		"wp-content/plugins/one/injected.php": "<?php\n// injected\n",
	})
	sum, err := md5File(filepath.Join(site.Path, "wp-content", "plugins", "one", "one.php"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := ctxFor(site)
	ctx.Checksums = &stubChecksums{
		pluginsEnabled: true,
		plugins:        map[string]map[string]string{"one@1.0": {"one.php": sum}},
	}
	f := findingByID(t, runByID(t, "PLUGIN_INTEGRITY_EXTRA_FILE", ctx), "PLUGIN_INTEGRITY_EXTRA_FILE")
	if f.Status != StatusFailed {
		t.Fatalf("extra PHP in a plugin must be reported: %+v", f)
	}
	if f.Severity != SevMedium {
		t.Errorf("extra PHP files should raise the severity above the low default, got %s", f.Severity)
	}
	for _, o := range f.Occurrences {
		if o.Location == ".DS_Store" || o.Location == ".git/config" {
			t.Errorf("explainable extras must be excluded: %+v", o)
		}
	}
	if len(f.Occurrences) != 1 || f.Occurrences[0].Location != "injected.php" {
		t.Errorf("occurrences = %+v, want only the injected file", f.Occurrences)
	}
}

func TestPluginIntegrityDisabled(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-settings.php":                "<?php\n",
		"wp-content/plugins/one/one.php": "<?php\n/*\nPlugin Name: One\nVersion: 1.0\n*/\n",
	})
	ctx := ctxFor(site)
	ctx.Checksums = &stubChecksums{}
	f := findingByID(t, runByID(t, "PLUGIN_INTEGRITY_MODIFIED", ctx), "PLUGIN_INTEGRITY_MODIFIED")
	if f.Status != StatusSkipped {
		t.Fatalf("plugin checksums must be opt-in: %+v", f)
	}
	if !contains(f.Evidence["reason"], "--verify-plugin-checksums") {
		t.Errorf("the skip must tell the operator how to enable it: %+v", f.Evidence)
	}
}

// TestWalkDeadlineAppliesWithoutMatches pins the fixed traversal bug: the
// wall-clock budget must be honoured even when nothing matched, otherwise a
// large tree with no hits ignores the deadline entirely.
func TestWalkDeadlineAppliesWithoutMatches(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 20; i++ {
		p := filepath.Join(dir, "sub", itoa(i)+".txt")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res := walk(dir, walkCaps{Deadline: time.Now().Add(-time.Second), MaxFiles: 100, MaxDepth: 8}, func(string) bool { return false })
	if !res.Truncated || res.TruncationReason != "time" {
		t.Fatalf("an expired deadline must truncate regardless of matches: %+v", res)
	}
}

func TestWalkFileBudgetAndCoverage(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		if err := os.WriteFile(filepath.Join(dir, itoa(i)+".php"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res := walk(dir, walkCaps{MaxFiles: 3, MaxDepth: 4, MaxMatches: 10}, func(string) bool { return true })
	if !res.Truncated || res.TruncationReason != "max_files" {
		t.Errorf("file budget must report truncation: %+v", res)
	}
	ev := walkEvidence(res)
	if ev["truncation"] != "max_files" || ev["note"] == "" {
		t.Errorf("evidence must disclose the truncation: %+v", ev)
	}

	// The Context must aggregate walk accounting for the coverage score.
	site := testSite(t, map[string]string{"wp-settings.php": "<?php\n"})
	ctx := ctxFor(site)
	ctx.walk(dir, walkCaps{MaxFiles: 3, MaxDepth: 4, MaxMatches: 10}, func(string) bool { return true })
	stats := ctx.WalkStats()
	if !stats.Truncated || stats.FilesVisited == 0 {
		t.Errorf("context walk stats = %+v", stats)
	}
}

func TestCoverageGapsAreRecorded(t *testing.T) {
	site := testSite(t, map[string]string{"wp-settings.php": "<?php\n"})
	ctx := ctxFor(site)
	ctx.AddGap("something was not examined")
	ctx.AddGap("something was not examined") // deduplicated
	ctx.AddGap("something else")
	gaps := ctx.CoverageGaps()
	if len(gaps) != 2 {
		t.Fatalf("gaps = %v", gaps)
	}
}

// TestCoreVulnerabilityCheck covers the core advisory path, which previously
// had a provider method but no check using it.
func TestCoreVulnerabilityCheck(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-includes/version.php": "<?php\n$wp_version = '6.4.1';\n",
		"wp-settings.php":         "<?php\n",
	})
	ctx := ctxFor(site)
	ctx.Vulns = stubProvider{}
	if s := statusOf(t, runByID(t, "WP_CORE_VULNERABILITY", ctx), "WP_CORE_VULNERABILITY"); s != StatusPassed {
		t.Errorf("stub provider has no core advisories, got %s", s)
	}
	ctx.Vulns = vulnerability.Unavailable{}
	if s := statusOf(t, runByID(t, "WP_CORE_VULNERABILITY", ctx), "WP_CORE_VULNERABILITY"); s != StatusSkipped {
		t.Errorf("no provider must skip, got %s", s)
	}
}
