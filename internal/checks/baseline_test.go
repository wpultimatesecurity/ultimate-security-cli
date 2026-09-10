package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/baseline"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wpcli"
)

func baselineAt() time.Time {
	return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
}

func TestBaselineDriftSkipsWithoutBaseline(t *testing.T) {
	site := testSite(t, map[string]string{"wp-includes/version.php": "<?php\n$wp_version = '6.8.2';\n"})
	fs := runByID(t, BaselineCheckID, ctxFor(site))
	f := findingByID(t, fs, BaselineCheckID)
	if f.Status != StatusSkipped {
		t.Errorf("status = %s, want skipped", f.Status)
	}
	if !strings.Contains(f.Evidence["reason"], "--baseline") {
		t.Errorf("skip reason must name the missing flag: %v", f.Evidence)
	}
}

func TestBaselineDriftSkipsWithoutSite(t *testing.T) {
	ctx := &Context{Baseline: &baseline.Baseline{SchemaVersion: baseline.SchemaVersion, CreatedAt: baselineAt()}}
	fs := runByID(t, BaselineCheckID, ctx)
	f := findingByID(t, fs, BaselineCheckID)
	if f.Status != StatusSkipped {
		t.Errorf("status = %s, want skipped", f.Status)
	}
	if f.Evidence["baseline_schema_version"] != baseline.SchemaVersion {
		t.Errorf("skip finding should still name the baseline: %v", f.Evidence)
	}
}

func TestBaselineDriftPassesWhenMatching(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-content/plugins/hello.php": "<?php\n/*\nPlugin Name: Hello\nVersion: 1.6\n*/\n",
	})
	ctx := ctxFor(site)
	ctx.Baseline = &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		CreatedAt:     baselineAt(),
		Plugins:       []baseline.Component{{Slug: "hello", Version: "1.6"}},
	}
	fs := runByID(t, BaselineCheckID, ctx)
	if len(fs) != 1 {
		t.Fatalf("want one passed finding, got %+v", fs)
	}
	f := fs[0]
	if f.Status != StatusPassed || f.ID != BaselineCheckID {
		t.Errorf("got %+v", f)
	}
	if f.Evidence["baseline_schema_version"] != baseline.SchemaVersion {
		t.Errorf("evidence must name the schema version: %v", f.Evidence)
	}
	if f.Evidence["baseline_created_at"] != baselineAt().Format(time.RFC3339) {
		t.Errorf("evidence must name the baseline creation time: %v", f.Evidence)
	}
}

func TestBaselineDriftGroupsChangesByKindAndSeverity(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-content/plugins/hello.php":           "<?php\n/*\nPlugin Name: Hello\nVersion: 2.0\n*/\n",
		"wp-content/plugins/akismet/akismet.php": "<?php\n/*\nPlugin Name: Akismet\nVersion: 5.0\n*/\n",
	})
	ctx := ctxFor(site)
	ctx.WP = &wpcli.Siteenv{Admins: []wpcli.WPUser{{Login: "newadmin"}}}
	ctx.Findings = []Finding{{
		ID: "WP_DEBUG_ENABLED", Severity: SevMedium, Status: StatusFailed, Fingerprint: "fp-new",
	}}
	ctx.Baseline = &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		CreatedAt:     baselineAt(),
		Plugins: []baseline.Component{
			{Slug: "hello", Version: "1.0"},
			{Slug: "old-plugin", Version: "3.0"},
		},
		Dropins:  []string{"object-cache.php"},
		Admins:   []string{"alice"},
		Findings: []baseline.FindingRef{},
	}

	fs := runByID(t, BaselineCheckID, ctx)
	byKind := map[baseline.ChangeKind]Finding{}
	for _, f := range fs {
		if f.ID != BaselineCheckID {
			t.Errorf("drift finding has ID %s", f.ID)
		}
		if f.Evidence["baseline_schema_version"] == "" || f.Evidence["baseline_created_at"] == "" {
			t.Errorf("finding for %s lacks baseline evidence: %v", f.Evidence["change"], f.Evidence)
		}
		byKind[baseline.ChangeKind(f.Evidence["change"])] = f
	}
	want := map[baseline.ChangeKind]Severity{
		baseline.ChangeComponentAdded:   SevMedium,
		baseline.ChangeAdminAdded:       SevMedium,
		baseline.ChangeFindingAdded:     SevMedium,
		baseline.ChangeVersionChanged:   SevLow,
		baseline.ChangeComponentRemoved: SevInfo,
		baseline.ChangeDropinRemoved:    SevInfo,
		baseline.ChangeAdminRemoved:     SevInfo,
	}
	if len(fs) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(fs), len(want), byKind)
	}
	for kind, sev := range want {
		f, ok := byKind[kind]
		if !ok {
			t.Errorf("missing kind %s", kind)
			continue
		}
		if f.Severity != sev || f.Status != StatusFailed {
			t.Errorf("kind %s: severity=%s status=%s, want %s/failed", kind, f.Severity, f.Status, sev)
		}
	}
	// Severities are ordered descending so the actionable groups come first.
	for i := 1; i < len(fs); i++ {
		if fs[i-1].Severity.Rank() < fs[i].Severity.Rank() {
			t.Errorf("findings not ordered by severity: %s then %s", fs[i-1].Severity, fs[i].Severity)
		}
	}

	version := byKind[baseline.ChangeVersionChanged]
	if len(version.Occurrences) != 1 {
		t.Fatalf("version change occurrences = %+v", version.Occurrences)
	}
	if o := version.Occurrences[0]; o.ResourceType != "plugin" || o.Slug != "hello" || o.Detail != "1.0 → 2.0" {
		t.Errorf("version change occurrence = %+v", o)
	}
	added := byKind[baseline.ChangeComponentAdded]
	if len(added.Occurrences) != 1 || added.Occurrences[0].Slug != "akismet" || added.Occurrences[0].Detail != "added, version 5.0" {
		t.Errorf("component added occurrence = %+v", added.Occurrences)
	}
	adminAdded := byKind[baseline.ChangeAdminAdded]
	if len(adminAdded.Occurrences) != 1 || adminAdded.Occurrences[0].ResourceType != "user" || adminAdded.Occurrences[0].Slug != "newadmin" {
		t.Errorf("admin added occurrence = %+v", adminAdded.Occurrences)
	}
	findingAdded := byKind[baseline.ChangeFindingAdded]
	if len(findingAdded.Occurrences) != 1 {
		t.Fatalf("finding added occurrence = %+v", findingAdded.Occurrences)
	}
	o := findingAdded.Occurrences[0]
	if o.ResourceType != "finding" || o.Slug != "fp-new" || !strings.Contains(o.Detail, "WP_DEBUG_ENABLED") || !strings.Contains(o.Detail, "medium") {
		t.Errorf("finding added occurrence = %+v", o)
	}
}

func TestBaselineDriftCapsOccurrences(t *testing.T) {
	site := testSite(t, map[string]string{"wp-includes/version.php": "<?php\n$wp_version = '6.8.2';\n"})
	ctx := ctxFor(site)
	b := &baseline.Baseline{SchemaVersion: baseline.SchemaVersion, CreatedAt: baselineAt()}
	for i := 0; i < 30; i++ {
		b.Plugins = append(b.Plugins, baseline.Component{Slug: "p" + itoa(i), Version: "1.0"})
	}
	ctx.Baseline = b

	fs := runByID(t, BaselineCheckID, ctx)
	if len(fs) != 1 {
		t.Fatalf("want one grouped finding, got %+v", fs)
	}
	f := fs[0]
	if len(f.Occurrences) != maxBaselineOccurrences {
		t.Errorf("occurrences = %d, want the cap %d", len(f.Occurrences), maxBaselineOccurrences)
	}
	if f.Evidence["changes"] != "30" || f.Evidence["occurrences_omitted"] != "5" {
		t.Errorf("evidence must disclose the truncation: %v", f.Evidence)
	}
}

func TestBaselineDriftMissingAdminsIsACoverageGap(t *testing.T) {
	site := testSite(t, map[string]string{"wp-includes/version.php": "<?php\n$wp_version = '6.8.2';\n"})
	ctx := ctxFor(site)
	// No WP-CLI bundle: a static scan cannot see the user table.
	ctx.Baseline = &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		CreatedAt:     baselineAt(),
		Admins:        []string{"alice"},
	}
	fs := runByID(t, BaselineCheckID, ctx)
	if len(fs) != 1 || fs[0].Status != StatusPassed {
		t.Fatalf("unknown admins must not be reported as removals: %+v", fs)
	}
	if !strings.Contains(fs[0].Evidence["admins"], "not collected") {
		t.Errorf("evidence must say admin data was unavailable: %v", fs[0].Evidence)
	}
	gaps := ctx.CoverageGaps()
	if len(gaps) != 1 || !strings.Contains(gaps[0], "administrator") {
		t.Errorf("expected one administrator coverage gap, got %v", gaps)
	}
}

func TestBaselineDriftFindingRefs(t *testing.T) {
	site := testSite(t, map[string]string{"wp-includes/version.php": "<?php\n$wp_version = '6.8.2';\n"})
	ctx := ctxFor(site)
	ctx.Findings = []Finding{
		{ID: "WP_DEBUG_ENABLED", Severity: SevMedium, Status: StatusFailed, Fingerprint: "fp-a"},
		{ID: "IGNORED_PASSED", Severity: SevInfo, Status: StatusPassed, Fingerprint: "fp-b"},
		{ID: "IGNORED_SKIPPED", Severity: SevHigh, Status: StatusSkipped},
	}
	ctx.Baseline = &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		CreatedAt:     baselineAt(),
		Findings:      []baseline.FindingRef{{Fingerprint: "fp-old", ID: "OLD_CHECK", Severity: "low"}},
	}
	fs := runByID(t, BaselineCheckID, ctx)
	byKind := map[baseline.ChangeKind]Finding{}
	for _, f := range fs {
		byKind[baseline.ChangeKind(f.Evidence["change"])] = f
	}
	added, ok := byKind[baseline.ChangeFindingAdded]
	if !ok {
		t.Fatalf("missing finding_added: %+v", fs)
	}
	if added.Occurrences[0].Slug != "fp-a" || added.Occurrences[0].Detail != "finding WP_DEBUG_ENABLED (medium) is new" {
		t.Errorf("finding_added = %+v", added.Occurrences)
	}
	resolved, ok := byKind[baseline.ChangeFindingResolved]
	if !ok {
		t.Fatalf("missing finding_resolved: %+v", fs)
	}
	if resolved.Severity != SevInfo || resolved.Occurrences[0].Slug != "fp-old" {
		t.Errorf("finding_resolved = %+v", resolved)
	}
}
