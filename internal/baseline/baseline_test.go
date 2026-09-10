package baseline

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testBaseline() *Baseline {
	return &Baseline{
		SchemaVersion: SchemaVersion,
		CreatedAt:     time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
		Tool:          "wpus test",
		WordPress:     "6.8.2",
		Plugins:       []Component{{Slug: "akismet", Version: "5.3"}},
		Themes:        []Component{{Slug: "twentytwentyfour", Version: "1.2"}},
		MuPlugins:     []Component{{Slug: "0-host-loader", Version: ""}},
		Dropins:       []string{"object-cache.php"},
		Admins:        []string{"alice"},
		Findings:      []FindingRef{{Fingerprint: "abc123", ID: "WP_DEBUG_ENABLED", Severity: "medium"}},
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	want := testBaseline()
	if err := want.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

// TestSaveLeavesNoTemporaryFile pins the atomic-write contract: the
// destination directory holds exactly the baseline afterwards.
func TestSaveLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := testBaseline().Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "baseline.json" {
		t.Errorf("expected only baseline.json, got %v", entryNames(entries))
	}
}

// TestSaveCleansUpWhenRenameFails forces the final rename to fail (the target
// is a directory) and asserts no partial or temporary file survives.
func TestSaveCleansUpWhenRenameFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "baseline.json")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := testBaseline().Save(target); err == nil {
		t.Fatal("expected Save to fail when the destination cannot be replaced")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "baseline.json" || !entries[0].IsDir() {
		t.Errorf("a failed save left artifacts behind: %v", entryNames(entries))
	}
}

func TestLoadRejectsUnknownSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"9.9","findings":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an unsupported schema_version to be refused")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error must name the offending field: %v", err)
	}
}

func TestLoadMissingFileIsAnError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("a missing baseline file must be an error")
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("malformed JSON must be an error")
	}
}

func TestCompareTable(t *testing.T) {
	base := func() *Baseline {
		return &Baseline{Plugins: []Component{{Slug: "hello", Version: "1.0"}}}
	}
	pluginChange := func(kind ChangeKind, from, to string) Change {
		return Change{Kind: kind, Resource: ResourcePlugin, Slug: "hello", From: from, To: to}
	}
	tests := []struct {
		name    string
		old     *Baseline
		current *Snapshot
		want    []Change
	}{
		{
			name:    "no changes",
			old:     base(),
			current: &Snapshot{Plugins: []Component{{Slug: "hello", Version: "1.0"}}},
			want:    []Change{},
		},
		{
			name:    "metadata only differences are not drift",
			old:     &Baseline{WordPress: "6.5.0"},
			current: &Snapshot{WordPress: "6.8.2"},
			want:    []Change{},
		},
		{
			name:    "plugin added",
			old:     &Baseline{},
			current: &Snapshot{Plugins: []Component{{Slug: "akismet", Version: "5.3"}}},
			want:    []Change{{Kind: ChangeComponentAdded, Resource: ResourcePlugin, Slug: "akismet", To: "5.3"}},
		},
		{
			name:    "plugin removed",
			old:     &Baseline{Plugins: []Component{{Slug: "hello", Version: "1.0"}}},
			current: &Snapshot{},
			want:    []Change{{Kind: ChangeComponentRemoved, Resource: ResourcePlugin, Slug: "hello", From: "1.0"}},
		},
		{
			name:    "version change is one change",
			old:     base(),
			current: &Snapshot{Plugins: []Component{{Slug: "hello", Version: "2.0"}}},
			want:    []Change{pluginChange(ChangeVersionChanged, "1.0", "2.0")},
		},
		{
			name:    "component kinds are distinguished by resource",
			old:     &Baseline{Themes: []Component{{Slug: "twentytwentyfour", Version: "1.0"}}},
			current: &Snapshot{Themes: []Component{{Slug: "twentytwentyfour", Version: "1.2"}}, MuPlugins: []Component{{Slug: "0-loader", Version: ""}}},
			want: []Change{
				{Kind: ChangeComponentAdded, Resource: ResourceMuPlugin, Slug: "0-loader", To: ""},
				{Kind: ChangeVersionChanged, Resource: ResourceTheme, Slug: "twentytwentyfour", From: "1.0", To: "1.2"},
			},
		},
		{
			name:    "dropin added and removed",
			old:     &Baseline{Dropins: []string{"object-cache.php"}},
			current: &Snapshot{Dropins: []string{"advanced-cache.php"}},
			want: []Change{
				{Kind: ChangeDropinAdded, Resource: ResourceDropin, Slug: "advanced-cache.php"},
				{Kind: ChangeDropinRemoved, Resource: ResourceDropin, Slug: "object-cache.php"},
			},
		},
		{
			name:    "admins added and removed",
			old:     &Baseline{Admins: []string{"alice"}},
			current: &Snapshot{Admins: []string{"bob"}},
			want: []Change{
				{Kind: ChangeAdminRemoved, Resource: ResourceUser, Slug: "alice"},
				{Kind: ChangeAdminAdded, Resource: ResourceUser, Slug: "bob"},
			},
		},
		{
			name:    "finding added",
			old:     &Baseline{},
			current: &Snapshot{Findings: []FindingRef{{Fingerprint: "fp1", ID: "WP_DEBUG_ENABLED", Severity: "medium"}}},
			want: []Change{
				{Kind: ChangeFindingAdded, Resource: ResourceFinding, Slug: "fp1", To: "medium", CheckID: "WP_DEBUG_ENABLED"},
			},
		},
		{
			name:    "finding resolved",
			old:     &Baseline{Findings: []FindingRef{{Fingerprint: "fp1", ID: "WP_DEBUG_ENABLED", Severity: "medium"}}},
			current: &Snapshot{},
			want: []Change{
				{Kind: ChangeFindingResolved, Resource: ResourceFinding, Slug: "fp1", From: "medium", CheckID: "WP_DEBUG_ENABLED"},
			},
		},
		{
			name:    "finding compared by fingerprint, not ID",
			old:     &Baseline{Findings: []FindingRef{{Fingerprint: "fp1", ID: "X", Severity: "low"}}},
			current: &Snapshot{Findings: []FindingRef{{Fingerprint: "fp2", ID: "X", Severity: "low"}}},
			want: []Change{
				{Kind: ChangeFindingResolved, Resource: ResourceFinding, Slug: "fp1", From: "low", CheckID: "X"},
				{Kind: ChangeFindingAdded, Resource: ResourceFinding, Slug: "fp2", To: "low", CheckID: "X"},
			},
		},
		{
			name:    "nil inputs produce no changes",
			old:     nil,
			current: &Snapshot{},
			want:    []Change{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.old, tt.current)
			if got == nil {
				t.Fatal("Compare must return an empty slice, never nil")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Compare:\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// TestCompareOrderingIsDeterministicShuffledInputs feeds the same state in two
// different orders and requires identical, canonically sorted output.
func TestCompareOrderingIsDeterministicShuffledInputs(t *testing.T) {
	old := &Baseline{
		Plugins: []Component{{Slug: "zeta", Version: "1.0"}, {Slug: "alpha", Version: "1.0"}},
		Dropins: []string{"db.php", "object-cache.php"},
		Admins:  []string{"carol", "alice"},
		Findings: []FindingRef{
			{Fingerprint: "ff", ID: "B", Severity: "low"},
			{Fingerprint: "aa", ID: "A", Severity: "high"},
		},
	}
	current := &Snapshot{
		Plugins: []Component{{Slug: "alpha", Version: "2.0"}},
		Themes:  []Component{{Slug: "t2", Version: "1.0"}, {Slug: "t1", Version: "1.0"}},
		Admins:  []string{"bob"},
		Findings: []FindingRef{
			{Fingerprint: "zz", ID: "C", Severity: "medium"},
			{Fingerprint: "aa", ID: "A", Severity: "high"},
		},
	}
	want := Compare(old, current)
	// Shuffle: reverse every slice and re-run.
	shuffled := &Baseline{
		Plugins: []Component{{Slug: "alpha", Version: "1.0"}, {Slug: "zeta", Version: "1.0"}},
		Dropins: []string{"object-cache.php", "db.php"},
		Admins:  []string{"alice", "carol"},
		Findings: []FindingRef{
			{Fingerprint: "aa", ID: "A", Severity: "high"},
			{Fingerprint: "ff", ID: "B", Severity: "low"},
		},
	}
	shuffledCurrent := &Snapshot{
		Plugins: []Component{{Slug: "alpha", Version: "2.0"}},
		Themes:  []Component{{Slug: "t1", Version: "1.0"}, {Slug: "t2", Version: "1.0"}},
		Admins:  []string{"bob"},
		Findings: []FindingRef{
			{Fingerprint: "aa", ID: "A", Severity: "high"},
			{Fingerprint: "zz", ID: "C", Severity: "medium"},
		},
	}
	got := Compare(shuffled, shuffledCurrent)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ordering depends on input order:\n got %+v\nwant %+v", got, want)
	}
	// And the canonical order is resource, then slug, then kind.
	for i := 1; i < len(got); i++ {
		a, b := got[i-1], got[i]
		if a.Resource > b.Resource ||
			(a.Resource == b.Resource && a.Slug > b.Slug) ||
			(a.Resource == b.Resource && a.Slug == b.Slug && a.Kind > b.Kind) {
			t.Errorf("changes not sorted deterministically: %+v then %+v", a, b)
		}
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
