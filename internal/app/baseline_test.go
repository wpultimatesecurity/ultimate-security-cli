package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/baseline"
)

func writeFixtureFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestBaselineCreateAndScanDrift is the end-to-end contract: record a
// fixture, change it, and require `scan --baseline` to report exactly the
// component drift that happened.
func TestBaselineCreateAndScanDrift(t *testing.T) {
	root := makeFixture(t)
	baselinePath := filepath.Join(t.TempDir(), "baseline.json")

	var stdout, stderr bytes.Buffer
	code := ExecuteWithWriters("wpus test", []string{
		"baseline", "create", root, "--offline", "--no-config", "--output", baselinePath,
	}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("baseline create exit = %d\n%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "baseline written to") {
		t.Errorf("expected a one-line confirmation on stderr, got %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("baseline create must not write to stdout: %q", stdout.String())
	}
	record, err := baseline.Load(baselinePath)
	if err != nil {
		t.Fatalf("loading the recorded baseline: %v", err)
	}
	if record.SchemaVersion != baseline.SchemaVersion {
		t.Errorf("schema = %q", record.SchemaVersion)
	}
	if len(record.Plugins) != 1 || record.Plugins[0].Slug != "hello" || record.Plugins[0].Version != "1.6" {
		t.Fatalf("recorded plugins = %+v", record.Plugins)
	}
	if len(record.Findings) == 0 {
		t.Fatal("the baseline must record the fixture's findings")
	}

	// Mutate the installation: a plugin appears and an existing one updates.
	writeFixtureFile(t, root, "wp-content/plugins/newthing/newthing.php",
		"<?php\n/*\nPlugin Name: New Thing\nVersion: 1.0\n*/\n")
	writeFixtureFile(t, root, "wp-content/plugins/hello.php",
		"<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7\n*/\n")

	code, out := runRaw(t, "scan", "--offline", "--no-config", "--format", "json", "--baseline", baselinePath, root)
	if code != ExitOK {
		t.Fatalf("scan exit = %d\n%s", code, out)
	}
	report := decodeReport(t, out)
	details := map[string][]string{}
	for _, f := range report.Sites[0].Findings {
		if f.ID != "BASELINE_DRIFT" || f.Status != "failed" {
			continue
		}
		if f.Evidence["baseline_created_at"] == "" || f.Evidence["baseline_schema_version"] == "" {
			t.Errorf("drift finding lacks baseline evidence: %v", f.Evidence)
		}
		for _, o := range f.Occurrences {
			details[f.Evidence["change"]] = append(details[f.Evidence["change"]], o.Slug+" "+o.Detail)
		}
	}
	if !containsString(details["added"], "newthing added, version 1.0") {
		t.Errorf("added drift not reported: %v", details)
	}
	if !containsString(details["version_changed"], "hello 1.6 → 1.7") {
		t.Errorf("version drift not reported: %v", details)
	}
	if len(details["removed"]) != 0 {
		t.Errorf("nothing was removed, but got %v", details["removed"])
	}
}

func TestScanMissingBaselineIsUsageError(t *testing.T) {
	root := makeFixture(t)
	code, out := runRaw(t, "scan", "--offline", "--no-config",
		"--baseline", filepath.Join(t.TempDir(), "absent.json"), root)
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d\n%s", code, ExitUsage, out)
	}
}

func TestScanUnsupportedBaselineSchemaIsUsageError(t *testing.T) {
	root := makeFixture(t)
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"99.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := runRaw(t, "scan", "--offline", "--no-config", "--baseline", path, root)
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d\n%s", code, ExitUsage, out)
	}
}

func TestBaselineCreateRequiresOutput(t *testing.T) {
	root := makeFixture(t)
	code, out := runRaw(t, "baseline", "create", root, "--offline", "--no-config")
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d\n%s", code, ExitUsage, out)
	}
}

func TestBaselineCreateRefusesOutputInsideSite(t *testing.T) {
	root := makeFixture(t)
	inside := filepath.Join(root, "baseline.json")
	code, out := runRaw(t, "baseline", "create", root, "--offline", "--no-config", "--output", inside)
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d\n%s", code, ExitUsage, out)
	}
	if _, err := os.Stat(inside); err == nil {
		t.Error("a baseline was written inside the audited site")
	}
}
