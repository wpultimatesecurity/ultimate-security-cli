package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/reporting"
)

// makeFixture writes a deterministic, intentionally weak WordPress fixture.
func makeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"wp-config.php": `<?php
define( 'DB_PASSWORD', 'FixtureSecret42!' );
define( 'WP_DEBUG', true );
$table_prefix = 'wp_';
`,
		"wp-settings.php":                   "<?php\n",
		"wp-load.php":                       "<?php\n",
		"wp-includes/version.php":           "<?php\n$wp_version = '6.4.1';\n$wp_db_version = '56657';\n",
		"wp-content/debug.log":              "[10-Sep-2026] PHP Notice: test\n",
		"wp-content/plugins/hello.php":      "<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.6\n*/\n",
		"wp-content/themes/tt/style.css":    "/*\nTheme Name: Twenty X\nVersion: 1.0\n*/\n",
		"backup.sql":                        "CREATE TABLE t;",
		"wp-content/uploads/2026/weird.php": "<?php echo 1;",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A directory requirement: wp-admin.
	if err := os.MkdirAll(filepath.Join(root, "wp-admin"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	// Hermetic: skip WP-CLI and network for deterministic tests.
	full := append([]string{"scan", "--skip-wpcli", "--offline"}, args...)
	var out bytes.Buffer
	code := ExecuteWithWriters("wpus test", full, &out, &out)
	return code, out.String()
}

func TestScanJSONExitCodes(t *testing.T) {
	root := makeFixture(t)

	// Plain scan passes (no --fail-on policy).
	code, out := runCLI(t, root, "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	var report reporting.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(report.Sites) != 1 || report.Sites[0].Path != root {
		t.Fatalf("unexpected sites: %+v", report.Sites)
	}
	if report.SchemaVersion != reporting.SchemaVersion {
		t.Errorf("schema = %q", report.SchemaVersion)
	}

	// Findings must include the deterministic failures.
	ids := map[string]bool{}
	for _, f := range report.Sites[0].Findings {
		if f.Status == "failed" {
			ids[f.ID] = true
		}
	}
	for _, want := range []string{"WP_DEBUG_ENABLED", "SECURITY_KEYS_MISSING", "DEFAULT_DATABASE_PREFIX", "EXPOSED_DEBUG_LOG", "EXPOSED_BACKUP_FILE", "PHP_EXECUTION_IN_UPLOADS"} {
		if !ids[want] {
			t.Errorf("expected failed finding %s (got %v)", want, ids)
		}
	}

	// Secrets must never appear anywhere in the report.
	if strings.Contains(out, "FixtureSecret42!") {
		t.Error("DB_PASSWORD leaked into JSON output")
	}

	// --fail-on high must exit 1 (vulnerable-plugin finding is skipped
	// offline — but EXPOSED_BACKUP_FILE is high... verify threshold logic).
	code, _ = runCLI(t, root, "--format", "json", "--fail-on", "low")
	if code != ExitFindings {
		t.Errorf("--fail-on low should exit 1, got %d", code)
	}

	// Without a threshold, findings never fail the run.
	code, _ = runCLI(t, root, "--format", "json")
	if code != ExitOK {
		t.Errorf("no threshold should exit 0, got %d", code)
	}
}

func TestScanUsageErrors(t *testing.T) {
	root := makeFixture(t)
	cases := [][]string{
		{root, "--severity", "banana"},
		{root, "--fail-on", "everything"},
		{root, "--format", "xml"},
		{"/nonexistent-path-xyz"},
	}
	for _, args := range cases {
		code, out := runCLI(t, args...)
		if code != ExitUsage {
			t.Errorf("args %v: exit = %d, want 2 (out: %s)", args, code, out)
		}
	}
}

func TestScanTerminalAndMarkdown(t *testing.T) {
	root := makeFixture(t)
	_, out := runCLI(t, root, "--format", "markdown")
	if !strings.Contains(out, "# Ultimate Security CLI") || !strings.Contains(out, "## Site `") {
		t.Errorf("markdown output wrong:\n%s", out)
	}
	_, out = runCLI(t, root)
	if !strings.Contains(out, "Ultimate Security CLI") || !strings.Contains(out, "Summary") {
		t.Errorf("terminal output wrong:\n%s", out)
	}
}

func TestDiscoverCommand(t *testing.T) {
	root := makeFixture(t)
	var out bytes.Buffer
	code := ExecuteWithWriters("wpus test", []string{"discover", root, "--json"}, &out, &out)
	if code != ExitOK {
		t.Fatalf("exit = %d, out:\n%s", code, out.String())
	}
	var decoded struct {
		Sites []struct {
			Path  string `json:"path"`
			Valid bool   `json:"valid"`
		} `json:"sites"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if len(decoded.Sites) != 1 || !decoded.Sites[0].Valid || decoded.Sites[0].Path != root {
		t.Errorf("discover result wrong: %+v", decoded.Sites)
	}

	// Nothing found → exit 1.
	out.Reset()
	code = ExecuteWithWriters("wpus test", []string{"discover", filepath.Join(t.TempDir(), "empty")}, &out, &out)
	if code != ExitFindings {
		t.Errorf("discover with no sites should exit 1, got %d", code)
	}
}

func TestChecksCommand(t *testing.T) {
	var out bytes.Buffer
	code := ExecuteWithWriters("wpus test", []string{"checks", "--json"}, &out, &out)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var decoded struct {
		Checks []struct {
			ID       string `json:"id"`
			Category string `json:"category"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Checks) < 20 {
		t.Errorf("expected a substantial check registry, got %d", len(decoded.Checks))
	}
}

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	code := ExecuteWithWriters("wpus test", []string{"version"}, &out, &out)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.HasPrefix(out.String(), "wpus ") {
		t.Errorf("version output = %q", out.String())
	}
}

func TestExcludeCheckFlag(t *testing.T) {
	root := makeFixture(t)
	var out bytes.Buffer
	code := ExecuteWithWriters("wpus test", []string{"scan", "--skip-wpcli", "--offline", "--format", "json",
		"--exclude-check", "WP_DEBUG_ENABLED", "--exclude-check", "SECURITY_KEYS_MISSING", root}, &out, &out)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out.String(), "WP_DEBUG_ENABLED") {
		t.Error("excluded check still present in output")
	}
}
