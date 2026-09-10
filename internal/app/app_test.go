package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/probe"
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

// runCLI runs the CLI hermetically: no network, no WP-CLI, no config file.
func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	return runRaw(t, append([]string{"scan", "--offline", "--no-config"}, args...)...)
}

// runRaw runs the CLI with exactly the given arguments, for tests that supply
// their own policy file. Streams are separate, as they are in production:
// stdout carries the report, stderr carries diagnostics.
func runRaw(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, diagnostics bytes.Buffer
	code := ExecuteWithWriters("wpus test", args, &out, &diagnostics)
	if testing.Verbose() && diagnostics.Len() > 0 {
		t.Logf("stderr: %s", diagnostics.String())
	}
	return code, out.String()
}

func decodeReport(t *testing.T, out string) reporting.Report {
	t.Helper()
	var report reporting.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	return report
}

func TestScanJSONExitCodes(t *testing.T) {
	root := makeFixture(t)

	code, out := runCLI(t, root, "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	report := decodeReport(t, out)
	if len(report.Sites) != 1 || report.Sites[0].Path != root {
		t.Fatalf("unexpected sites: %+v", report.Sites)
	}
	if report.SchemaVersion != reporting.SchemaVersion {
		t.Errorf("schema = %q", report.SchemaVersion)
	}
	// Risk and coverage are separate, and a static offline scan must not claim
	// complete coverage.
	site := report.Sites[0]
	if site.RiskScore < 0 || site.RiskScore > 100 {
		t.Errorf("risk score out of range: %d", site.RiskScore)
	}
	if site.CoverageScore >= 100 {
		t.Errorf("an offline static scan cannot have full coverage, got %d", site.CoverageScore)
	}
	if site.Confidence == "" || site.Coverage.Total == 0 {
		t.Errorf("coverage detail missing: %+v", site.Coverage)
	}
	if len(site.Coverage.Gaps) == 0 {
		t.Error("coverage gaps must be listed when checks cannot be determined")
	}
	if report.Summary.Unknown == 0 && report.Summary.Skipped == 0 {
		t.Error("summary must count skipped/unknown explicitly")
	}

	ids := map[string]bool{}
	for _, f := range site.Findings {
		if f.Status == "failed" {
			ids[f.ID] = true
		}
	}
	for _, want := range []string{"WP_DEBUG_ENABLED", "SECURITY_KEYS_MISSING", "DEFAULT_DATABASE_PREFIX", "EXPOSED_DEBUG_LOG", "EXPOSED_BACKUP_FILE", "PHP_EXECUTION_IN_UPLOADS"} {
		if !ids[want] {
			t.Errorf("expected failed finding %s (got %v)", want, ids)
		}
	}
	// Every finding carries a stable identity for diffing.
	for _, f := range site.Findings {
		if f.Fingerprint == "" {
			t.Errorf("finding %s has no fingerprint", f.ID)
		}
	}

	if strings.Contains(out, "FixtureSecret42!") {
		t.Error("DB_PASSWORD leaked into JSON output")
	}

	code, _ = runCLI(t, root, "--format", "json", "--fail-on", "low")
	if code != ExitFindings {
		t.Errorf("--fail-on low should exit 1, got %d", code)
	}
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

// TestZeroTargetsFailsTheRun pins the CI-safety property: a scan that found
// nothing must not look like a successful scan unless the operator says so.
func TestZeroTargetsFailsTheRun(t *testing.T) {
	var out, diagnostics bytes.Buffer
	code := ExecuteWithWriters("wpus test", []string{
		"scan", "--offline", "--timeout", "1ms", "--exclude", "/nonexistent-root",
	}, &out, &diagnostics)
	if code != ExitNoTargets {
		t.Fatalf("exit = %d, want %d (no targets)\n%s", code, ExitNoTargets, out.String())
	}

	out.Reset()
	diagnostics.Reset()
	code = ExecuteWithWriters("wpus test", []string{
		"scan", "--offline", "--timeout", "1ms", "--exclude", "/nonexistent-root", "--allow-empty", "--format", "json",
	}, &out, &diagnostics)
	if code != ExitOK {
		t.Fatalf("--allow-empty should exit 0, got %d\n%s", code, out.String())
	}
	// Machine consumers must get arrays, never null, for list fields.
	if !strings.Contains(out.String(), `"sites": []`) {
		t.Errorf("an empty scan must emit an empty sites array, got:\n%s", out.String())
	}
	var raw struct {
		Sites []any `json:"sites"`
	}
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Sites == nil {
		t.Error("sites decoded as null; lists must always be arrays")
	}
	report := decodeReport(t, out.String())
	if report.Meta["note"] == "" {
		t.Error("an empty scan must still report why it was empty")
	}
	if report.Scan.Discovery == nil {
		t.Error("discovery accounting should be reported so an empty result is interpretable")
	}
}

func TestScanTerminalAndMarkdown(t *testing.T) {
	root := makeFixture(t)
	_, out := runCLI(t, root, "--format", "markdown")
	if !strings.Contains(out, "# Ultimate Security CLI") || !strings.Contains(out, "## Site `") {
		t.Errorf("markdown output wrong:\n%s", out)
	}
	if !strings.Contains(out, "Coverage") {
		t.Errorf("markdown must state coverage:\n%s", out)
	}
	_, out = runCLI(t, root)
	if !strings.Contains(out, "Ultimate Security CLI") || !strings.Contains(out, "Summary") {
		t.Errorf("terminal output wrong:\n%s", out)
	}
}

func TestSARIFAndOutputFile(t *testing.T) {
	root := makeFixture(t)
	outFile := filepath.Join(t.TempDir(), "report.sarif")

	var out bytes.Buffer
	code := ExecuteWithWriters("wpus test", []string{
		"scan", "--offline", "--no-config",
		"--format", "sarif", "--output", outFile, root,
	}, &out, &out)
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, out.String())
	}
	if strings.Contains(out.String(), "ruleId") {
		t.Error("--output must keep the report off stdout")
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("report file missing: %v", err)
	}
	var sarif struct {
		Version string `json:"version"`
		Runs    []any  `json:"runs"`
	}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("SARIF file is not valid JSON: %v", err)
	}
	if sarif.Version != "2.1.0" || len(sarif.Runs) != 1 {
		t.Errorf("SARIF shape wrong: %s %d runs", sarif.Version, len(sarif.Runs))
	}

	// Writing a report inside the audited tree must be refused: the scan is
	// read-only, and a report in a web root is its own information leak. The
	// relative-path form is the one that regressed in the field (discovery
	// returns the path as given), so the case scans the site by its basename
	// from the parent directory, exactly as an operator would.
	leak := filepath.Join(root, "leak.json")
	var out2 bytes.Buffer
	code = ExecuteWithWriters("wpus test", []string{
		"scan", "--offline", "--no-config",
		"--format", "json", "--output", leak, root,
	}, &out2, &out2)
	if code != ExitUsage {
		t.Errorf("writing a report into the site should be a usage error, got %d: %s", code, out2.String())
	}
	if _, err := os.Stat(leak); err == nil {
		t.Error("report was written into the audited site")
	}

	base := filepath.Base(root)
	t.Chdir(filepath.Dir(root))
	var out3 bytes.Buffer
	code = ExecuteWithWriters("wpus test", []string{
		"scan", "--offline", "--no-config",
		"--format", "json", "--output", filepath.Join(base, "relative-leak.json"), base,
	}, &out3, &out3)
	if code != ExitUsage {
		t.Errorf("a relative site path must not defeat the output guard, got %d: %s", code, out3.String())
	}
	if _, err := os.Stat(filepath.Join(root, "relative-leak.json")); err == nil {
		t.Error("report was written into the relatively-addressed site")
	}
}

// TestStaticScanNeverExecutesTargetPHP is the scanner's trust-boundary test: a
// fake WP-CLI binary records every invocation, and only --live may run it.
func TestStaticScanNeverExecutesTargetPHP(t *testing.T) {
	root := makeFixture(t)
	marker := filepath.Join(t.TempDir(), "executed")
	wp := filepath.Join(t.TempDir(), "wp")
	script := "#!/bin/sh\ntouch " + marker + "\necho 6.4.1\nexit 1\n"
	if err := os.WriteFile(wp, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WPUS_WP_CLI", wp)

	// Default: static. The target's PHP is never executed.
	code, out := runCLI(t, root, "--format", "json")
	if code != ExitOK {
		t.Fatalf("static scan failed: %d\n%s", code, out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the static scan executed the audited site's code (WP-CLI ran without --live)")
	}

	// --live: WP-CLI is expected to run.
	var liveOut bytes.Buffer
	code = ExecuteWithWriters("wpus test", []string{
		"scan", "--no-config", "--live", "--offline", "--format", "json", root,
	}, &liveOut, &liveOut)
	if code != ExitOK {
		t.Fatalf("live scan failed: %d\n%s", code, liveOut.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("--live did not run WP-CLI; the flag is not wired to the runner")
	}
	if !strings.Contains(liveOut.String(), `"live": true`) {
		t.Error("a live scan must disclose that it executed target code")
	}
}

// TestProjectConfigIsNotTrustedByDefault is the policy-poisoning fixture: a
// scanned directory cannot disable its own checks.
func TestProjectConfigIsNotTrustedByDefault(t *testing.T) {
	root := makeFixture(t)
	poison := "fail_on: critical\nchecks:\n  disabled:\n    - WP_DEBUG_ENABLED\n"
	if err := os.WriteFile(filepath.Join(root, ".wpus.yaml"), []byte(poison), 0o644); err != nil {
		t.Fatal(err)
	}
	// The attack is an operator (or agent) running the scan from inside the
	// untrusted directory, so the working directory is the site itself.
	t.Chdir(root)

	run := func(extra ...string) (int, string) {
		args := append([]string{"scan", "--offline", "--format", "json"}, extra...)
		args = append(args, root)
		var buf bytes.Buffer
		code := ExecuteWithWriters("wpus test", args, &buf, &buf)
		return code, buf.String()
	}

	code, out := run()
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, out)
	}
	if !strings.Contains(out, "WP_DEBUG_ENABLED") {
		t.Error("a project-local config disabled a check without --trust-project-config")
	}

	// Even when trusted, the report must disclose where the policy came from.
	code, out = run("--trust-project-config")
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, out)
	}
	report := decodeReport(t, out)
	if !report.Scan.ProjectConfig || report.Scan.ConfigPath == "" {
		t.Errorf("trusted project config must be disclosed in the report: %+v", report.Scan)
	}
}

// TestTrustedConfigSuppressionIsDisclosed pins that a suppression hides a
// finding from scoring while keeping it visible in the report.
func TestTrustedConfigSuppressionIsDisclosed(t *testing.T) {
	root := makeFixture(t)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	content := "suppressions:\n  - id: WP_DEBUG_ENABLED\n    reason: local development fixture\n"
	if err := os.WriteFile(cfg, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, baselineJSON := runCLI(t, root, "--format", "json")
	baseline := decodeReport(t, baselineJSON)

	code, out := runRaw(t, "scan", "--offline", "--format", "json", "--config", cfg, root)
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, out)
	}
	report := decodeReport(t, out)
	if report.Summary.Suppressed != 1 {
		t.Errorf("suppressed count = %d, want 1", report.Summary.Suppressed)
	}
	var found bool
	for _, f := range report.Sites[0].Findings {
		if f.ID == "WP_DEBUG_ENABLED" {
			found = true
			if !f.Suppressed || f.SuppressionReason == "" {
				t.Errorf("suppression must be recorded on the finding: %+v", f)
			}
		}
	}
	if !found {
		t.Error("a suppressed finding must stay in the report, not be deleted")
	}
	// The suppression must also remove the finding's weight from the score,
	// while leaving every other finding untouched.
	if report.Sites[0].RiskScore <= baseline.Sites[0].RiskScore {
		t.Errorf("suppression did not change the risk score: %d vs %d",
			report.Sites[0].RiskScore, baseline.Sites[0].RiskScore)
	}
}

// TestUnknownCheckIDIsRejected pins that a typo cannot silently disable a
// security check.
func TestUnknownCheckIDIsRejected(t *testing.T) {
	root := makeFixture(t)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("checks:\n  disabled:\n    - PLUGIN_VULNERABLITY\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	code := ExecuteWithWriters("wpus test", []string{"scan", "--offline", "--config", cfg, "--format", "json", root}, &out, &diagnostics)
	if code != ExitUsage {
		t.Fatalf("a misspelled check ID must be a usage error, got %d: %s", code, out.String())
	}
	if !strings.Contains(diagnostics.String(), "PLUGIN_VULNERABLITY") {
		t.Errorf("the error must name the offending ID: %s", diagnostics.String())
	}

	diagnostics.Reset()
	code = ExecuteWithWriters("wpus test", []string{"scan", "--offline", "--no-config", "--exclude-check", "NOT_A_CHECK", root}, &out, &diagnostics)
	if code != ExitUsage {
		t.Errorf("--exclude-check with an unknown ID must fail, got %d: %s", code, diagnostics.String())
	}
}

// TestOutputIsInjectionSafe creates a real file whose name carries terminal
// and Markdown metacharacters, then checks that no reporter emits them.
func TestOutputIsInjectionSafe(t *testing.T) {
	root := makeFixture(t)
	hostile := "evil`|`\x1b]8;;http://attacker.example\x07backup.sql"
	if err := os.WriteFile(filepath.Join(root, hostile), []byte("dump"), 0o644); err != nil {
		t.Skipf("filesystem rejects the hostile name: %v", err)
	}
	for _, format := range []string{"terminal", "markdown", "json"} {
		_, out := runCLI(t, root, "--format", format)
		if strings.Contains(out, "\x1b]8;;") {
			t.Errorf("%s output carried a target-controlled OSC sequence", format)
		}
		if strings.Contains(out, "\x07") {
			t.Errorf("%s output carried a target-controlled BEL", format)
		}
		if format == "markdown" && strings.Contains(out, "http://attacker.example") {
			t.Errorf("%s output leaked the injected hyperlink target", format)
		}
	}
}

// TestSeverityFilterKeepsCoverageHonest pins that a filtered report still
// scores and describes everything that ran.
func TestSeverityFilterKeepsCoverageHonest(t *testing.T) {
	root := makeFixture(t)
	_, full := runCLI(t, root, "--format", "json")
	_, filtered := runCLI(t, root, "--format", "json", "--severity", "high")
	base := decodeReport(t, full)
	got := decodeReport(t, filtered)
	if got.Sites[0].Coverage.Total != base.Sites[0].Coverage.Total {
		t.Errorf("filtering must not change reported coverage: %d vs %d",
			got.Sites[0].Coverage.Total, base.Sites[0].Coverage.Total)
	}
	if got.Sites[0].CoverageScore != base.Sites[0].CoverageScore {
		t.Errorf("filtering must not change the coverage score: %d vs %d",
			got.Sites[0].CoverageScore, base.Sites[0].CoverageScore)
	}
	for _, f := range got.Sites[0].Findings {
		if f.Status != "failed" || f.Severity.Rank() < 3 {
			t.Errorf("filtered report contains a non-high finding: %+v", f)
		}
	}
}

// TestCoverageFloorPolicy covers --fail-on-coverage-below.
func TestCoverageFloorPolicy(t *testing.T) {
	root := makeFixture(t)
	code, out := runCLI(t, root, "--format", "json", "--fail-on-coverage-below", "1")
	if code == ExitFindings {
		t.Fatalf("coverage 1%% should never fail: %d\n%s", code, out)
	}
	code, out = runCLI(t, root, "--format", "json", "--fail-on-coverage-below", "100")
	if code != ExitFindings {
		t.Fatalf("coverage below 100%% must fail the run, got %d\n%s", code, out)
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
			ID         string `json:"id"`
			Category   string `json:"category"`
			Importance string `json:"importance"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Checks) < 40 {
		t.Errorf("expected the expanded check registry, got %d", len(decoded.Checks))
	}
	// Importance drives the coverage score, so the machine-readable registry
	// must publish it, and the levels must stay the documented set.
	counts := map[string]int{}
	for _, c := range decoded.Checks {
		switch c.Importance {
		case "core", "standard", "context":
			counts[c.Importance]++
		default:
			t.Errorf("check %s has unexpected importance %q", c.ID, c.Importance)
		}
	}
	for _, level := range []string{"core", "standard", "context"} {
		if counts[level] == 0 {
			t.Errorf("no check carries %q importance", level)
		}
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
	code := ExecuteWithWriters("wpus test", []string{"scan", "--offline", "--no-config",
		"--format", "json", "--exclude-check", "WP_DEBUG_ENABLED", "--exclude-check", "SECURITY_KEYS_MISSING", root}, &out, &out)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	// The report deliberately discloses which checks policy disabled, so the
	// assertion is on the findings themselves.
	report := decodeReport(t, out.String())
	for _, f := range report.Sites[0].Findings {
		if f.ID == "WP_DEBUG_ENABLED" || f.ID == "SECURITY_KEYS_MISSING" {
			t.Errorf("excluded check still produced a finding: %+v", f)
		}
	}
	var disabled []string
	disabled = append(disabled, report.Scan.DisabledChecks...)
	if len(disabled) != 2 {
		t.Errorf("the report must disclose the disabled checks, got %v", disabled)
	}
}

// TestProberPolicyForSiteURL pins the SSRF policy construction: probes are
// pinned to the site's own origin, private targets only for local installs,
// and metadata hosts are never reachable.
func TestProberPolicyForSiteURL(t *testing.T) {
	p := proberFor("https://example.com", false)
	if p == nil {
		t.Fatal("expected a prober for a public https site")
	}
	if !p.OriginAllowed("https://example.com/wp-json/") {
		t.Error("the site's own origin must be allowed")
	}
	if p.OriginAllowed("http://169.254.169.254/latest/meta-data/") {
		t.Error("a metadata endpoint must never be allowed")
	}
	if p.OriginAllowed("https://attacker.example/") {
		t.Error("a foreign origin must not be allowed")
	}
	if proberFor("", false) != nil {
		t.Error("no site URL means no prober")
	}
	if proberFor("https://example.com", true) != nil {
		t.Error("offline scans must not build a prober")
	}

	// A local development site may reach loopback, and only loopback.
	local := proberFor("http://localhost:8080", false)
	if local == nil {
		t.Fatal("expected a prober for a local site")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/", nil)
	if req == nil {
		t.Fatal("request build failed")
	}
	var blocked *probe.BlockedError
	if err := local.OriginAllowed("http://127.0.0.1:9999/"); err != false {
		t.Error("a different loopback port is a different origin")
	}
	_ = blocked
}

// TestVerboseLoggingSanitizesTargetOutput pins that WP-CLI's stderr — which is
// target-controlled text — cannot inject escape sequences into the operator's
// terminal and cannot echo a value read from wp-config.php.
func TestVerboseLoggingSanitizesTargetOutput(t *testing.T) {
	root := makeFixture(t)
	wp := filepath.Join(t.TempDir(), "wp")
	// A hostile WP-CLI: an OSC hyperlink, a BEL, a newline, and a secret read
	// from the site configuration.
	script := "#!/bin/sh\n" +
		"printf '\\033]8;;http://attacker.example\\007click\\033]8;;\\007\\nFixtureSecret42!\\n' >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(wp, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WPUS_WP_CLI", wp)

	var out, errBuf bytes.Buffer
	code := ExecuteWithWriters("wpus test", []string{
		"scan", "--no-config", "--offline", "--live", "--verbose", root,
	}, &out, &errBuf)
	if code != ExitOK {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	logged := errBuf.String()
	for _, bad := range []string{"\x1b]8;;", "\x07", "FixtureSecret42!"} {
		if strings.Contains(logged, bad) {
			t.Errorf("verbose log carried target-controlled content %q:\n%s", bad, logged)
		}
	}
	if !strings.Contains(logged, "wp ") {
		t.Errorf("the WP-CLI failure should still be logged (sanitized):\n%s", logged)
	}
}
