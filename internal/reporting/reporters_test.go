package reporting

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/platform"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/scoring"
)

func sampleReport() *Report {
	start := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	return &Report{
		SchemaVersion: SchemaVersion,
		Tool:          ToolInfo{Name: "wpus", Version: "0.1.0"},
		Environment:   platform.Info{OS: "darwin", Arch: "arm64"},
		Scan:          ScanInfo{StartedAt: start, DurationMs: 1234, ChecksRun: 30},
		Sites: []SiteReport{
			{
				Path:          "/var/www/example.com",
				WordPress:     "6.8.2",
				PHP:           "8.2.10",
				Server:        "nginx",
				RiskScore:     78,
				CoverageScore: 85,
				Confidence:    string(checks.ConfMedium),
				Coverage: scoring.Coverage{
					Score: 85, Determined: 26, Total: 30, Confidence: string(checks.ConfMedium),
					Gaps: []scoring.Gap{{CheckID: "PLUGIN_OUTDATED", Status: "skipped", Reason: "WP-CLI unavailable", Importance: 2}},
				},
				Categories: map[string]int{
					"wordpress-config": 90,
					"plugins":          61,
				},
				Findings: []checks.Finding{
					{
						ID: "WP_DEBUG_ENABLED", Title: "WP_DEBUG is enabled",
						Category: checks.CatConfig, Severity: checks.SevMedium,
						Status: checks.StatusFailed, Confidence: checks.ConfHigh,
						Description:    "Debugging is enabled.",
						Evidence:       map[string]string{"file": "wp-config.php"},
						Recommendation: "Disable WP_DEBUG.",
						References:     []string{"https://developer.wordpress.org/debugging-in-wordpress/"},
						Fingerprint:    "abcd1234abcd1234",
					},
					{
						ID: "PLUGIN_VULNERABILITY", Title: "Vulnerable plugin",
						Category: checks.CatPlugins, Severity: checks.SevHigh,
						Status: checks.StatusFailed, Confidence: checks.ConfHigh,
						Description: "1 plugin matches known vulnerabilities.",
						Occurrences: []checks.Occurrence{{
							ResourceType: "plugin", Slug: "broke", Version: "1.0.0",
							AdvisoryID: "adv-1", CVE: "CVE-2026-0001", Severity: "critical",
							FixedIn: []string{"1.0.1"}, Provider: "stub",
						}},
					},
					{
						ID: "FILE_EDITOR_ENABLED", Title: "File editor disabled",
						Category: checks.CatConfig, Severity: checks.SevInfo,
						Status: checks.StatusPassed, Confidence: checks.ConfHigh,
						Description: "DISALLOW_FILE_EDIT set.",
					},
					{
						ID: "XMLRPC_ENABLED", Title: "XML-RPC state unknown",
						Category: checks.CatHardening, Severity: checks.SevInfo,
						Status: checks.StatusSkipped, Confidence: checks.ConfHigh,
						Description: "Requires WP-CLI.",
					},
					{
						ID: "ADMIN_USERNAME", Title: "Accepted risk",
						Category: checks.CatAuth, Severity: checks.SevMedium,
						Status: checks.StatusFailed, Confidence: checks.ConfHigh,
						Description: "Admin login in use.", Suppressed: true,
						SuppressionReason: "documented exception",
					},
				},
			},
		},
		Summary: Summary{SitesScanned: 1, High: 1, Medium: 1, Passed: 1, Skipped: 1, Suppressed: 1},
	}
}

func TestJSONOutputIsParseableAndStable(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out1 := buf.String()

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded["schema_version"] != "2.0" {
		t.Errorf("schema_version = %v", decoded["schema_version"])
	}
	// Deterministic: identical bytes on re-render.
	buf.Reset()
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if buf.String() != out1 {
		t.Error("JSON output not deterministic")
	}
	if strings.ContainsAny(out1, "\x1b") {
		t.Error("JSON output contains ANSI escapes")
	}
	sites, _ := decoded["sites"].([]any)
	site0, _ := sites[0].(map[string]any)
	// Risk and coverage are separate, and coverage is never implied by risk.
	for _, key := range []string{"risk_score", "coverage_score", "confidence", "coverage"} {
		if _, ok := site0[key]; !ok {
			t.Errorf("site JSON missing key %q", key)
		}
	}
	findings, _ := site0["findings"].([]any)
	f0, _ := findings[0].(map[string]any)
	for _, key := range []string{"id", "title", "category", "severity", "status", "confidence", "description", "evidence", "recommendation", "references", "fingerprint"} {
		if _, ok := f0[key]; !ok {
			t.Errorf("finding JSON missing key %q", key)
		}
	}
	// Structured occurrences replace the joined string for vulnerability rows.
	f1, _ := findings[1].(map[string]any)
	occ, ok := f1["occurrences"].([]any)
	if !ok || len(occ) != 1 {
		t.Fatalf("vulnerability finding should carry structured occurrences: %v", f1["occurrences"])
	}
	// Suppression is explicit and reversible by a consumer.
	f4, _ := findings[4].(map[string]any)
	if f4["suppressed"] != true || f4["suppression_reason"] != "documented exception" {
		t.Errorf("suppression not represented: %v", f4)
	}
}

func TestMarkdownOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	for _, want := range []string{
		"# Ultimate Security CLI",
		"## Summary",
		"| Critical | 0 |",
		"| High | 1 |",
		"| Unknown | 0 |",
		"| Suppressed | 1 |",
		"## Site `/var/www/example.com`",
		"| **Risk score** | **78 / 100** |",
		"| **Coverage** | **85%**",
		"### [HIGH] Vulnerable plugin",
		"### [MEDIUM] WP_DEBUG is enabled",
		"`WP_DEBUG_ENABLED`",
		"**Recommendation:** Disable WP_DEBUG.",
		"### Not determined",
		"WP-CLI unavailable",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if strings.Contains(md, "### [INFO] File editor disabled") {
		t.Error("passed finding should not render as failed section")
	}
	if !strings.Contains(md, "_(suppressed)_") {
		t.Error("suppressed finding should be labelled")
	}
}

func TestTerminalOutput(t *testing.T) {
	rep := sampleReport()

	var buf bytes.Buffer
	term := Terminal{Opts: TerminalOptions{Color: false}}
	if err := term.Write(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Error("terminal emitted ANSI color with color disabled")
	}
	for _, want := range []string{
		"Ultimate Security CLI",
		"Path",
		"/var/www/example.com",
		"78/100",
		"Coverage 85%",
		"HIGH",
		"Vulnerable plugin",
		"Recommendation",
		"Summary",
		"Suppressed",
		"suppressed: documented exception",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q", want)
		}
	}

	buf.Reset()
	colorTerm := Terminal{Opts: TerminalOptions{Color: true}}
	if err := colorTerm.Write(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Error("colored terminal output lacks ANSI codes")
	}
	if !regexp.MustCompile(`78/100`).MatchString(stripANSI(buf.String())) {
		t.Error("score text corrupted by color handling")
	}
}

// TestTerminalWarnsOnLowCoverage pins the property that a high score is never
// presented as "secure" when most checks could not run.
func TestTerminalWarnsOnLowCoverage(t *testing.T) {
	rep := sampleReport()
	rep.Sites[0].CoverageScore = 40
	rep.Sites[0].Coverage = scoring.Coverage{Score: 40, Determined: 12, Total: 30}
	var buf bytes.Buffer
	if err := (Terminal{}).Write(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Incomplete:") {
		t.Errorf("low coverage must be called out:\n%s", buf.String())
	}
}

func TestTerminalQuiet(t *testing.T) {
	var buf bytes.Buffer
	term := Terminal{Opts: TerminalOptions{Quiet: true}}
	if err := term.Write(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "Ultimate Security CLI\n") || strings.Contains(out, "Summary") {
		t.Errorf("quiet mode should suppress banner/summary: %q", out)
	}
	if !strings.Contains(out, "/var/www/example.com") {
		t.Errorf("quiet mode keeps one-line site summary: %q", out)
	}
	if !strings.Contains(out, "coverage 85%") {
		t.Errorf("quiet mode must keep the coverage figure: %q", out)
	}
}

func TestSARIFOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			OriginalURIBaseID map[string]struct {
				URI string `json:"uri"`
			} `json:"originalUriBaseIds"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Suppressions        []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif") {
		t.Fatalf("SARIF header wrong: %s %s", log.Version, log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected one run per site, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "wpus" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if got := run.OriginalURIBaseID["SITE"].URI; got != "file:///var/www/example.com/" {
		t.Errorf("uri base = %q", got)
	}
	if len(run.Tool.Driver.Rules) != len(run.Results) {
		t.Fatalf("rules (%d) and results (%d) disagree", len(run.Tool.Driver.Rules), len(run.Results))
	}
	if len(run.Results) != 3 { // two failed plus one suppressed
		t.Fatalf("expected 3 results, got %d", len(run.Results))
	}
	ruleIDs := map[string]int{}
	for i, r := range run.Tool.Driver.Rules {
		ruleIDs[r.ID] = i
	}
	for _, res := range run.Results {
		if idx, ok := ruleIDs[res.RuleID]; !ok || idx != res.RuleIndex {
			t.Errorf("result %s: ruleIndex %d does not match the rules table", res.RuleID, res.RuleIndex)
		}
		if res.Message.Text == "" {
			t.Errorf("result %s has an empty message", res.RuleID)
		}
		if res.RuleID == "WP_DEBUG_ENABLED" {
			if res.Level != "warning" {
				t.Errorf("medium severity should map to warning, got %s", res.Level)
			}
			if len(res.Locations) != 1 || res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "wp-config.php" {
				t.Errorf("expected a site-relative location: %+v", res.Locations)
			}
			if res.PartialFingerprints["wpus/v1"] != "abcd1234abcd1234" {
				t.Errorf("fingerprint not carried into SARIF: %+v", res.PartialFingerprints)
			}
		}
		if res.RuleID == "ADMIN_USERNAME" && len(res.Suppressions) != 1 {
			t.Errorf("suppressed finding must carry a SARIF suppression: %+v", res)
		}
	}
}

// TestOutputInjectionCannotRestructureReports is the adversarial fixture for
// the reporting layer: a hostile plugin name, path, or evidence value must not
// be able to inject terminal escapes, break a Markdown table, or terminate a
// code span.
func TestOutputInjectionCannotRestructureReports(t *testing.T) {
	hostile := "evil\x1b]8;;http://attacker.example\x07name\x1b]8;;\x07\n| injected | row |\n`code` <script>alert(1)</script>"
	rep := sampleReport()
	rep.Sites[0].Findings = []checks.Finding{{
		ID: "PLUGIN_VULNERABILITY", Title: hostile, Category: checks.CatPlugins,
		Severity: checks.SevHigh, Status: checks.StatusFailed, Confidence: checks.ConfHigh,
		Description: hostile,
		Evidence:    map[string]string{"matches": hostile},
		Occurrences: []checks.Occurrence{{ResourceType: "plugin", Slug: hostile, Version: hostile}},
	}}

	var term bytes.Buffer
	if err := (Terminal{Opts: TerminalOptions{Color: true}}).Write(&term, rep); err != nil {
		t.Fatal(err)
	}
	// Colour codes are ours; any other escape sequence is the payload's.
	if strings.Contains(term.String(), "]8;;") {
		t.Error("terminal output carried a target-controlled OSC sequence")
	}
	if strings.Contains(term.String(), "\x07") {
		t.Error("terminal output carried a target-controlled BEL")
	}

	var md bytes.Buffer
	if err := WriteMarkdown(&md, rep); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script>", "http://attacker.example", "\x1b", "\x07"} {
		if strings.Contains(md.String(), bad) {
			t.Errorf("markdown output carried hostile content %q", bad)
		}
	}
	// The table must keep exactly the header, separator, and one data row per
	// occurrence: a payload newline must not add rows.
	rows := 0
	for _, line := range strings.Split(md.String(), "\n") {
		if strings.HasPrefix(line, "| plugin ") {
			rows++
		}
	}
	if rows != 1 {
		t.Errorf("occurrence table gained rows from injected content: %d", rows)
	}
}

func TestTally(t *testing.T) {
	s := Tally(sampleReport().Sites)
	if s.SitesScanned != 1 || s.High != 1 || s.Medium != 1 || s.Passed != 1 || s.Skipped != 1 || s.Suppressed != 1 {
		t.Errorf("tally wrong: %+v", s)
	}
}

func TestTallyCountsUnknownSeparately(t *testing.T) {
	sites := []SiteReport{{Findings: []checks.Finding{
		{ID: "A", Status: checks.StatusUnknown, Severity: checks.SevInfo},
		{ID: "B", Status: checks.StatusSkipped, Severity: checks.SevInfo},
	}}}
	got := Tally(sites)
	if got.Unknown != 1 || got.Skipped != 1 {
		t.Errorf("unknown and skipped must be counted separately: %+v", got)
	}
}

func stripANSI(s string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(s, "")
}
