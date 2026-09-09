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
				Path:      "/var/www/example.com",
				WordPress: "6.8.2",
				PHP:       "8.2.10",
				Server:    "nginx",
				Score:     78,
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
					},
					{
						ID: "PLUGIN_VULNERABILITY", Title: "Vulnerable plugin",
						Category: checks.CatPlugins, Severity: checks.SevHigh,
						Status: checks.StatusFailed, Confidence: checks.ConfHigh,
						Description: "1 plugin matches known vulnerabilities.",
					},
					{
						ID: "FILE_EDITOR_ENABLED", Title: "File editor disabled",
						Category: checks.CatConfig, Severity: checks.SevInfo,
						Status: checks.StatusPassed, Confidence: checks.ConfHigh,
						Description: "DISALLOW_FILE_EDIT set.",
					},
					{
						ID: "XMLRPC_ENABLED", Title: "XML-RPC state unknown",
						Category: checks.CatHardning, Severity: checks.SevInfo,
						Status: checks.StatusSkipped, Confidence: checks.ConfHigh,
						Description: "Requires WP-CLI.",
					},
				},
			},
		},
		Summary: Summary{SitesScanned: 1, High: 1, Medium: 1, Passed: 1, Skipped: 1},
	}
}

func TestJSONOutputIsParseableAndStable(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out1 := buf.String()

	// Parseable with encoding/json.
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded["schema_version"] != "1.0" {
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
	// No ANSI escapes in JSON output.
	if strings.ContainsAny(out1, "\x1b") {
		t.Error("JSON output contains ANSI escapes")
	}
	// Finding shape matches the documented schema.
	sites, _ := decoded["sites"].([]any)
	site0, _ := sites[0].(map[string]any)
	findings, _ := site0["findings"].([]any)
	f0, _ := findings[0].(map[string]any)
	for _, key := range []string{"id", "title", "category", "severity", "status", "confidence", "description", "evidence", "recommendation", "references"} {
		if _, ok := f0[key]; !ok {
			t.Errorf("finding JSON missing key %q", key)
		}
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
		"## Site `/var/www/example.com`",
		"**Score** | **78 / 100**",
		"### [HIGH] Vulnerable plugin",
		"### [MEDIUM] WP_DEBUG is enabled",
		"`WP_DEBUG_ENABLED`",
		"**Recommendation:** Disable WP_DEBUG.",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	// Passed/skipped findings are not rendered as findings sections.
	if strings.Contains(md, "### [INFO] File editor disabled") {
		t.Error("passed finding should not render as failed section")
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
		"HIGH",
		"Vulnerable plugin",
		"Recommendation",
		"Summary",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q", want)
		}
	}

	// Color mode emits escape codes.
	buf.Reset()
	colorTerm := Terminal{Opts: TerminalOptions{Color: true}}
	if err := colorTerm.Write(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Error("colored terminal output lacks ANSI codes")
	}
	// Score coloring must not corrupt the score text.
	if !regexp.MustCompile(`78/100`).MatchString(stripANSI(buf.String())) {
		t.Error("score text corrupted by color handling")
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
}

func stripANSI(s string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(s, "")
}

func TestTally(t *testing.T) {
	s := Tally(sampleReport().Sites)
	if s.SitesScanned != 1 || s.High != 1 || s.Medium != 1 || s.Passed != 1 || s.Skipped != 1 {
		t.Errorf("tally wrong: %+v", s)
	}
}
