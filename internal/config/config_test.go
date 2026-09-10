package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissing(t *testing.T) {
	cfg, src, err := Load(Options{ConfigDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != "" || len(cfg.Exclude) != 0 {
		t.Errorf("missing config must be zero-value: %+v", cfg)
	}
	if src.Path != "" {
		t.Errorf("source = %+v, want empty", src)
	}
}

func TestLoadValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	write(t, path, `fail_on: high
fail_on_coverage_below: 80
exclude:
  - /var/www/staging
checks:
  disabled:
    - XMLRPC_ENABLED
    - REST_USER_ENUMERATION
suppressions:
  - id: XMLRPC_ENABLED
    reason: Jetpack requires it
    expires: 2026-12-31
severity_overrides:
  DEFAULT_DATABASE_PREFIX: info
`)
	cfg, src, err := Load(Options{Explicit: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != "high" {
		t.Errorf("fail_on = %q", cfg.FailOn)
	}
	if cfg.FailOnCoverageBelow != 80 {
		t.Errorf("fail_on_coverage_below = %d", cfg.FailOnCoverageBelow)
	}
	if len(cfg.Exclude) != 1 || cfg.Exclude[0] != "/var/www/staging" {
		t.Errorf("exclude = %v", cfg.Exclude)
	}
	if len(cfg.Checks.Disabled) != 2 || cfg.Checks.Disabled[0] != "XMLRPC_ENABLED" {
		t.Errorf("disabled = %v", cfg.Checks.Disabled)
	}
	if len(cfg.Suppressions) != 1 || cfg.Suppressions[0].ID != "XMLRPC_ENABLED" || cfg.Suppressions[0].Reason == "" {
		t.Errorf("suppressions = %+v", cfg.Suppressions)
	}
	if cfg.SeverityOverrides["DEFAULT_DATABASE_PREFIX"] != "info" {
		t.Errorf("severity_overrides = %v", cfg.SeverityOverrides)
	}
	if src.Path != path || src.ProjectLocal {
		t.Errorf("source = %+v", src)
	}
}

func TestLoadMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	write(t, path, "fail_on: [unclosed\n  - broken")
	if _, _, err := Load(Options{Explicit: path}); err == nil {
		t.Error("malformed config must error")
	}
}

// TestLoadRejectsUnknownKeys pins the strict decoding contract: a typo in a
// policy key must fail loudly instead of silently doing nothing.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "typo.yaml")
	write(t, path, "fail_onn: high\n")
	if _, _, err := Load(Options{Explicit: path}); err == nil {
		t.Fatal("unknown top-level key must be rejected")
	}
	write(t, path, "checks:\n  disable:\n    - XMLRPC_ENABLED\n")
	if _, _, err := Load(Options{Explicit: path}); err == nil {
		t.Fatal("unknown nested key must be rejected")
	}
}

func TestLoadExplicitMissingIsError(t *testing.T) {
	if _, _, err := Load(Options{Explicit: filepath.Join(t.TempDir(), "absent.yaml")}); err == nil {
		t.Error("an explicitly requested config file that does not exist must error")
	}
}

// TestLoadDoesNotTrustProjectConfigByDefault pins the core trust property:
// an untrusted directory cannot configure its own audit.
func TestLoadDoesNotTrustProjectConfigByDefault(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	write(t, filepath.Join(dir, ".wpus.yaml"), "fail_on: critical\nchecks:\n  disabled:\n    - WP_DEBUG_ENABLED\n")
	cfg, src, err := Load(Options{ConfigDir: filepath.Join(dir, "user")})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Checks.Disabled) != 0 || cfg.FailOn != "" {
		t.Errorf("project config was honoured without --trust-project-config: %+v", cfg)
	}
	if src.Path != "" {
		t.Errorf("source = %+v", src)
	}
}

func TestLoadTrustsProjectConfigWhenAsked(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	write(t, filepath.Join(dir, ".wpus.yaml"), "fail_on: medium\n")
	cfg, src, err := Load(Options{ConfigDir: filepath.Join(dir, "user"), TrustProject: true})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != "medium" {
		t.Errorf("fail_on = %q", cfg.FailOn)
	}
	if !src.ProjectLocal || src.Path == "" {
		t.Errorf("source = %+v, want project-local", src)
	}
}

// TestUserConfigBeatsProjectConfig pins the documented precedence.
func TestUserConfigBeatsProjectConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	userDir := filepath.Join(dir, "user")
	write(t, filepath.Join(userDir, "config.yaml"), "fail_on: high\n")
	write(t, filepath.Join(dir, ".wpus.yaml"), "fail_on: critical\n")
	cfg, src, err := Load(Options{ConfigDir: userDir, TrustProject: true})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != "high" {
		t.Errorf("fail_on = %q, want the user config to win", cfg.FailOn)
	}
	if src.ProjectLocal {
		t.Error("source says project-local but the user config was used")
	}
}

func TestNoConfigSkipsEverything(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	write(t, path, "fail_on: high\n")
	cfg, _, err := Load(Options{Explicit: path, NoConfig: true})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != "" {
		t.Errorf("--no-config must ignore the file, got %+v", cfg)
	}
}

func TestSuppressionExpiry(t *testing.T) {
	// Suppressions last through the end of their expiry date.
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		expires string
		want    bool
	}{
		{"", false},
		{"2026-12-31", false},
		{"2026-09-10", true},
		{"2026-09-11", false},
		{"not-a-date", true},
	}
	for _, tc := range cases {
		got := Suppression{ID: "X", Expires: tc.expires}.Expired(now)
		if got != tc.want {
			t.Errorf("Expired(%q) = %v, want %v", tc.expires, got, tc.want)
		}
	}
}
