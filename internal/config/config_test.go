package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissing(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != "" || len(cfg.Exclude) != 0 {
		t.Errorf("missing config must be zero-value: %+v", cfg)
	}
}

func TestLoadValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".wpus.yaml")
	content := `fail_on: high
exclude:
  - /var/www/staging
checks:
  disabled:
    - XMLRPC_ENABLED
    - REST_USER_ENUMERATION
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != "high" {
		t.Errorf("fail_on = %q", cfg.FailOn)
	}
	if len(cfg.Exclude) != 1 || cfg.Exclude[0] != "/var/www/staging" {
		t.Errorf("exclude = %v", cfg.Exclude)
	}
	if len(cfg.Checks.Disabled) != 2 || cfg.Checks.Disabled[0] != "XMLRPC_ENABLED" {
		t.Errorf("disabled = %v", cfg.Checks.Disabled)
	}
}

func TestLoadMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	_ = os.WriteFile(path, []byte("fail_on: [unclosed\n  - broken"), 0o644)
	if _, err := Load(path); err == nil {
		t.Error("malformed config must error")
	}
}

func TestLoadFirstPrecedence(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	local := filepath.Join(dir, ".wpus.yaml")
	_ = os.WriteFile(local, []byte("fail_on: medium\n"), 0o644)
	cfg, used, err := LoadFirst(dir)
	if err != nil {
		t.Fatal(err)
	}
	if used != ".wpus.yaml" {
		t.Errorf("used = %q, want local candidate", used)
	}
	if cfg.FailOn != "medium" {
		t.Errorf("fail_on = %q", cfg.FailOn)
	}
}
