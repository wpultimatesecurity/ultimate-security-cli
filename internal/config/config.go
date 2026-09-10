// Package config loads the optional wpus configuration file and merges it
// with command-line flags. Precedence: flags > environment > file > defaults.
//
// # Trust model
//
// A configuration file can disable checks and set the exit policy, so a
// hostile directory must not be able to configure its own audit. The default
// precedence is therefore:
//
//  1. an explicit --config path (the operator chose it),
//  2. the per-user config directory,
//  3. the project-local ./.wpus.yaml — only with --trust-project-config.
//
// Decoding is strict: unknown keys are an error rather than a silent no-op,
// because a typo in a YAML key would otherwise disable nothing while looking
// like it did.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// File is the on-disk configuration schema.
type File struct {
	// FailOn mirrors --fail-on: findings at or above this severity exit 1.
	FailOn string `yaml:"fail_on,omitempty"`
	// FailOnCoverageBelow mirrors --fail-on-coverage-below: exit 1 when the
	// weighted scan coverage score of any site falls below this percentage.
	FailOnCoverageBelow int `yaml:"fail_on_coverage_below,omitempty"`
	// Exclude lists site paths to skip during automatic discovery.
	Exclude []string `yaml:"exclude,omitempty"`
	// Checks.Disabled lists check IDs to skip. Unknown IDs are rejected by
	// the scanner, not silently ignored.
	Checks struct {
		Disabled []string `yaml:"disabled,omitempty"`
	} `yaml:"checks,omitempty"`
	// Suppressions silence known-accepted findings. Unlike a disabled check a
	// suppression is scoped to a check ID, must carry a reason, and may
	// expire — so an accepted risk stays visible and auditable in the report.
	Suppressions []Suppression `yaml:"suppressions,omitempty"`
	// SeverityOverrides remaps a check's severity to a project-appropriate
	// one (for example an exposure signal that is informational on this
	// profile). Accepted values: critical, high, medium, low, info.
	SeverityOverrides map[string]string `yaml:"severity_overrides,omitempty"`
}

// Suppression silences one check ID.
type Suppression struct {
	ID     string `yaml:"id"`
	Reason string `yaml:"reason"`
	// Expires is an optional YYYY-MM-DD date after which the suppression no
	// longer applies. Empty means "until removed".
	Expires string `yaml:"expires,omitempty"`
}

// Expired reports whether the suppression has passed its expiry date as of
// now. An unparsable date is treated as expired, so a typo cannot silently
// extend an accepted risk forever.
func (s Suppression) Expired(now time.Time) bool {
	if s.Expires == "" {
		return false
	}
	d, err := time.Parse("2006-01-02", s.Expires)
	if err != nil {
		return true
	}
	return now.After(d.Add(24 * time.Hour))
}

// Source records where the effective configuration came from. It is echoed
// into every report so a reader can tell which policy produced the result.
type Source struct {
	Path string `json:"path,omitempty"`
	// ProjectLocal is true when the loaded file came from the scanned
	// directory tree rather than the operator's own configuration.
	ProjectLocal bool `json:"project_local,omitempty"`
}

// Options selects which configuration file may be used.
type Options struct {
	// Explicit is the --config path. When set it is authoritative and must
	// exist.
	Explicit string
	// TrustProject allows ./.wpus.yaml from the current directory.
	TrustProject bool
	// NoConfig disables configuration loading entirely.
	NoConfig bool
	// ConfigDir is the per-user configuration directory.
	ConfigDir string
}

// Load resolves and parses the effective configuration file.
//
// A missing file is not an error (zero values are returned); a malformed or
// partially unknown file is an error, because silently ignoring operator
// policy is worse than refusing to run.
func Load(opts Options) (*File, Source, error) {
	if opts.NoConfig {
		return &File{}, Source{}, nil
	}
	if opts.Explicit != "" {
		cfg, err := loadFile(opts.Explicit)
		if err != nil {
			return nil, Source{}, err
		}
		return cfg, Source{Path: opts.Explicit}, nil
	}
	for _, p := range userPaths(opts.ConfigDir) {
		if !exists(p) {
			continue
		}
		cfg, err := loadFile(p)
		if err != nil {
			return nil, Source{}, err
		}
		return cfg, Source{Path: p}, nil
	}
	if opts.TrustProject {
		for _, p := range projectPaths() {
			if !exists(p) {
				continue
			}
			abs, err := filepath.Abs(p)
			if err != nil {
				abs = p
			}
			cfg, err := loadFile(p)
			if err != nil {
				return nil, Source{}, err
			}
			return cfg, Source{Path: abs, ProjectLocal: true}, nil
		}
	}
	return &File{}, Source{}, nil
}

// loadFile parses one configuration file with strict field checking.
func loadFile(path string) (*File, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-selected config path
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	cfg := &File{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w (unknown keys are rejected; check spelling)", path, err)
	}
	return cfg, nil
}

func exists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// userPaths lists the per-user configuration candidates in precedence order.
func userPaths(configDir string) []string {
	if configDir == "" {
		return nil
	}
	return []string{
		filepath.Join(configDir, "config.yaml"),
		filepath.Join(configDir, "config.yml"),
	}
}

// projectPaths lists the repository-local candidates. They are only
// considered with --trust-project-config.
func projectPaths() []string {
	return []string{".wpus.yaml", ".wpus.yml"}
}
