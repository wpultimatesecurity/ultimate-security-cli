// Package config loads the optional wpus configuration file and merges it
// with command-line flags. Precedence: flags > environment > file > defaults.
//
// V1 intentionally keeps the surface small: fail_on, exclude paths, and
// disabled checks.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// File is the on-disk configuration schema.
type File struct {
	// FailOn mirrors --fail-on: findings at or above this severity exit 1.
	FailOn string `yaml:"fail_on,omitempty"`
	// Exclude lists site paths to skip during automatic discovery.
	Exclude []string `yaml:"exclude,omitempty"`
	// Checks.Disabled lists check IDs to skip.
	Checks struct {
		Disabled []string `yaml:"disabled,omitempty"`
	} `yaml:"checks,omitempty"`
}

// Load reads a single config file. Missing file returns zero values and nil
// error; a malformed file is an error (users must know their config is dead).
func Load(path string) (*File, error) {
	cfg := &File{}
	data, err := os.ReadFile(path) //nolint:gosec // user-specified config path
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// CandidatePaths lists config locations in precedence order:
// ./.wpus.yaml, ./.wpus.yml, then the user config dir.
func CandidatePaths(configDir string) []string {
	return []string{
		".wpus.yaml",
		".wpus.yml",
		filepath.Join(configDir, "config.yaml"),
		filepath.Join(configDir, "config.yml"),
	}
}

// LoadFirst loads the first existing candidate config.
func LoadFirst(configDir string) (*File, string, error) {
	for _, p := range CandidatePaths(configDir) {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		cfg, err := Load(p)
		if err != nil {
			return nil, "", err
		}
		return cfg, p, nil
	}
	return &File{}, "", nil
}
