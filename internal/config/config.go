package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	ErrNoSites        = errors.New("no sites configured")
	ErrInvalidURL     = errors.New("invalid site URL")
	ErrDuplicateName  = errors.New("duplicate site name")
	ErrMissingField   = errors.New("missing required field")
	ErrInvalidTheme   = errors.New("invalid theme value")
	ErrInvalidTimeout = errors.New("timeout out of range")
)

type Config struct {
	Version     int          `yaml:"version"`
	DefaultSite string       `yaml:"default_site"`
	Sites       []SiteConfig `yaml:"sites"`
	UI          UIConfig     `yaml:"ui"`
	API         APIConfig    `yaml:"api"`
	Debug       DebugConfig  `yaml:"debug"`

	path string `yaml:"-"`
}

type SiteConfig struct {
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	Username    string `yaml:"username"`
	AppPassword string `yaml:"app_password"`
	VerifySSL   bool   `yaml:"verify_ssl"`
}

type UIConfig struct {
	Theme           string        `yaml:"theme"`
	AltScreen       bool          `yaml:"alt_screen"`
	Mouse           bool          `yaml:"mouse"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	DefaultPage     string        `yaml:"default_page"`
}

type APIConfig struct {
	Timeout       time.Duration `yaml:"timeout"`
	RetryAttempts int           `yaml:"retry_attempts"`
	RetryDelay    time.Duration `yaml:"retry_delay"`
}

type DebugConfig struct {
	Enabled bool   `yaml:"enabled"`
	LogPath string `yaml:"log_path"`
	LogHTTP bool   `yaml:"log_http"`
}

func DefaultConfig() Config {
	return Config{
		Version: 1,
		Sites:   []SiteConfig{},
		UI: UIConfig{
			Theme:           "dark",
			AltScreen:       true,
			Mouse:           true,
			RefreshInterval: 60 * time.Second,
			DefaultPage:     "dashboard",
		},
		API: APIConfig{
			Timeout:       30 * time.Second,
			RetryAttempts: 3,
			RetryDelay:    time.Second,
		},
		Debug: DebugConfig{},
	}
}

func Load(path string) (Config, error) {
	cfg := DefaultConfig()
	cfg.path = path

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config: %w", err)
	}

	cfg.path = path
	applyEnvOverrides(&cfg)

	if err := validate(&cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func (c *Config) Save() error {
	if c.path == "" {
		p, err := ConfigPath()
		if err != nil {
			return err
		}
		c.path = p
	}

	dir := filepath.Dir(c.path)
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "uscli-config-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing config: %w", err)
	}
	tmp.Close()

	if err := os.Chmod(tmpName, 0600); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("setting config permissions: %w", err)
	}

	if err := os.Rename(tmpName, c.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("replacing config: %w", err)
	}

	return nil
}

func (c *Config) Path() string {
	return c.path
}

func (c *Config) ActiveSite() (*SiteConfig, error) {
	if len(c.Sites) == 0 {
		return nil, ErrNoSites
	}
	if c.DefaultSite == "" {
		return &c.Sites[0], nil
	}
	for i := range c.Sites {
		if c.Sites[i].Name == c.DefaultSite {
			return &c.Sites[i], nil
		}
	}
	return &c.Sites[0], nil
}

func (c *Config) SetPath(path string) {
	c.path = path
}

var invalidURLSuffixes = regexp.MustCompile(`(?i)/wp-admin/?$|/wp-login\.php/?$`)

func normalizeURL(raw string) string {
	u := strings.TrimSpace(raw)
	u = strings.TrimRight(u, "/")
	return u
}

func validateSite(s SiteConfig, idx int, names map[string]bool) error {
	if s.Name == "" {
		return fmt.Errorf("%w: site %d missing name", ErrMissingField, idx)
	}
	if names[s.Name] {
		return fmt.Errorf("%w: %q", ErrDuplicateName, s.Name)
	}
	names[s.Name] = true

	if s.URL == "" {
		return fmt.Errorf("%w: site %q missing url", ErrMissingField, s.Name)
	}
	u := normalizeURL(s.URL)
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("%w: %q must start with http:// or https://", ErrInvalidURL, u)
	}
	if invalidURLSuffixes.MatchString(u) {
		return fmt.Errorf("%w: %q looks like an admin URL, use the site root", ErrInvalidURL, u)
	}

	if s.Username == "" {
		return fmt.Errorf("%w: site %q missing username", ErrMissingField, s.Name)
	}
	if s.AppPassword == "" {
		return fmt.Errorf("%w: site %q missing app_password", ErrMissingField, s.Name)
	}
	return nil
}

func validate(cfg *Config) error {
	validThemes := map[string]bool{"dark": true, "light": true, "auto": true}
	if !validThemes[cfg.UI.Theme] {
		return fmt.Errorf("%w: %q (must be dark, light, or auto)", ErrInvalidTheme, cfg.UI.Theme)
	}
	if cfg.API.Timeout < time.Second || cfg.API.Timeout > 120*time.Second {
		return fmt.Errorf("%w: %v (must be 1s-120s)", ErrInvalidTimeout, cfg.API.Timeout)
	}
	if cfg.API.RetryAttempts < 0 || cfg.API.RetryAttempts > 10 {
		return fmt.Errorf("retry_attempts out of range: %d (must be 0-10)", cfg.API.RetryAttempts)
	}
	if cfg.UI.RefreshInterval < 5*time.Second || cfg.UI.RefreshInterval > 10*time.Minute {
		return fmt.Errorf("refresh_interval out of range: %v (must be 5s-10m)", cfg.UI.RefreshInterval)
	}

	names := make(map[string]bool)
	for i, s := range cfg.Sites {
		if err := validateSite(s, i, names); err != nil {
			return err
		}
	}
	return nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("USCLI_SITE_URL"); v != "" {
		ensureEnvSite(cfg)
		cfg.Sites[0].URL = v
	}
	if v := os.Getenv("USCLI_SITE_USERNAME"); v != "" {
		ensureEnvSite(cfg)
		cfg.Sites[0].Username = v
	}
	if v := os.Getenv("USCLI_SITE_APP_PASSWORD"); v != "" {
		ensureEnvSite(cfg)
		cfg.Sites[0].AppPassword = v
	}
	if v := os.Getenv("USCLI_VERIFY_SSL"); v != "" {
		ensureEnvSite(cfg)
		cfg.Sites[0].VerifySSL = v == "true" || v == "1"
	}
	if v := os.Getenv("USCLI_THEME"); v != "" {
		cfg.UI.Theme = v
	}
	if v := os.Getenv("USCLI_DEBUG"); v == "true" || v == "1" {
		cfg.Debug.Enabled = true
	}
}

func ensureEnvSite(cfg *Config) {
	if len(cfg.Sites) == 0 {
		cfg.Sites = append(cfg.Sites, SiteConfig{Name: "env"})
	}
}

func (s *SiteConfig) BaseURL() string {
	return normalizeURL(s.URL) + "/wp-json/ultimate-security/v1"
}

func (s *SiteConfig) AuthHeader() string {
	cred := s.Username + ":" + s.AppPassword
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(cred))
}

func (s *SiteConfig) MaskedPassword() string {
	if len(s.AppPassword) == 0 {
		return ""
	}
	return "****"
}
