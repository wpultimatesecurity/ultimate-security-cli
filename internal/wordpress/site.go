// Package wordpress models a WordPress installation on disk: detection,
// static parsing of wp-config.php and core metadata, plugin/theme headers,
// and the provider abstraction that merges filesystem knowledge with
// optional WP-CLI insight.
//
// Nothing in this package ever executes site PHP or writes to the site.
package wordpress

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Site is a validated WordPress installation.
type Site struct {
	Path string // absolute path to the WordPress root (webroot)

	// Core metadata (parsed from wp-includes/version.php).
	Version         string // e.g. "6.8.2"
	DatabaseVersion string // e.g. "58975"

	// Config is the statically parsed wp-config.php. Nil if unreadable.
	Config *WpConfig

	// Layout records where WordPress actually keeps its content, plugins,
	// MU plugins, themes and uploads, and whether wp-config.php lives one
	// directory above the installation. Checks read paths from here.
	Layout Layout

	// Content layout (resolved from the site's configuration, never assumed).
	ContentPath   string // resolved wp-content directory
	UploadsPath   string // resolved uploads directory (may not exist)
	PluginsPath   string
	ThemesPath    string
	MuPluginsPath string // resolved MU-plugin directory (may not exist)
	IsMultisite   bool
	MultisiteDir  bool // sites/ subdir in uploads (subdir multisite)

	Plugins   []Plugin
	Themes    []Theme
	MuPlugins []Plugin // must-use plugins: auto-loaded, never in the plugin list
	Dropins   []Dropin // files WordPress loads at fixed bootstrap points

	// Enriched data (populated from WP-CLI when available; nil fields mean
	// "not determined", never "no").
	ActivePlugins   []string // slugs
	ActiveTheme     string   // stylesheet slug
	AdminUsers      []User
	SiteURL         string // wp_options siteurl
	HomeURL         string // wp_options home
	Prefix          string // effective table prefix (config or wpcli)
	WPCLIPHPVersion string // PHP version reported by WP-CLI's runtime
	XMLRPCEnabled   *bool  // apply_filters('xmlrpc_enabled') via WP-CLI
}

// User is a WordPress account (metadata only — never credentials or hashes).
type User struct {
	ID         int64  `json:"id"`
	Login      string `json:"login"`
	Email      string `json:"email,omitempty"`
	Roles      string `json:"roles,omitempty"`
	Registered string `json:"registered,omitempty"`
}

// Plugin is an installed plugin (directory or single-file style).
type Plugin struct {
	Slug    string
	Name    string
	Version string
	Active  *bool  // nil = unknown (no WP-CLI)
	Update  string // "available" when WP-CLI reports an update
}

// Theme is an installed theme.
type Theme struct {
	Slug    string
	Name    string
	Version string
	Active  *bool
	Update  string
}

// Validate checks whether dir looks like a genuine WordPress root.
// It requires strong evidence, not a single file:
// wp-includes/version.php must exist and contain a parsable $wp_version,
// plus at least two of: wp-config.php, wp-settings.php, wp-load.php,
// wp-admin/, wp-includes/, wp-content/.
func Validate(dir string) error {
	versionFile := filepath.Join(dir, "wp-includes", "version.php")
	if _, err := os.Stat(versionFile); err != nil {
		return fmt.Errorf("not WordPress: %s not found", "wp-includes/version.php")
	}
	score := 0
	for _, rel := range []string{
		"wp-config.php", "wp-settings.php", "wp-load.php",
		"wp-admin", "wp-includes", "wp-content",
	} {
		if _, err := os.Lstat(filepath.Join(dir, rel)); err == nil {
			score++
		}
	}
	if score < 2 {
		return fmt.Errorf("not WordPress: only %d of 6 core indicators present", score)
	}
	return nil
}

// Load reads core metadata for a validated site path. It never fails hard:
// unreadable pieces are reported as empty and the checks handle absence.
func Load(path string) (*Site, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// wp-config.php may legitimately live one directory above the webroot,
	// so parse it before resolving any path constant.
	cfgPath, configParent := findConfig(abs)
	cfg := ParseWpConfig(cfgPath)
	layout := resolveLayout(abs, cfg)
	layout.ConfigPath = cfgPath
	layout.ConfigParent = configParent

	site := &Site{
		Path:          abs,
		Config:        cfg,
		Layout:        layout,
		ContentPath:   layout.ContentPath,
		PluginsPath:   layout.PluginsPath,
		ThemesPath:    layout.ThemesPath,
		UploadsPath:   layout.UploadsPath,
		MuPluginsPath: layout.MuPluginsPath,
	}
	site.Version, site.DatabaseVersion = parseVersionFile(filepath.Join(abs, "wp-includes", "version.php"))
	site.Plugins = LoadPlugins(site.PluginsPath)
	site.Themes = LoadThemes(site.ThemesPath)
	site.MuPlugins = LoadMUPlugins(site.MuPluginsPath)
	site.Dropins = LoadDropins(site.ContentPath)
	if site.Config != nil {
		if v, _ := site.Config.Bool("MULTISITE"); v {
			site.IsMultisite = true
		}
		site.Prefix = site.Config.Prefix
		if v, ok := site.Config.String("WP_HOME"); ok {
			site.HomeURL = strings.TrimRight(v, "/")
		}
		if v, ok := site.Config.String("WP_SITEURL"); ok {
			site.SiteURL = strings.TrimRight(v, "/")
		}
	}
	if site.Prefix == "" {
		site.Prefix = "wp_" // WordPress default when unset
	}
	if st, err := os.Stat(filepath.Join(site.UploadsPath, "sites")); err == nil && st.IsDir() && site.IsMultisite {
		site.MultisiteDir = true
	}
	return site, nil
}

// phpBool interprets a PHP literal as a boolean the way WordPress does.
func phpBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "'1'", "\"1\"":
		return true
	default:
		return false
	}
}

// parsePHPVersion extracts the version from $wp_version = '6.8.2';.
func parsePHPVersion(src, varName string) string {
	idx := strings.Index(src, "$"+varName)
	if idx < 0 {
		return ""
	}
	seg := src[idx:]
	if len(seg) > 400 {
		seg = seg[:400]
	}
	// find first quoted string after '='
	eq := strings.Index(seg, "=")
	if eq < 0 {
		return ""
	}
	rest := seg[eq:]
	q1 := strings.IndexAny(rest, "'\"")
	if q1 < 0 {
		return ""
	}
	q := rest[q1]
	q2 := strings.IndexByte(rest[q1+1:], q)
	if q2 < 0 {
		return ""
	}
	return rest[q1+1 : q1+1+q2]
}

func parseVersionFile(path string) (version, dbVersion string) {
	data, err := os.ReadFile(path) //nolint:gosec // path is under the site being scanned
	if err != nil {
		return "", ""
	}
	src := string(data)
	return parsePHPVersion(src, "wp_version"), parsePHPVersion(src, "wp_db_version")
}

// looksLikeEnvName filters PHP built-ins from define() interest.
func looksLikeConstantName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// PHP EOL awareness lives in the php check; this helper converts versions.
func atoiSafe(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
