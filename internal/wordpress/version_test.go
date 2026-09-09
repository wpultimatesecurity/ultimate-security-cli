package wordpress

import (
	"os"
	"testing"
)

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.8.2", "6.8.2", 0},
		{"6.8.2", "6.8.1", 1},
		{"6.8.1", "6.8.2", -1},
		{"6.8", "6.8.0", 0},
		{"10.0", "9.9", 1},
		{"6.9", "6.10", -1}, // numeric, not lexical
		{"8.2.1", "8.2", 1},
		{"v6.5", "6.5", 0},
		{"6.8.2.1", "6.8.2", 1},
	}
	for _, c := range cases {
		if got := VersionCompare(c.a, c.b); got != c.want {
			t.Errorf("VersionCompare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionBetween(t *testing.T) {
	cases := []struct {
		v, from       string
		fromInclusive bool
		to            string
		toInclusive   bool
		want          bool
	}{
		{"1.2.3", "1.0.0", true, "1.2.3", true, true},
		{"1.2.3", "1.0.0", true, "1.2.3", false, false},
		{"1.2.3", "1.2.3", false, "2.0", true, false},
		{"0.9", "1.0.0", true, "2.0", true, false},
		{"5.0", "", true, "", true, true}, // open range
		{"1.5", "1.0", true, "", true, true},
		{"9.9", "", true, "2.0", true, false},
		{"1.0", "*", true, "*", true, true},
	}
	for _, c := range cases {
		got := VersionBetween(c.v, c.from, c.fromInclusive, c.to, c.toInclusive)
		if got != c.want {
			t.Errorf("VersionBetween(%q,%q,%v,%q,%v) = %v, want %v",
				c.v, c.from, c.fromInclusive, c.to, c.toInclusive, got, c.want)
		}
	}
}

func TestParseVersionFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTemp(t, dir, "version.php", `<?php
$wp_version = '6.8.2';
$wp_db_version = '58975';
$required_php_version = '7.2.24';
`)
	v, db := parseVersionFile(path)
	if v != "6.8.2" {
		t.Errorf("version = %q", v)
	}
	if db != "58975" {
		t.Errorf("db version = %q", db)
	}

	missing := dir + "/nope.php"
	if v, _ := parseVersionFile(missing); v != "" {
		t.Errorf("missing file should give empty version, got %q", v)
	}
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	// Nothing there.
	if err := Validate(dir); err == nil {
		t.Error("empty dir must not validate")
	}
	// Only wp-includes/version.php — not enough.
	writeTemp(t, dir, "wp-includes/version.php", "<?php $wp_version = '6.8';")
	if err := Validate(dir); err == nil {
		t.Error("version.php alone must not validate (needs 2+ indicators)")
	}
	// Add wp-config.php and wp-admin → valid.
	writeTemp(t, dir, "wp-config.php", "<?php\n")
	if err := os.MkdirAll(dir+"/wp-admin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Validate(dir); err != nil {
		t.Errorf("expected valid, got %v", err)
	}
}

func TestLoadPluginsAndThemes(t *testing.T) {
	root := t.TempDir()
	// Directory plugin.
	plugDir := root + "/wp-content/plugins/akismet"
	if err := os.MkdirAll(plugDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, plugDir, "akismet.php", `<?php
/*
Plugin Name: Akismet Anti-spam
Version: 5.3.1
*/
`)
	// Single-file plugin.
	writeTemp(t, root+"/wp-content/plugins", "hello.php", `<?php
/*
Plugin Name: Hello Dolly
Version: 1.6
*/
`)
	// Theme.
	themeDir := root + "/wp-content/themes/twentytwentyfour"
	if err := os.MkdirAll(themeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, themeDir, "style.css", `/*
Theme Name: Twenty Twenty-Four
Version: 1.1
*/
`)

	plugins := LoadPlugins(root + "/wp-content/plugins")
	if len(plugins) != 2 {
		t.Fatalf("plugins = %d, want 2", len(plugins))
	}
	bySlug := map[string]Plugin{}
	for _, p := range plugins {
		bySlug[p.Slug] = p
	}
	if p := bySlug["akismet"]; p.Name != "Akismet Anti-spam" || p.Version != "5.3.1" {
		t.Errorf("akismet = %+v", p)
	}
	if p := bySlug["hello"]; p.Name != "Hello Dolly" || p.Version != "1.6" {
		t.Errorf("hello = %+v", p)
	}

	themes := LoadThemes(root + "/wp-content/themes")
	if len(themes) != 1 || themes[0].Name != "Twenty Twenty-Four" || themes[0].Version != "1.1" {
		t.Errorf("themes = %+v", themes)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "wp-includes/version.php", "<?php\n$wp_version = '6.4.1';\n$wp_db_version = '56657';\n")
	writeTemp(t, dir, "wp-config.php", "<?php\n$table_prefix = 'wpx_';\ndefine('DB_PASSWORD', 'hunter2secret');\n")
	site, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if site.Version != "6.4.1" {
		t.Errorf("version = %q", site.Version)
	}
	if site.Prefix != "wpx_" {
		t.Errorf("prefix = %q", site.Prefix)
	}
	if site.Config == nil || len(site.Config.SecretLiterals) == 0 {
		t.Error("config secrets should be captured")
	}
	if site.PluginsPath == "" || site.UploadsPath == "" {
		t.Error("content paths should be populated")
	}
}
