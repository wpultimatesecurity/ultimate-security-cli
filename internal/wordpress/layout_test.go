package wordpress

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// makeSite builds a minimal valid installation rooted at dir.
func makeSite(t *testing.T, dir string, extra map[string]string) {
	t.Helper()
	files := map[string]string{
		"wp-includes/version.php": "<?php\n$wp_version = '6.4.1';\n",
		"wp-settings.php":         "<?php\n",
		"wp-load.php":             "<?php\n",
	}
	for rel, content := range extra {
		files[rel] = content
	}
	for rel, content := range files {
		writeFile(t, filepath.Join(dir, rel), content)
	}
}

func TestEvalPathExpr(t *testing.T) {
	env := pathEnv{file: "/srv/site/wp-config.php", dir: "/srv/site", abspath: "/srv/site"}
	cases := []struct {
		expr string
		want string
		ok   bool
	}{
		{"'/srv/content'", "/srv/content", true},
		{`"/srv/content"`, "/srv/content", true},
		{"__DIR__ . '/content'", "/srv/site/content", true},
		{"dirname(__FILE__) . '/content'", "/srv/site/content", true},
		{"dirname(dirname(__FILE__)) . '/shared/wp-content'", "/srv/shared/wp-content", true},
		{"ABSPATH . 'wp-content'", "/srv/sitewp-content", true}, // PHP semantics: ABSPATH carries its own slash
		{"__DIR__.'/../content'", "/srv/site/../content", true},
		{"getenv('WP_CONTENT')", "", false},
		{"$dir . '/content'", "", false},
		{"__DIR__ . '/' . ( PHP_OS === 'WIN' ? 'a' : 'b' )", "", false},
		{"", "", false},
		{"'/unterminated", "", false},
	}
	for _, tc := range cases {
		got, ok := evalPathExpr(tc.expr, env)
		if ok != tc.ok {
			t.Errorf("evalPathExpr(%q) ok = %v, want %v", tc.expr, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("evalPathExpr(%q) = %q, want %q", tc.expr, got, tc.want)
		}
	}
}

func TestLayoutDefaults(t *testing.T) {
	root := t.TempDir()
	makeSite(t, root, map[string]string{
		"wp-config.php": "<?php\n$table_prefix = 'wp_';\n",
	})
	site, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if site.ContentPath != filepath.Join(root, "wp-content") {
		t.Errorf("content = %q", site.ContentPath)
	}
	if site.Layout.ContentSource != "default" || site.Layout.PluginsSource != "default" {
		t.Errorf("expected default sources, got %+v", site.Layout)
	}
	if site.Layout.ConfigParent {
		t.Error("wp-config.php is in the root, not the parent")
	}
	if site.Layout.Custom() {
		t.Error("a default layout must not be reported as custom")
	}
}

// TestLayoutRespectsConfiguredPaths pins the coverage fix: a site with moved
// content, plugin, MU-plugin and uploads directories must be inventoried at
// the configured locations, not at wp-content/*.
func TestLayoutRespectsConfiguredPaths(t *testing.T) {
	root := t.TempDir()
	makeSite(t, root, map[string]string{
		"wp-config.php": `<?php
define( 'WP_CONTENT_DIR', dirname( __FILE__ ) . '/app/content' );
define( 'WP_PLUGIN_DIR', dirname( __FILE__ ) . '/app/plugins' );
define( 'WPMU_PLUGIN_DIR', dirname( __FILE__ ) . '/app/mu' );
define( 'UPLOADS', 'app/files' );
`,
		"app/content/mu-plugins/loader.php": "<?php\n/*\nPlugin Name: MU Loader\nVersion: 1.0\n*/\n",
		"app/plugins/real-plugin/index.php": "<?php\n/*\nPlugin Name: Real Plugin\nVersion: 2.3\n*/\n",
		"app/content/object-cache.php":      "<?php\n// persistent object cache\n",
	})
	// A decoy inside the default location must NOT be inventoried.
	writeFile(t, filepath.Join(root, "wp-content", "plugins", "decoy", "index.php"),
		"<?php\n/*\nPlugin Name: Decoy\nVersion: 9.9\n*/\n")

	site, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if site.ContentPath != filepath.Join(root, "app", "content") {
		t.Errorf("content = %q", site.ContentPath)
	}
	if site.PluginsPath != filepath.Join(root, "app", "plugins") {
		t.Errorf("plugins = %q", site.PluginsPath)
	}
	if site.MuPluginsPath != filepath.Join(root, "app", "mu") {
		t.Errorf("mu-plugins = %q", site.MuPluginsPath)
	}
	if site.UploadsPath != filepath.Join(root, "app", "files") {
		t.Errorf("uploads = %q", site.UploadsPath)
	}
	if len(site.Plugins) != 1 || site.Plugins[0].Slug != "real-plugin" {
		t.Errorf("plugins = %+v, want only the configured plugin dir", site.Plugins)
	}
	if len(site.Dropins) != 1 || site.Dropins[0].File != "object-cache.php" {
		t.Errorf("dropins = %+v", site.Dropins)
	}
	if !site.Layout.Custom() {
		t.Error("a relocated layout must be reported as custom")
	}
	for _, tc := range []struct{ got, want string }{
		{site.Layout.ContentSource, "WP_CONTENT_DIR"},
		{site.Layout.PluginsSource, "WP_PLUGIN_DIR"},
		{site.Layout.MuPluginsSource, "WPMU_PLUGIN_DIR"},
		{site.Layout.UploadsSource, "UPLOADS"},
	} {
		if tc.got != tc.want {
			t.Errorf("source = %q, want %q", tc.got, tc.want)
		}
	}
}

// TestLayoutUnresolvableConstantIsAGap pins that an unevaluable path
// expression degrades to a reported gap instead of silently scanning the
// default location and implying full coverage.
func TestLayoutUnresolvableConstantIsAGap(t *testing.T) {
	root := t.TempDir()
	makeSite(t, root, map[string]string{
		"wp-config.php": "<?php\ndefine( 'WP_CONTENT_DIR', getenv( 'WP_CONTENT_DIR' ) );\n",
	})
	site, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(site.Layout.Unresolved) != 1 || site.Layout.Unresolved[0] != "WP_CONTENT_DIR" {
		t.Fatalf("unresolved = %v, want [WP_CONTENT_DIR]", site.Layout.Unresolved)
	}
	if site.Layout.ContentSource == "WP_CONTENT_DIR" {
		t.Error("an unresolved constant must not be reported as the content source")
	}
	if site.ContentPath != filepath.Join(root, "wp-content") {
		t.Errorf("content fallback = %q, want the default path", site.ContentPath)
	}
}

// TestParentWpConfig covers WordPress's supported layout where wp-config.php
// sits one directory above the installation.
func TestParentWpConfig(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "public")
	makeSite(t, root, nil)
	writeFile(t, filepath.Join(parent, "wp-config.php"), `<?php
define( 'WP_DEBUG', true );
define( 'WP_CONTENT_DIR', dirname( __FILE__ ) . '/shared-content' );
`)
	writeFile(t, filepath.Join(parent, "shared-content", "plugins", "p", "index.php"),
		"<?php\n/*\nPlugin Name: Shared\nVersion: 1.1\n*/\n")

	site, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if !site.Layout.ConfigParent {
		t.Error("expected wp-config.php to be detected one level above the root")
	}
	if site.Config == nil || !site.Config.Exists {
		t.Fatal("parent wp-config.php was not parsed")
	}
	if v, _ := site.Config.Bool("WP_DEBUG"); !v {
		t.Error("constants from the parent wp-config.php were not read")
	}
	if site.ContentPath != filepath.Join(parent, "shared-content") {
		t.Errorf("content = %q, want the sibling content dir", site.ContentPath)
	}
	if len(site.Plugins) != 1 || site.Plugins[0].Name != "Shared" {
		t.Errorf("plugins = %+v", site.Plugins)
	}
}

func TestLoadMUPlugins(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "loader.php"), "<?php\n/*\nPlugin Name: Loader\nVersion: 1.0\n*/\n")
	writeFile(t, filepath.Join(dir, "no-header.php"), "<?php\n// nothing\n")
	writeFile(t, filepath.Join(dir, "nested", "inner.php"), "<?php\n/*\nPlugin Name: Inner\nVersion: 1.0\n*/\n")
	writeFile(t, filepath.Join(dir, ".hidden.php"), "<?php\n/*\nPlugin Name: Hidden\nVersion: 1.0\n*/\n")

	got := LoadMUPlugins(dir)
	if len(got) != 1 || got[0].Slug != "loader" || got[0].Version != "1.0" {
		t.Fatalf("mu-plugins = %+v, want only the top-level header-carrying file", got)
	}
}
