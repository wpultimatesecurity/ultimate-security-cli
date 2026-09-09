package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func mk(t *testing.T, base, rel string) {
	t.Helper()
	p := filepath.Join(base, rel)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func put(t *testing.T, base, rel, content string) {
	t.Helper()
	p := filepath.Join(base, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// makeSite writes a minimal valid WordPress tree and returns its path.
func makeSite(t *testing.T, base, rel string) string {
	t.Helper()
	mk(t, base, filepath.Join(rel, "wp-admin"))
	mk(t, base, filepath.Join(rel, "wp-includes"))
	mk(t, base, filepath.Join(rel, "wp-content"))
	put(t, base, filepath.Join(rel, "wp-includes", "version.php"), "<?php\n$wp_version = '6.8.2';\n")
	put(t, base, filepath.Join(rel, "wp-config.php"), "<?php\n$table_prefix = 'wp_';\n")
	put(t, base, filepath.Join(rel, "wp-settings.php"), "<?php\n")
	return filepath.Join(base, rel)
}

func TestDiscoverFindsStandardLayouts(t *testing.T) {
	home := t.TempDir()

	// macOS Local Sites layout: ~/Local Sites/<site>/app/public
	localSite := makeSite(t, home, filepath.Join("Local Sites", "blog", "app", "public"))

	// Hosting layout: /home-style under a root dir.
	root := t.TempDir()
	publicHTML := makeSite(t, root, filepath.Join("home", "alice", "public_html"))

	// Plain project dir.
	root2 := t.TempDir()
	simple := makeSite(t, root2, "blog")

	results := Discover(Options{
		Explicit: []string{filepath.Join(home, "Local Sites"), root, root2},
	})
	valid := map[string]bool{}
	for _, r := range results {
		valid[r.Path] = r.Valid
	}
	for _, want := range []string{localSite, publicHTML, simple} {
		if !valid[want] {
			t.Errorf("expected %q in results: %+v", want, results)
		}
	}
}

func TestDiscoverRejectsFalsePositives(t *testing.T) {
	root := t.TempDir()

	// A dir with only wp-config.php — not WordPress.
	put(t, root, filepath.Join("fake", "wp-config.php"), "<?php\n")

	// A dir with wp-includes/version.php only — not enough indicators.
	put(t, root, filepath.Join("half", "wp-includes", "version.php"), "<?php\n")

	// Corrupted core: wp-includes present but version.php renamed away.
	mk(t, root, filepath.Join("broken", "wp-includes"))
	mk(t, root, filepath.Join("broken", "wp-admin"))
	put(t, root, filepath.Join("broken", "wp-settings.php"), "<?php\n")

	results := Discover(Options{Explicit: []string{
		filepath.Join(root, "fake"),
		filepath.Join(root, "half"),
		filepath.Join(root, "broken"),
	}})
	for _, r := range results {
		if r.Valid {
			t.Errorf("false positive: %q validated", r.Path)
		}
		if r.Note == "" {
			t.Errorf("invalid result %q must carry a reason", r.Path)
		}
	}
}

func TestDiscoverExplicitInvalidPath(t *testing.T) {
	results := Discover(Options{Explicit: []string{filepath.Join(t.TempDir(), "nope")}})
	if len(results) != 1 || results[0].Valid {
		t.Errorf("missing explicit path must yield invalid result: %+v", results)
	}
}

func TestDiscoverSkipsHiddenAndVendorDirs(t *testing.T) {
	root := t.TempDir()
	// A site hidden inside .git must not be reported.
	nested := makeSite(t, root, filepath.Join("wrapper", ".git", "site"))
	_ = nested
	site := makeSite(t, root, filepath.Join("wrapper", "vendor", "site2"))
	_ = site
	good := makeSite(t, root, "wrapper")

	results := Discover(Options{Explicit: []string{root}})
	for _, r := range results {
		p := r.Path
		if p == nested || p == site {
			t.Errorf("hidden/vendor nested site must be skipped: %s", p)
		}
	}
	if len(results) != 1 || results[0].Path != good {
		t.Errorf("expected only %q, got %+v", good, results)
	}
}

func TestDiscoverDeduplicatesNestedRoots(t *testing.T) {
	root := t.TempDir()
	site := makeSite(t, root, "site")
	// Passing both a parent and the site itself yields one entry per path,
	// not duplicates.
	results := Discover(Options{Explicit: []string{site, site, root + "/site"}})
	count := 0
	for _, r := range results {
		if r.Path == site && r.Valid {
			count++
		}
	}
	if count != 1 {
		t.Errorf("dedup failed: %d entries for %s", count, site)
	}
}

func TestIsVirtual(t *testing.T) {
	for _, p := range []string{"/proc/1", "/sys", "/dev/null", "/run/motd"} {
		if !isVirtual(p) {
			t.Errorf("%s should be virtual", p)
		}
	}
	for _, p := range []string{"/var/www", "/srv/site", "/home/u"} {
		if isVirtual(p) {
			t.Errorf("%s should not be virtual", p)
		}
	}
}
