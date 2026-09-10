package discovery

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
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

// smallTree writes two valid sites and one plain directory under a fresh
// temp root. A complete walk of it enters 10 directories: the root, the two
// sites, and each site's three core trees (wp-admin, wp-content,
// wp-includes), which are entered and then skipped.
func smallTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	makeSite(t, root, "alpha")
	mk(t, root, "beta")
	put(t, root, filepath.Join("beta", "notes.txt"), "not a site\n")
	makeSite(t, root, "gamma")
	return root
}

func TestDiscoverWithStatsAccounting(t *testing.T) {
	tests := []struct {
		name          string
		opts          func(t *testing.T) Options
		wantResults   int
		wantValid     int
		wantRoots     int
		wantDirs      int
		wantDepth     int
		wantTruncated bool
		wantReason    string
	}{
		{
			name:        "complete small tree is not truncated",
			opts:        func(t *testing.T) Options { return Options{Explicit: []string{smallTree(t)}} },
			wantResults: 2, wantValid: 2,
			wantRoots: 1, wantDirs: 10, wantDepth: DefaultDepth,
		},
		{
			name: "result cap truncates",
			opts: func(t *testing.T) Options {
				return Options{Explicit: []string{smallTree(t)}, MaxResults: 1}
			},
			wantResults: 1, wantValid: 1,
			wantRoots: 1, wantDirs: 10, wantDepth: DefaultDepth,
			wantTruncated: true, wantReason: "max_results",
		},
		{
			name: "expired timeout truncates before walking",
			opts: func(t *testing.T) Options {
				return Options{Explicit: []string{smallTree(t)}, Timeout: time.Nanosecond}
			},
			wantRoots: 1, wantDepth: DefaultDepth,
			wantTruncated: true, wantReason: "time",
		},
		{
			name: "missing root still counts",
			opts: func(t *testing.T) Options {
				return Options{Explicit: []string{filepath.Join(t.TempDir(), "nope")}}
			},
			wantResults: 1, wantValid: 0,
			wantRoots: 1, wantDepth: DefaultDepth,
		},
		{
			name: "custom depth is reported",
			opts: func(t *testing.T) Options {
				return Options{Explicit: []string{smallTree(t)}, Depth: 2}
			},
			wantResults: 2, wantValid: 2,
			wantRoots: 1, wantDirs: 10, wantDepth: 2,
		},
		{
			name: "skipped directories are not truncation",
			opts: func(t *testing.T) Options {
				root := t.TempDir()
				makeSite(t, root, filepath.Join("wrapper", ".git", "site"))
				makeSite(t, root, filepath.Join("wrapper", "vendor", "site2"))
				makeSite(t, root, "wrapper")
				return Options{Explicit: []string{root}}
			},
			wantResults: 1, wantValid: 1,
			wantRoots: 1, wantDirs: 7, wantDepth: DefaultDepth,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results, stats := DiscoverWithStats(tc.opts(t))
			valid := 0
			for _, r := range results {
				if r.Valid {
					valid++
				}
			}
			if len(results) != tc.wantResults || valid != tc.wantValid {
				t.Errorf("results = %d (%d valid), want %d (%d valid): %+v",
					len(results), valid, tc.wantResults, tc.wantValid, results)
			}
			if stats.Roots != tc.wantRoots {
				t.Errorf("Roots = %d, want %d", stats.Roots, tc.wantRoots)
			}
			if stats.DirectoriesVisited != tc.wantDirs {
				t.Errorf("DirectoriesVisited = %d, want %d", stats.DirectoriesVisited, tc.wantDirs)
			}
			if stats.MaxDepth != tc.wantDepth {
				t.Errorf("MaxDepth = %d, want %d", stats.MaxDepth, tc.wantDepth)
			}
			if stats.Truncated != tc.wantTruncated {
				t.Errorf("Truncated = %v, want %v", stats.Truncated, tc.wantTruncated)
			}
			if stats.TruncationReason != tc.wantReason {
				t.Errorf("TruncationReason = %q, want %q", stats.TruncationReason, tc.wantReason)
			}
		})
	}
}

func TestDiscoverWithStatsUnreadableRootCounts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	root := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })

	results, stats := DiscoverWithStats(Options{Explicit: []string{root}})
	if stats.Roots != 1 {
		t.Errorf("unreadable root must count as a root: Roots = %d", stats.Roots)
	}
	if stats.Truncated {
		t.Errorf("unreadable root is not truncation: %+v", stats)
	}
	if len(results) != 1 || results[0].Valid || results[0].Note != "permission denied" {
		t.Errorf("want one permission-denied result, got %+v", results)
	}
}

func TestDiscoverMatchesDiscoverWithStats(t *testing.T) {
	opts := Options{Explicit: []string{smallTree(t), filepath.Join(t.TempDir(), "nope")}}
	plain := Discover(opts)
	detailed, _ := DiscoverWithStats(opts)
	if !reflect.DeepEqual(plain, detailed) {
		t.Fatalf("Discover and DiscoverWithStats disagree:\n Discover = %+v\n withStats = %+v", plain, detailed)
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
