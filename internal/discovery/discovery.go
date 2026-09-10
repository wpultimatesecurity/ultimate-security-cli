// Package discovery finds WordPress installations on the local machine.
//
// Discovery is bounded in every dimension: limited depth, a wall-clock
// budget, a visited-directory cap, and a skip list for huge or irrelevant
// trees. It never touches virtual filesystems and never requires elevated
// permissions.
package discovery

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
)

// Options controls a discovery run.
type Options struct {
	// Explicit paths act as walk seeds. With no explicit paths, the
	// platform root list is used.
	Explicit []string
	// Home is the user's home directory ("" uses $HOME).
	Home string
	// Timeout bounds the walk. Zero uses DefaultTimeout.
	Timeout time.Duration
	// Depth bounds recursion depth below each root. Zero uses DefaultDepth.
	Depth int
	// MaxResults caps the number of results (valid and invalid).
	MaxResults int
}

const (
	DefaultTimeout = 20 * time.Second
	DefaultDepth   = 6
	DefaultMaxRes  = 100
	maxVisitedDirs = 300_000
	wpIncludesDir  = "wp-includes"
)

// autoRoots returns the default search roots for the runtime platform.
func autoRoots(home string) []string {
	if home == "" {
		home = os.Getenv("HOME")
	}
	var roots []string
	if home != "" {
		// macOS development locations and generic project directories.
		for _, rel := range []string{
			"Sites", "Local Sites", "Developer", "Projects", "Code",
			"dev", "src", "web", "htdocs", "work", "Documents",
			"OrbStack", // OrbStack exposes Docker volumes here
		} {
			roots = append(roots, filepath.Join(home, rel))
		}
	}
	// Linux hosting locations (harmless if absent on macOS).
	roots = append(roots, "/var/www", "/srv", "/opt", "/usr/share/nginx", "/home")
	return roots
}

// skipNames are directories never worth descending into anywhere.
var skipNames = map[string]bool{
	".git": true, ".svn": true, ".hg": true, "node_modules": true,
	"vendor": true, "bower_components": true, ".npm": true,
	".cache": true, "__pycache__": true, ".terraform": true,
}

// virtualPrefixes are path prefixes never scanned on any platform.
var virtualPrefixes = []string{
	"/proc", "/sys", "/dev", "/run", "/var/run", "/snap",
	"/System/Volumes", "/private/var/db", "/private/var/folders", "/private/var/run",
}

// coreTrees are WordPress's large core trees; below a confirmed site they
// are never descended into.
var coreTrees = map[string]bool{
	"wp-content": true, "wp-admin": true, "wp-includes": true,
}

// Result is one discovery outcome.
type Result struct {
	Path  string `json:"path"`
	Valid bool   `json:"valid"`
	Note  string `json:"note,omitempty"` // why a path is not a usable installation
}

// Stats accounts for a discovery run.
//
// Discovery stops early on three ceilings — the wall-clock timeout, the
// visited-directory cap, and the result cap — so "no installations found"
// is otherwise ambiguous between "none exist" and "the search gave up".
// These counters let a caller tell the two apart.
//
// Directories skipped by the skip list, the hidden-directory rule, or the
// core-tree rule do not mark the run truncated: skipping them is
// deliberate scope, not an exhausted budget.
type Stats struct {
	// Roots is how many search roots the walk set out from. Roots that do
	// not exist still count: they were part of the search. Roots on
	// virtual filesystems are filtered before the count, so they never
	// appear here.
	Roots int `json:"roots"`
	// DirectoriesVisited counts directories the walker entered, including
	// the roots and directories it then decided to skip.
	DirectoriesVisited int `json:"directories_visited"`
	// MaxDepth is the recursion depth applied, after defaulting.
	MaxDepth int `json:"max_depth"`
	// Truncated reports whether a ceiling stopped the search early.
	Truncated bool `json:"truncated"`
	// TruncationReason names the first ceiling hit: "time",
	// "max_directories", or "max_results". Empty when Truncated is false.
	TruncationReason string `json:"truncation_reason,omitempty"`
}

// Discover finds WordPress installations and returns results only.
//
// Explicit paths are walked as seeds (so `wpus scan /var/www` finds the
// sites inside, while `wpus scan /var/www/site` validates that one).
// Everything is bounded by timeout, depth, and visited-directory caps.
// The returned slice is sorted: valid sites first, then by path.
//
// Use DiscoverWithStats when the search's completeness matters: a bounded
// search can stop early, so an empty result slice does not by itself prove
// there are no installations.
func Discover(opts Options) []Result {
	results, _ := DiscoverWithStats(opts)
	return results
}

// DiscoverWithStats finds WordPress installations and accounts for the
// search that produced them.
//
// It behaves exactly like Discover but also reports how far the walk got,
// which ceiling (if any) cut it short, and which one did so first.
func DiscoverWithStats(opts Options) ([]Result, Stats) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	depth := opts.Depth
	if depth <= 0 {
		depth = DefaultDepth
	}
	maxResults := opts.MaxResults
	if maxResults <= 0 {
		maxResults = DefaultMaxRes
	}
	deadline := time.Now().Add(timeout)

	var stats Stats
	stats.MaxDepth = depth
	truncate := func(reason string) {
		if !stats.Truncated {
			stats.Truncated = true
			stats.TruncationReason = reason
		}
	}

	roots := opts.Explicit
	if len(roots) == 0 {
		roots = autoRoots(opts.Home)
	}
	roots = filterVirtual(roots)
	stats.Roots = len(roots)

	var out []Result
	seen := map[string]bool{}
	add := func(r Result) {
		if seen[r.Path] {
			return
		}
		if len(out) >= maxResults {
			truncate("max_results")
			return
		}
		seen[r.Path] = true
		out = append(out, r)
	}

	visited := 0
	confirmed := map[string]bool{}
	for _, root := range roots {
		if len(out) >= maxResults {
			truncate("max_results")
			break
		}
		if time.Now().After(deadline) {
			truncate("time")
			break
		}
		if visited > maxVisitedDirs {
			truncate("max_directories")
			break
		}
		if _, err := os.Stat(root); err != nil {
			if len(opts.Explicit) > 0 {
				add(Result{Path: root, Note: "path not accessible"})
			}
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if len(opts.Explicit) > 0 && path == root && os.IsPermission(err) {
					add(Result{Path: root, Note: "permission denied"})
				}
				return fs.SkipDir // unreadable subtree — skip quietly
			}
			if time.Now().After(deadline) {
				truncate("time")
				return fs.SkipAll
			}
			if !d.IsDir() {
				return nil
			}
			visited++
			if visited > maxVisitedDirs {
				truncate("max_directories")
				return fs.SkipAll
			}
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || skipNames[name]) {
				return fs.SkipDir
			}
			if path != root && confirmed[filepath.Dir(path)] && coreTrees[name] {
				return fs.SkipDir // never descend into a confirmed site's core trees
			}
			if path != root && isVirtual(path) {
				return fs.SkipDir
			}
			if relDepth(root, path) > depth {
				return fs.SkipDir
			}
			// Cheap marker first: wp-includes must exist for a candidate.
			if _, statErr := os.Stat(filepath.Join(path, wpIncludesDir)); statErr != nil {
				return nil
			}
			if vErr := wordpress.Validate(path); vErr == nil {
				add(Result{Path: path, Valid: true})
				confirmed[path] = true
			}
			return nil
		})
	}
	stats.DirectoriesVisited = visited
	sortResults(out)
	return out, stats
}

// filterVirtual drops roots inside virtual/system filesystems.
func filterVirtual(roots []string) []string {
	out := roots[:0:0]
	for _, r := range roots {
		if !isVirtual(r) {
			out = append(out, r)
		}
	}
	return out
}

func relDepth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return strings.Count(filepath.ToSlash(rel), "/")
}

func isVirtual(path string) bool {
	p := filepath.ToSlash(path)
	if os.PathSeparator != '/' {
		p = strings.TrimPrefix(p, "/private")
	}
	for _, prefix := range virtualPrefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func sortResults(rs []Result) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Valid != rs[j].Valid {
			return rs[i].Valid
		}
		return rs[i].Path < rs[j].Path
	})
}

// ValidPaths returns just the valid site paths from results.
func ValidPaths(rs []Result) []string {
	var out []string
	for _, r := range rs {
		if r.Valid {
			out = append(out, r.Path)
		}
	}
	return out
}
