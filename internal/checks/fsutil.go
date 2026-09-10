package checks

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// walkCaps bound every filesystem walk a check performs. A normal scan must
// stay fast on huge sites; --deep raises the budget.
type walkCaps struct {
	Deadline time.Time
	MaxFiles int
	MaxDepth int
	// MaxMatches caps how many matching paths are recorded. Traversals still
	// complete; only the displayed list is bounded.
	MaxMatches int
	// IncludeHidden descends into dot-directories. Off by default because
	// .git/.cache noise dwarfs the value; high-risk trees (uploads) turn it
	// on in --deep mode.
	IncludeHidden bool
}

func defaultCaps(deep bool) walkCaps {
	if deep {
		return walkCaps{Deadline: time.Now().Add(30 * time.Second), MaxFiles: 250_000, MaxDepth: 16, MaxMatches: 200}
	}
	return walkCaps{Deadline: time.Now().Add(5 * time.Second), MaxFiles: 50_000, MaxDepth: 12, MaxMatches: 50}
}

// walkResult summarizes one bounded walk. Everything the walker chose not to
// examine is counted, because "no matches" and "did not look" must never be
// confused in a security report.
type walkResult struct {
	Files              int
	WorldWritableFiles int
	WorldWritableDirs  int
	Matches            []string
	MatchesDropped     int
	Unreadable         int
	SymlinksSkipped    int
	// Truncated is true when a budget cut the traversal short, so Files and
	// Matches are lower bounds rather than complete answers.
	Truncated        bool
	TruncationReason string // "time", "max_files", "max_depth"
}

// walk is a bounded walker rooted at dir. match is called for every regular
// file (relative, slash-separated path); return true to record it. Directory
// symlinks are never followed.
func walk(dir string, caps walkCaps, match func(rel string) bool) walkResult {
	var res walkResult
	stop := func(reason string) error {
		res.Truncated = true
		res.TruncationReason = reason
		return fs.SkipAll
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		// The deadline is checked on every entry, including when nothing has
		// matched: a huge tree on slow storage must not run past its budget
		// just because it happens to contain no interesting files.
		if !caps.Deadline.IsZero() && time.Now().After(caps.Deadline) {
			return stop("time")
		}
		if err != nil {
			res.Unreadable++
			return fs.SkipDir
		}
		if res.Files >= caps.MaxFiles {
			return stop("max_files")
		}
		name := d.Name()
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			res.Unreadable++
			return fs.SkipDir
		}
		if rel == "." {
			return nil
		}
		if !caps.IncludeHidden && strings.HasPrefix(name, ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			depth := strings.Count(filepath.ToSlash(rel), "/")
			if depth >= caps.MaxDepth {
				return stop("max_depth")
			}
			if d.Type()&os.ModeSymlink != 0 {
				res.SymlinksSkipped++
				return fs.SkipDir // never follow directory symlinks
			}
			info, statErr := d.Info()
			if statErr != nil {
				res.Unreadable++
				return nil
			}
			if info.Mode().Perm()&0o002 != 0 {
				res.WorldWritableDirs++
			}
			return nil
		}
		res.Files++
		if d.Type()&os.ModeSymlink != 0 {
			res.SymlinksSkipped++
			return nil // skip symlinked files too
		}
		info, statErr := d.Info()
		if statErr != nil {
			res.Unreadable++
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Mode().Perm()&0o002 != 0 {
			res.WorldWritableFiles++
		}
		if match(filepath.ToSlash(rel)) {
			if caps.MaxMatches > 0 && len(res.Matches) >= caps.MaxMatches {
				res.MatchesDropped++
				return nil
			}
			res.Matches = append(res.Matches, filepath.ToSlash(rel))
		}
		return nil
	})
	return res
}

// walk runs a bounded traversal and folds its accounting into the site's
// coverage record.
func (c *Context) walk(dir string, caps walkCaps, match func(rel string) bool) walkResult {
	res := walk(dir, caps, match)
	c.recordWalk(res)
	return res
}

// walkEvidence renders the standard coverage evidence shared by walk-backed
// checks: what was examined, and what was not.
func walkEvidence(res walkResult) map[string]string {
	ev := map[string]string{"files_examined": strconv.Itoa(res.Files)}
	if res.MatchesDropped > 0 {
		ev["matches_omitted"] = strconv.Itoa(res.MatchesDropped)
	}
	if res.Unreadable > 0 {
		ev["unreadable_entries"] = strconv.Itoa(res.Unreadable)
	}
	if res.Truncated {
		ev["truncation"] = res.TruncationReason
		ev["note"] = "walk stopped early (" + res.TruncationReason + " budget); results are partial — rerun with --deep for full coverage"
	}
	return ev
}

// itoa is the integer-to-string helper used when building evidence maps.
func itoa(n int) string { return strconv.Itoa(n) }

// fileExists reports whether path exists.
func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// fileSize returns the size of path, or -1 when unknown.
func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return st.Size()
}

// hasExtension reports whether name ends with one of the (lowercase) exts.
func hasExtension(name string, exts ...string) bool {
	lower := strings.ToLower(name)
	for _, e := range exts {
		if strings.HasSuffix(lower, e) {
			return true
		}
	}
	return false
}
