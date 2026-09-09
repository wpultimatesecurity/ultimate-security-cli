package checks

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// walkCaps bound every filesystem walk a check performs. A normal scan must
// stay fast on huge sites; --deep raises the budget.
type walkCaps struct {
	Deadline time.Time
	MaxFiles int
	MaxDepth int
}

func defaultCaps(deep bool) walkCaps {
	if deep {
		return walkCaps{Deadline: time.Now().Add(30 * time.Second), MaxFiles: 250_000, MaxDepth: 16}
	}
	return walkCaps{Deadline: time.Now().Add(5 * time.Second), MaxFiles: 50_000, MaxDepth: 12}
}

// walkResult summarizes one bounded walk.
type walkResult struct {
	Files              int
	Truncated          bool // budget exhausted; results are partial
	Matches            []string
	WorldWritableFiles int
	WorldWritableDirs  int
}

// walk is a bounded walker rooted at dir. match is called for every regular
// file (relative path); return true to record it. Directory symlinks are
// never followed. Hidden directories are skipped.
func walk(dir string, caps walkCaps, match func(rel string) bool) walkResult {
	var res walkResult
	rootRel := ""
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fs.SkipDir
		}
		if len(res.Matches) > 0 && time.Now().After(caps.Deadline) {
			res.Truncated = true
			return fs.SkipAll
		}
		if res.Files >= caps.MaxFiles {
			res.Truncated = true
			return fs.SkipAll
		}
		name := d.Name()
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return fs.SkipDir
		}
		if rel == "." {
			return nil
		}
		if strings.HasPrefix(name, ".") && rel != rootRel {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			depth := strings.Count(filepath.ToSlash(rel), "/")
			if depth >= caps.MaxDepth {
				return fs.SkipDir
			}
			if d.Type()&os.ModeSymlink != 0 {
				return fs.SkipDir // never follow directory symlinks
			}
			if info, statErr := d.Info(); statErr == nil {
				if info.Mode().Perm()&0o002 != 0 {
					res.WorldWritableDirs++
				}
			}
			return nil
		}
		res.Files++
		if d.Type()&os.ModeSymlink != 0 {
			return nil // skip symlinked files too
		}
		if info, statErr := d.Info(); statErr == nil && info.Mode().IsRegular() {
			if info.Mode().Perm()&0o002 != 0 {
				res.WorldWritableFiles++
			}
			if match(filepath.ToSlash(rel)) && len(res.Matches) < 50 {
				res.Matches = append(res.Matches, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	return res
}

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
