package wordpress

import (
	"os"
	"path/filepath"
	"strings"
)

// Must-use plugins and drop-ins are the two persistence mechanisms that a
// plugin-inventory-only scanner misses entirely. MU plugins are auto-loaded
// without appearing in the plugin list, and drop-ins run at privileged points
// in the WordPress bootstrap, before plugins and sometimes before the
// database. Both are prime locations for attacker persistence, so they are
// inventoried explicitly.

// Dropin is one WordPress drop-in file.
type Dropin struct {
	// File is the drop-in's basename inside the content directory.
	File string
	// Path is the absolute path on disk.
	Path string
	// Purpose describes what WordPress loads the file for.
	Purpose string
}

// knownDropins maps each documented drop-in to its load point.
var knownDropins = map[string]string{
	"advanced-cache.php":      "advanced caching; loaded before regular plugins",
	"db.php":                  "custom database layer; loaded before regular plugins",
	"db-error.php":            "custom database error handler",
	"install.php":             "custom installation routine",
	"maintenance.php":         "custom maintenance-mode page",
	"object-cache.php":        "persistent object cache; loaded before regular plugins",
	"php-error.php":           "custom PHP error handler (WordPress 6.1+)",
	"fatal-error-handler.php": "fatal error handler (WordPress 5.2+)",
	"sunrise.php":             "multisite domain mapping; loaded very early",
}

// DropinPurpose returns the documented purpose of a drop-in filename.
func DropinPurpose(file string) string {
	if p, ok := knownDropins[strings.ToLower(file)]; ok {
		return p
	}
	return ""
}

// LoadMUPlugins inventories must-use plugins in dir. WordPress loads only
// top-level *.php files from the MU directory (subdirectories require an
// explicit loader), so that is exactly what is reported.
func LoadMUPlugins(dir string) []Plugin {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Plugin
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".php") {
			continue
		}
		if p := pluginFromFile(dir, name); p.Slug != "" {
			out = append(out, p)
		}
	}
	return out
}

// LoadDropins enumerates the drop-in files present in the content directory.
// Files are matched against the documented set; anything else in the content
// root is ordinary WordPress content.
func LoadDropins(contentDir string) []Dropin {
	entries, err := os.ReadDir(contentDir)
	if err != nil {
		return nil
	}
	var out []Dropin
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		purpose := DropinPurpose(name)
		if purpose == "" {
			continue
		}
		out = append(out, Dropin{
			File:    e.Name(),
			Path:    filepath.Join(contentDir, e.Name()),
			Purpose: purpose,
		})
	}
	return out
}
