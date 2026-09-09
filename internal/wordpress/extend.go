package wordpress

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Plugin/theme "header" fields are declared in DocComment style:
//
//	Plugin Name: X / Version: 1.2.3   (in the main plugin PHP file)
//	Theme Name:  X / Version: 1.2.3   (in style.css)
//
// Parsing is a plain scan of small header files — no PHP execution.

var headerField = regexp.MustCompile(`(?m)^[ \t\*/]*([A-Za-z ][A-Za-z0-9 _\-]*?):[ \t]*(.+?)[ \t\*/]*$`)

// maxHeaderFile bounds how much of a header file is read.
const maxHeaderFile = 64 << 10 // 64 KiB

func parseHeaderFile(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path) //nolint:gosec // site under audit
	if err != nil {
		return out
	}
	defer f.Close() //nolint:errcheck
	buf := make([]byte, maxHeaderFile)
	n, _ := f.Read(buf)
	if n <= 0 {
		return out
	}
	src := string(buf[:n])
	for _, m := range headerField.FindAllStringSubmatch(src, -1) {
		key := strings.ToUpper(strings.TrimSpace(m[1]))
		val := strings.TrimSpace(m[2])
		if _, exists := out[key]; !exists {
			out[key] = val
		}
	}
	return out
}

// LoadPlugins reads plugin metadata from a wp-content/plugins directory.
// Returns an empty slice when the directory is absent or unreadable.
func LoadPlugins(dir string) []Plugin {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Plugin
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			continue
		}
		if !e.IsDir() {
			// Single-file plugin: hello.php
			if strings.HasSuffix(strings.ToLower(name), ".php") {
				if p := pluginFromFile(dir, name); p.Slug != "" {
					out = append(out, p)
				}
			}
			continue
		}
		p := pluginFromDir(filepath.Join(dir, name), name)
		if p.Slug != "" {
			out = append(out, p)
		}
	}
	return out
}

func pluginFromDir(dir, slug string) Plugin {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Plugin{}
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(n), ".php") || strings.HasPrefix(n, ".") {
			continue
		}
		h := parseHeaderFile(filepath.Join(dir, n))
		if pn, ok := h["PLUGIN NAME"]; ok {
			return Plugin{Slug: slug, Name: pn, Version: h["VERSION"]}
		}
	}
	return Plugin{}
}

func pluginFromFile(dir, file string) Plugin {
	h := parseHeaderFile(filepath.Join(dir, file))
	if pn, ok := h["PLUGIN NAME"]; ok {
		return Plugin{
			Slug:    strings.TrimSuffix(file, filepath.Ext(file)),
			Name:    pn,
			Version: h["VERSION"],
		}
	}
	return Plugin{}
}

// LoadThemes reads theme metadata from a wp-content/themes directory.
func LoadThemes(dir string) []Theme {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Theme
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		h := parseHeaderFile(filepath.Join(dir, e.Name(), "style.css"))
		if tn, ok := h["THEME NAME"]; ok {
			out = append(out, Theme{
				Slug:    e.Name(),
				Name:    tn,
				Version: h["VERSION"],
			})
		}
	}
	return out
}
