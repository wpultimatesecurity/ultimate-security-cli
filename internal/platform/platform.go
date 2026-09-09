// Package platform isolates OS/architecture specifics: identity strings,
// user directories, and platform-appropriate defaults for discovery.
package platform

import (
	"runtime"
	"strings"
)

// Info describes the runtime platform.
type Info struct {
	OS   string // "linux" or "darwin" (runtime.GOOS)
	Arch string // "amd64" or "arm64" (runtime.GOARCH)
}

// Current returns the runtime platform identity.
func Current() Info {
	return Info{OS: runtime.GOOS, Arch: runtime.GOARCH}
}

// DisplayName renders the OS in human-friendly form ("macOS" / "Linux").
func (i Info) DisplayName() string {
	switch i.OS {
	case "darwin":
		return "macOS"
	case "linux":
		return "Linux"
	default:
		return i.OS
	}
}

// Triple renders the release-target form used by goreleaser ("darwin-arm64").
func (i Info) Triple() string {
	return i.OS + "-" + i.Arch
}

// Supported reports whether the binary is running on a V1-supported platform.
func (i Info) Supported() bool {
	switch i.OS {
	case "linux", "darwin":
		return i.Arch == "amd64" || i.Arch == "arm64"
	default:
		return false
	}
}

// ConfigDir returns the per-user configuration directory for wpus:
// Linux: ~/.config/wpus, macOS: ~/Library/Application Support/wpus.
// The WPUS_CONFIG_DIR environment variable overrides the result.
func ConfigDir(home string, getenv func(string) string) string {
	if d := getenv("WPUS_CONFIG_DIR"); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "darwin":
		return home + "/Library/Application Support/wpus"
	default: // linux and other unix-likes
		if d := getenv("XDG_CONFIG_HOME"); d != "" {
			return d + "/wpus"
		}
		return home + "/.config/wpus"
	}
}

// CacheDir returns the per-user cache directory for wpus
// (vulnerability feed and release-data caches).
func CacheDir(home string, getenv func(string) string) string {
	if d := getenv("WPUS_CACHE_DIR"); d != "" {
		return d
	}
	switch runtime.GOOS {
	case "darwin":
		return home + "/Library/Caches/wpus"
	default:
		if d := getenv("XDG_CACHE_HOME"); d != "" {
			return d + "/wpus"
		}
		return home + "/.cache/wpus"
	}
}

// IsLoopbackHost reports whether a hostname refers to the local machine,
// where plain HTTP is a normal development setup.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	switch h {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	// Common local dev TLDs (Valet, DDEV, Docker Compose projects).
	for _, suffix := range []string{".localhost", ".local", ".test", ".internal"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return strings.HasPrefix(h, "127.") && strings.Count(h, ".") == 3
}
