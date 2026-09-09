// Package version holds the build identity of the wpus binary.
package version

import "runtime"

// Build-time values. Overridden via -ldflags -X during release builds.
var (
	Name      = "wpus"
	Version   = "0.1.0"
	GitCommit = "dev"
	BuildDate = "unknown"
)

// UserAgent is used for the tool's own outbound HTTP requests
// (WordPress.org release API, vulnerability data feeds).
func UserAgent() string {
	return Name + "/" + Version + " (" + runtime.GOOS + "; " + runtime.GOARCH + ")"
}
