// Command wpus is the Ultimate Security CLI: a local, read-only WordPress
// security auditor for humans and AI agents.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/app"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/version"
)

func main() {
	info := fmt.Sprintf("%s %s (%s %s/%s), commit %s, built %s",
		version.Name, version.Version, "go", runtime.GOOS, runtime.GOARCH,
		version.GitCommit, version.BuildDate)
	os.Exit(app.Execute(info, os.Args[1:]))
}
