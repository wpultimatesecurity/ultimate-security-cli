package app

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
)

// Exit codes. They are a stable contract for automation:
//
//	0 scan completed and policy passed
//	1 policy failure (findings at or above --fail-on, or coverage below
//	  --fail-on-coverage-below)
//	2 usage or configuration error
//	3 runtime failure
//	4 permission failure
//	5 no targets scanned (a scan that inspected nothing must not pass CI)
const (
	ExitOK         = 0
	ExitFindings   = 1
	ExitUsage      = 2
	ExitError      = 3
	ExitPermission = 4
	ExitNoTargets  = 5
)

// GlobalFlags are the flags every command accepts.
type GlobalFlags struct {
	NoColor bool
	Quiet   bool
	Verbose bool
}

// colorEnabled decides whether stdout gets ANSI color: explicit flag wins,
// then NO_COLOR/CLICOLOR_FORCE env, then TTY detection.
func colorEnabled(noColor bool) bool {
	if noColor {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("CLICOLOR_FORCE") != "" && os.Getenv("CLICOLOR_FORCE") != "0" {
		return true
	}
	if st, err := os.Stdout.Stat(); err == nil {
		return st.Mode()&os.ModeCharDevice != 0
	}
	return false
}

// usageError wraps a cobra RunE error meaning "bad arguments" (exit 2).
type usageError struct{ err error }

func (u usageError) Error() string { return u.err.Error() }

func usagef(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

// runtimeError marks scan/runtime failures (exit 3).
type runtimeError struct{ err error }

func (r runtimeError) Error() string { return r.err.Error() }

// permissionError marks denied access (exit 4).
type permissionError struct{ err error }

func (p permissionError) Error() string { return p.err.Error() }

// NewRoot builds the wpus root command.
func NewRoot(versionInfo string) *cobra.Command {
	var globals GlobalFlags

	root := &cobra.Command{
		Use:   "wpus",
		Short: "Ultimate Security CLI — local, read-only WordPress security auditing",
		// The count comes from the registry so the help text cannot drift.
		Long: fmt.Sprintf(`wpus audits the security posture of local WordPress installations.

It discovers WordPress sites on the machine, runs %d read-only security checks
(core and file integrity, configuration, plugins, themes, must-use plugins and
drop-ins, filesystem, PHP, web server, exposure, network), and reports for
humans (terminal), documents (markdown), machines (JSON), and code scanning
(SARIF).`, len(checks.All())) + `

Scans never modify the site, and a default scan never executes the audited
site's PHP. Two scores are produced: a risk score for the findings, and a
coverage score for how much of the audit actually ran — a clean risk score
with low coverage means "not examined", not "secure".

Use --live to let WP-CLI load WordPress for additional facts (this executes
target-controlled code), and ` + "`wpus baseline create`" + ` / ` + "`--baseline`" + ` to
compare an installation against a recorded state.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVar(&globals.NoColor, "no-color", false, "disable ANSI color output")
	root.PersistentFlags().BoolVarP(&globals.Quiet, "quiet", "q", false, "suppress decorative output")
	root.PersistentFlags().BoolVarP(&globals.Verbose, "verbose", "v", false, "verbose diagnostics on stderr")

	root.AddCommand(
		newScanCmd(&globals),
		newBaselineCmd(&globals),
		newDiscoverCmd(&globals),
		newChecksCmd(&globals),
		newVersionCmd(versionInfo),
	)
	return root
}

// ExecuteWithWriters runs the CLI against explicit writers (used by tests).
func ExecuteWithWriters(versionInfo string, args []string, stdout, stderr io.Writer) int {
	root := NewRoot(versionInfo)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	fmt.Fprintln(stderr, "error:", err)
	switch err.(type) {
	case usageError:
		return ExitUsage
	case permissionError:
		return ExitPermission
	case runtimeError:
		return ExitError
	case exitNoTargetsError:
		return ExitNoTargets
	case exitFindingsError, exitCoverageError, errNotFound:
		// Policy outcome, not a crash: findings met the threshold (or
		// discover found nothing). Distinguish from usage errors.
		return ExitFindings
	}
	// Cobra flag parse errors land here.
	return ExitUsage
}

// Execute runs the root command with process-standard streams.
func Execute(versionInfo string, args []string) int {
	return ExecuteWithWriters(versionInfo, args, os.Stdout, os.Stderr)
}
