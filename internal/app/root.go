package app

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes.
const (
	ExitOK         = 0
	ExitFindings   = 1
	ExitUsage      = 2
	ExitError      = 3
	ExitPermission = 4
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
		Long: `wpus audits the security posture of local WordPress installations.

It discovers WordPress sites on the machine, runs a battery of read-only
security checks (core, configuration, plugins, themes, filesystem, PHP,
server, network), computes a deterministic score, and reports for humans
(terminal), documents (markdown), and AI agents (JSON).

Scans never modify the site.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVar(&globals.NoColor, "no-color", false, "disable ANSI color output")
	root.PersistentFlags().BoolVarP(&globals.Quiet, "quiet", "q", false, "suppress decorative output")
	root.PersistentFlags().BoolVarP(&globals.Verbose, "verbose", "v", false, "verbose diagnostics on stderr")

	root.AddCommand(
		newScanCmd(&globals),
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
	case exitFindingsError, errNotFound:
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
