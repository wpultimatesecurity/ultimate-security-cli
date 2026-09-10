package app

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/discovery"
)

func newDiscoverCmd(globals *GlobalFlags) *cobra.Command {
	var asJSON bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "discover [path...]",
		Short: "Find WordPress installations without scanning",
		Long: `Locates WordPress installations on this machine (or validates the
given paths) without running security checks.

Exit code 0 when at least one installation is found; 1 otherwise.`,
		Example: `  wpus discover
  wpus discover /var/www
  wpus discover --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := discovery.Options{
				Explicit: args,
				Home:     homeDir(),
				Timeout:  timeout,
			}
			results := discovery.Discover(opts)
			out := cmd.OutOrStdout()
			if asJSON {
				// Machine consumers must always receive an array: a null
				// "sites" forces every consumer to special-case the empty
				// result.
				if results == nil {
					results = []discovery.Result{}
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(struct {
					Sites []discovery.Result `json:"sites"`
				}{results}); err != nil {
					return runtimeError{err}
				}
			} else {
				if len(results) == 0 {
					fmt.Fprintln(out, "no WordPress installations found")
				}
				for _, r := range results {
					if r.Valid {
						fmt.Fprintln(out, r.Path)
					} else {
						fmt.Fprintf(out, "%s  (%s)\n", r.Path, r.Note)
					}
				}
			}
			if discovery.ValidPaths(results) == nil {
				return errNotFound{}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output machine-readable JSON")
	cmd.Flags().DurationVar(&timeout, "timeout", discovery.DefaultTimeout, "discovery time budget (e.g. 30s)")
	return cmd
}

// errNotFound signals "no installations found" for discover (exit 1).
type errNotFound struct{}

func (errNotFound) Error() string { return "no valid WordPress installations found" }

func newChecksCmd(globals *GlobalFlags) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "List available security checks",
		Long: `Lists every registered check with its category and coverage
importance. "Importance" is the weight the check carries in the coverage
score: core checks are blind spots when they cannot run, context checks are
advisory.`,
		Example: `  wpus checks
  wpus checks --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			all := checks.All()
			out := cmd.OutOrStdout()
			if asJSON {
				type row struct {
					ID          string `json:"id"`
					Title       string `json:"title"`
					Category    string `json:"category"`
					Description string `json:"description"`
					// Importance drives the coverage score, so a consumer
					// reading the registry needs it to interpret coverage.
					Importance string `json:"importance"`
				}
				rows := make([]row, 0, len(all))
				for _, c := range all {
					rows = append(rows, row{
						ID: c.ID, Title: c.Title, Category: string(c.Category),
						Description: c.Description, Importance: c.Importance.String(),
					})
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Checks []row `json:"checks"`
				}{rows})
			}
			fmt.Fprintf(out, "%-34s %-18s %-9s %s\n", "ID", "CATEGORY", "IMPORTANCE", "DEFAULT")
			for _, c := range all {
				fmt.Fprintf(out, "%-34s %-18s %-9s %s\n", c.ID, c.Category, c.Importance.String(), "enabled")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output machine-readable JSON")
	return cmd
}

func newVersionCmd(versionInfo string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), versionInfo)
			if err != nil {
				return runtimeError{err}
			}
			return nil
		},
	}
}
