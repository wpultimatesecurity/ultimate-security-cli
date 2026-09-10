package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/baseline"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/config"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/discovery"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/platform"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/releases"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/reporting"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/sanitize"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/version"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/vulnerability"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wpcli"
)

// observedSite receives the resolved site model and WP-CLI bundle from
// scanSite. The report model deliberately carries only findings, so the
// recording command needs this out-parameter to capture the inventory without
// loading (or running WP-CLI on) the installation a second time.
type observedSite struct {
	site *wordpress.Site
	wp   *wpcli.Siteenv
}

type baselineCreateFlags struct {
	output   string
	live     bool
	offline  bool
	noConfig bool
}

func newBaselineCmd(globals *GlobalFlags) *cobra.Command {
	f := &baselineCreateFlags{}
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Record and compare installation baselines",
		Long: `A baseline records what an installation contained at a point in time —
components, drop-ins, administrators, and open findings — so a later scan
can answer "what changed since the last known-good state?".

Record one with ` + "`wpus baseline create`" + `, store it outside the site, and pass
it to ` + "`wpus scan --baseline`" + `.`,
	}
	create := &cobra.Command{
		Use:   "create <path>",
		Short: "Record a site's inventory as a baseline file",
		Long: `Runs the same static checks a scan runs and writes their inventory and
finding fingerprints to a JSON baseline. The file is written atomically and
must live outside the audited tree.

With --live, WP-CLI is additionally asked to load WordPress so administrator
accounts are recorded; without it, user drift cannot be compared later.`,
		Example: `  wpus baseline create /var/www/example.com --output baseline.json
  wpus baseline create ~/Sites/example --output baseline.json --live
  wpus scan /var/www/example.com --baseline baseline.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBaselineCreate(cmd, args[0], f, globals)
		},
	}
	create.Flags().StringVar(&f.output, "output", "", "write the baseline to this file (required)")
	create.Flags().BoolVar(&f.live, "live", false, "allow WP-CLI to load WordPress so administrator accounts are recorded")
	create.Flags().BoolVar(&f.offline, "offline", false, "disable all network access (release checks, REST probes, vulnerability feed)")
	create.Flags().BoolVar(&f.noConfig, "no-config", false, "ignore every configuration file")
	cmd.AddCommand(create)
	return cmd
}

func runBaselineCreate(cmd *cobra.Command, path string, f *baselineCreateFlags, globals *GlobalFlags) error {
	verbose := func(format string, args ...any) {
		if globals.Verbose {
			fmt.Fprintf(os.Stderr, "[wpus] "+format+"\n", args...)
		}
	}
	if f.output == "" {
		return usagef("baseline create needs --output <file>")
	}

	// Validate the target exactly as a scan validates an explicit path, so a
	// typo or a non-WordPress directory fails the same way.
	results := discovery.Discover(discovery.Options{Explicit: []string{path}})
	if len(results) != 1 {
		return usagef("%s: expected exactly one WordPress installation", path)
	}
	target := results[0]
	if !target.Valid {
		if strings.Contains(target.Note, "permission denied") {
			return permissionError{fmt.Errorf("%s: %s", target.Path, target.Note)}
		}
		return usagef("%s: %s (not a WordPress installation)", target.Path, target.Note)
	}
	// A baseline must never be written into the tree it describes.
	if err := rejectOutputInsideSites(f.output, []string{target.Path}); err != nil {
		return usageError{err}
	}

	cfg, cfgSource, err := config.Load(config.Options{
		NoConfig:  f.noConfig,
		ConfigDir: platform.ConfigDir(homeDir(), os.Getenv),
	})
	if err != nil {
		return usageError{err}
	}
	if cfgSource.Path != "" {
		verbose("config: %s", cfgSource.Path)
	}
	// The recorded findings must match what a scan produces, so the same
	// policy (disabled checks, severity overrides) applies here.
	opts, err := buildPolicy(cfg, &scanFlags{noConfig: f.noConfig}, verbose)
	if err != nil {
		return err
	}

	// Same services a scan builds: the finding fingerprints recorded here are
	// only comparable to a later scan if both saw the same check inputs.
	plat := platform.Current()
	var releaseClient *http.Client
	if !f.offline {
		releaseClient = &http.Client{Timeout: releaseTimeout}
	}
	var core *releases.Core
	if !f.offline {
		ctx, cancel := context.WithTimeout(context.Background(), releaseTimeout)
		c, err := releases.FetchCore(ctx, releaseClient, platform.CacheDir(homeDir(), os.Getenv))
		cancel()
		if err != nil {
			verbose("release data unavailable: %v", err)
		} else {
			verbose("latest WordPress release: %s", c.Latest)
			core = c
		}
	}
	vulns := vulnerability.Provider(vulnerability.Unavailable{})
	if !f.offline {
		vulns = vulnProvider(os.Getenv, platform.CacheDir(homeDir(), os.Getenv), &http.Client{Timeout: feedTimeout})
	}
	var checksumSrc checksumSource
	if !f.offline {
		checksumSrc = checksumSource{
			client:   &http.Client{Timeout: releaseTimeout},
			cacheDir: platform.CacheDir(homeDir(), os.Getenv),
		}
	}
	var runner *wpcli.Runner
	if f.live {
		runner = wpcli.Detect(os.Getenv)
		if runner != nil {
			runner.Log = func(s string) { verbose("%s", sanitize.Log(s)) }
			fmt.Fprintln(os.Stderr, "warning: --live lets WP-CLI load the audited site; target-controlled PHP will execute")
		} else {
			verbose("WP-CLI not detected; --live has no effect")
		}
	}

	observed := &observedSite{}
	report, err := scanSite(target.Path, scanSiteOpts{
		opts: opts, ctx: context.Background(), core: core,
		vulns: vulns, checksums: checksumSrc,
		runner: runner, offline: f.offline, deep: false,
		plat: plat, verbose: verbose, observed: observed,
	})
	if err != nil {
		if _, ok := err.(insufficientPermissions); ok {
			return permissionError{err}
		}
		return runtimeError{err}
	}

	record := baselineFrom(observed, report)
	if err := record.Save(f.output); err != nil {
		return runtimeError{err}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "baseline written to %s\n", sanitize.Path(f.output))
	return nil
}

// baselineFrom records the inventory the drift check compares: the site model
// for components and drop-ins, the live WP-CLI bundle for administrators, and
// the fingerprints of the findings this run reported. It reuses the check's
// own snapshot builder so a recorded baseline and a later comparison can never
// disagree about what the installation is.
func baselineFrom(observed *observedSite, report *reporting.SiteReport) *baseline.Baseline {
	snap := checks.BaselineSnapshot(&checks.Context{
		Site:     observed.site,
		WP:       observed.wp,
		Findings: report.Findings,
	})
	return &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		CreatedAt:     time.Now().UTC(),
		Tool:          version.Name + " " + version.Version,
		WordPress:     snap.WordPress,
		Plugins:       snap.Plugins,
		Themes:        snap.Themes,
		MuPlugins:     snap.MuPlugins,
		Dropins:       snap.Dropins,
		Admins:        snap.Admins,
		Findings:      snap.Findings,
	}
}
