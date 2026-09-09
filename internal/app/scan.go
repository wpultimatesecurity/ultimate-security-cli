package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/config"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/discovery"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/platform"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/redaction"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/releases"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/reporting"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/version"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/vulnerability"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wpcli"
)

type scanFlags struct {
	paths        []string
	format       string
	asJSON       bool
	severity     string
	failOn       string
	exclude      []string
	excludeCheck []string
	offline      bool
	deep         bool
	skipWPCLI    bool
	timeout      time.Duration
}

func newScanCmd(globals *GlobalFlags) *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Audit WordPress installation(s) (default command)",
		Long: `Scans WordPress installations with read-only security checks.

With no path arguments, wpus discovers installations in standard locations.
Pass one or more paths to scan specific sites. Results are scored and
reported; exit code reflects the --fail-on policy.`,
		Example: `  wpus scan
  wpus scan /var/www/example.com
  wpus scan ~/Sites/example --format markdown
  wpus scan --json --fail-on high`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args, f, globals)
		},
	}
	cmd.Flags().StringArrayVarP(&f.paths, "path", "p", nil, "site path(s) to scan (repeatable)")
	cmd.Flags().StringVar(&f.format, "format", "terminal", "output format: terminal, json, markdown")
	cmd.Flags().BoolVar(&f.asJSON, "json", false, "shorthand for --format json")
	cmd.Flags().StringVar(&f.severity, "severity", "", "only report failed findings at or above: critical, high, medium, low, info")
	cmd.Flags().StringVar(&f.failOn, "fail-on", "", "exit 1 when findings meet or exceed: critical, high, medium, low")
	cmd.Flags().StringArrayVar(&f.exclude, "exclude", nil, "exclude path(s) from discovery (repeatable)")
	cmd.Flags().StringArrayVar(&f.excludeCheck, "exclude-check", nil, "skip a check by ID (repeatable)")
	cmd.Flags().BoolVar(&f.offline, "offline", false, "disable all network access (release checks, REST probes)")
	cmd.Flags().BoolVar(&f.deep, "deep", false, "raise filesystem walk budgets for deeper inspection")
	cmd.Flags().BoolVar(&f.skipWPCLI, "skip-wpcli", false, "do not use WP-CLI even when available")
	cmd.Flags().DurationVar(&f.timeout, "timeout", discovery.DefaultTimeout, "discovery time budget (e.g. 30s)")
	return cmd
}

func runScan(cmd *cobra.Command, args []string, f *scanFlags, globals *GlobalFlags) error {
	start := time.Now()
	verbose := func(format string, args ...any) {
		if globals.Verbose {
			fmt.Fprintf(os.Stderr, "[wpus] "+format+"\n", args...)
		}
	}

	// Flags + config file.
	cfg, cfgPath, err := config.LoadFirst(platform.ConfigDir(homeDir(), os.Getenv))
	if err != nil {
		return usageError{err}
	}
	if cfgPath != "" {
		verbose("config: %s", cfgPath)
	}
	excludes := append(append([]string{}, cfg.Exclude...), f.exclude...)
	disabled := map[string]bool{}
	for _, id := range cfg.Checks.Disabled {
		disabled[id] = true
	}
	for _, id := range f.excludeCheck {
		disabled[id] = true
	}
	failOn := firstNonEmpty(f.failOn, cfg.FailOn)
	if f.asJSON {
		f.format = "json"
	}

	// Validate severity options early (exit 2 territory).
	if f.severity != "" {
		if _, ok := checks.ParseSeverity(f.severity); !ok {
			return usagef("invalid --severity %q (use critical|high|medium|low|info)", f.severity)
		}
	}
	if failOn != "" {
		if _, ok := checks.ParseSeverity(failOn); !ok {
			return usagef("invalid --fail-on %q (use critical|high|medium|low)", f.failOn)
		}
	}
	switch f.format {
	case "terminal", "json", "markdown":
	default:
		return usagef("invalid --format %q (use terminal|json|markdown)", f.format)
	}

	// Shared services.
	plat := platform.Current()
	var httpClient *http.Client
	if !f.offline {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	var core *releases.Core
	if !f.offline {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		c, err := releases.FetchCore(ctx, httpClient, platform.CacheDir(homeDir(), os.Getenv))
		cancel()
		if err != nil {
			verbose("release data unavailable: %v", err)
		} else {
			verbose("latest WordPress release: %s", c.Latest)
			core = c
		}
	}
	vulns := vulnProvider(os.Getenv, platform.CacheDir(homeDir(), os.Getenv), httpClient)
	var runner *wpcli.Runner
	if !f.skipWPCLI {
		runner = wpcli.Detect(os.Getenv)
	}
	if runner != nil {
		runner.Log = func(s string) { verbose("%s", s) }
	} else {
		verbose("WP-CLI not detected; filesystem-only scan")
	}

	// Resolve sites.
	explicit := append(append([]string{}, f.paths...), args...)
	excluded := map[string]bool{}
	for _, p := range excludes {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		excluded[abs] = true
	}

	var sitePaths []string
	if len(explicit) > 0 {
		results := discovery.Discover(discovery.Options{Explicit: explicit})
		for _, r := range results {
			if excluded[r.Path] {
				continue
			}
			if !r.Valid {
				if strings.Contains(r.Note, "permission denied") {
					return permissionError{fmt.Errorf("%s: %s", r.Path, r.Note)}
				}
				return usagef("%s: %s (not a WordPress installation)", r.Path, r.Note)
			}
			sitePaths = append(sitePaths, r.Path)
		}
	} else {
		if globals.Verbose {
			verbose("discovering WordPress installations…")
		}
		results := discovery.Discover(discovery.Options{Home: homeDir(), Timeout: f.timeout})
		for _, r := range results {
			if r.Valid && !excluded[r.Path] {
				sitePaths = append(sitePaths, r.Path)
			}
		}
		if len(sitePaths) == 0 {
			// Not an error: render an empty report so agents can parse the
			// output, then explain on stderr.
			empty := &reporting.Report{
				SchemaVersion: reporting.SchemaVersion,
				Tool:          reporting.ToolInfo{Name: version.Name, Version: version.Version},
				Environment:   plat,
				Scan: reporting.ScanInfo{
					StartedAt:  start.UTC(),
					DurationMs: time.Since(start).Milliseconds(),
					Offline:    f.offline,
					Deep:       f.deep,
				},
				Meta: map[string]string{"note": "no WordPress installations found"},
			}
			if renderErr := renderReport(cmd, empty, f, globals); renderErr != nil {
				return runtimeError{renderErr}
			}
			fmt.Fprintln(os.Stderr, "no WordPress installations found (pass a path, e.g. `wpus scan /path/to/site`)")
			return nil
		}
	}

	// Scan each site.
	report := &reporting.Report{
		SchemaVersion: reporting.SchemaVersion,
		Tool:          reporting.ToolInfo{Name: version.Name, Version: version.Version},
		Environment:   plat,
		Scan: reporting.ScanInfo{
			StartedAt: start.UTC(),
			Offline:   f.offline,
			Deep:      f.deep,
			ChecksRun: len(checks.Options{Disabled: disabled}.Selected()),
		},
	}
	opts := checks.Options{Disabled: disabled}
	if f.severity != "" {
		opts.MinSeverity, _ = checks.ParseSeverity(f.severity)
	}

	for _, path := range sitePaths {
		siteReport, err := scanSite(path, scanSiteOpts{
			opts: opts, ctx: context.Background(), http: httpClient, core: core,
			vulns: vulns, runner: runner, offline: f.offline, deep: f.deep,
			plat: plat, verbose: verbose,
		})
		if err != nil {
			if _, ok := err.(insufficientPermissions); ok {
				return permissionError{err}
			}
			return runtimeError{err}
		}
		report.Sites = append(report.Sites, *siteReport)
	}
	report.Scan.DurationMs = time.Since(start).Milliseconds()
	report.Summary = reporting.Tally(report.Sites)

	// Render.
	if err := renderReport(cmd, report, f, globals); err != nil {
		return runtimeError{err}
	}

	// Exit policy.
	if failOn != "" && meetsThreshold(report.Sites, checks.Severity(failOn)) {
		return exitFindingsError{threshold: failOn}
	}
	return nil
}

// renderReport writes the report in the requested format.
func renderReport(cmd *cobra.Command, report *reporting.Report, f *scanFlags, globals *GlobalFlags) error {
	out := cmd.OutOrStdout()
	switch f.format {
	case "json":
		return reporting.WriteJSON(out, report)
	case "markdown":
		return reporting.WriteMarkdown(out, report)
	default:
		term := reporting.Terminal{Opts: reporting.TerminalOptions{
			Color: colorEnabled(globals.NoColor), Quiet: globals.Quiet, Verbose: globals.Verbose,
		}}
		return term.Write(out, report)
	}
}

type scanSiteOpts struct {
	opts    checks.Options
	ctx     context.Context
	http    *http.Client
	core    *releases.Core
	vulns   vulnerability.Provider
	runner  *wpcli.Runner
	offline bool
	deep    bool
	plat    platform.Info
	verbose func(string, ...any)
}

type insufficientPermissions struct{ err error }

func (i insufficientPermissions) Error() string { return i.err.Error() }

func scanSite(path string, o scanSiteOpts) (*reporting.SiteReport, error) {
	if _, err := os.Stat(filepath.Join(path, "wp-includes")); err != nil {
		if os.IsPermission(err) {
			return nil, insufficientPermissions{fmt.Errorf("%s: permission denied", path)}
		}
	}
	site, err := wordpress.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", path, err)
	}

	var env *wpcli.Siteenv
	wpAvailable := false
	if o.runner != nil && o.runner.Available() {
		o.verbose("wp-cli: collecting %s", path)
		env = o.runner.Collect(path)
		wpAvailable = env.Version != "" || env.SiteURL != "" || len(env.Plugins) > 0
		if !wpAvailable {
			o.verbose("wp-cli: no usable response (database down or not a working site)")
		}
	}
	if env != nil {
		if env.Version != "" && site.Version == "" {
			site.Version = env.Version
		}
		site.ActivePlugins = activeSlugs(env.Plugins)
		for _, t := range env.Themes {
			if strings.EqualFold(t.Status, "active") {
				site.ActiveTheme = t.Name
			}
		}
		if len(env.Admins) > 0 {
			site.AdminUsers = make([]wordpress.User, 0, len(env.Admins))
			for _, u := range env.Admins {
				site.AdminUsers = append(site.AdminUsers, wordpress.User{
					ID: u.ID, Login: u.Login, Email: u.Email, Roles: u.Roles, Registered: u.Registered,
				})
			}
		}
		site.SiteURL = firstNonEmpty(env.SiteURL, site.SiteURL)
		site.HomeURL = firstNonEmpty(env.HomeURL, site.HomeURL)
		site.WPCLIPHPVersion = env.PHP
		site.XMLRPCEnabled = env.XMLRPC
	}

	ctx := &checks.Context{
		Site:        site,
		WP:          env,
		WPAvailable: wpAvailable,
		Vulns:       o.vulns,
		Core:        o.core,
		HTTP:        o.http,
		BaseURL:     firstNonEmpty(site.HomeURL, site.SiteURL),
		Ctx:         o.ctx,
		Offline:     o.offline,
		Deep:        o.deep,
		Platform:    o.plat,
		Server:      checks.DetectWebServer(site.Path),
	}

	var findings []checks.Finding
	for _, c := range o.opts.Selected() {
		findings = append(findings, runOneCheck(c, ctx)...)
	}
	findings = o.opts.FilterFindings(findings)
	checks.SortFindings(findings)

	// Central redaction: the only path findings take to reporters.
	scrub := redaction.NewScrubber(siteSecretLiterals(site)...)
	for i := range findings {
		findings[i] = redactFinding(scrub, findings[i])
	}

	score, cats := reporting.SiteScore(findings)
	sr := &reporting.SiteReport{
		Path:       site.Path,
		WordPress:  site.Version,
		Server:     ctx.Server,
		Score:      score,
		Categories: cats,
		Findings:   findings,
	}
	if site.WPCLIPHPVersion != "" {
		sr.PHP = site.WPCLIPHPVersion
		sr.PHPSource = "wp-cli runtime"
	}
	if env != nil && !wpAvailable {
		sr.Notes = append(sr.Notes, "WP-CLI present but site not responding (database down?) — WP-CLI-backed checks skipped")
	}
	return sr, nil
}

// runOneCheck executes a check with panic isolation: a broken check must
// not take down the scan.
func runOneCheck(c *checks.Simple, ctx *checks.Context) (out []checks.Finding) {
	defer func() {
		if r := recover(); r != nil {
			out = []checks.Finding{{
				ID: c.ID, Title: c.Title, Category: c.Category,
				Severity: checks.SevInfo, Status: checks.StatusUnknown,
				Confidence:  checks.ConfLow,
				Description: fmt.Sprintf("check panicked: %v", r),
			}}
		}
	}()
	return c.Run(ctx)
}

func redactFinding(scrub *redaction.Scrubber, f checks.Finding) checks.Finding {
	f.Description = scrub.Scrub(f.Description)
	f.Recommendation = scrub.Scrub(f.Recommendation)
	if f.Evidence != nil {
		f.Evidence = scrub.Map(f.Evidence)
	}
	f.References = scrub.Slice(f.References)
	return f
}

// siteSecretLiterals extracts secret values that must never appear in output.
func siteSecretLiterals(site *wordpress.Site) []string {
	if site.Config == nil {
		return nil
	}
	return site.Config.SecretLiterals
}

func meetsThreshold(sites []reporting.SiteReport, threshold checks.Severity) bool {
	for _, s := range sites {
		for _, f := range s.Findings {
			if f.Status == checks.StatusFailed && f.Severity.Rank() >= threshold.Rank() {
				return true
			}
		}
	}
	return false
}

// vulnProvider builds the vulnerability data provider from the environment.
func vulnProvider(getenv func(string) string, cacheDir string, client *http.Client) vulnerability.Provider {
	if file := getenv("WPUS_VULNDB_FILE"); file != "" {
		return &vulnerability.Wordfence{FeedFile: file, CacheDir: cacheDir, Client: client}
	}
	if token := getenv("WPUS_WORDFENCE_TOKEN"); token != "" {
		return &vulnerability.Wordfence{Token: token, CacheDir: cacheDir, Client: client}
	}
	return vulnerability.Unavailable{}
}

func activeSlugs(rows []wpcli.ExtStatus) []string {
	var out []string
	for _, r := range rows {
		if strings.EqualFold(r.Status, "active") {
			out = append(out, r.Name)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// exitFindingsError signals the fail-threshold outcome (exit 1).
type exitFindingsError struct{ threshold string }

func (e exitFindingsError) Error() string {
	return fmt.Sprintf("findings met or exceeded the --fail-on %s threshold", e.threshold)
}
