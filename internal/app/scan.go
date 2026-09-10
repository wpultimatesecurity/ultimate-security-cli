package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/baseline"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/config"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/discovery"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/platform"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/probe"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/redaction"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/releases"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/reporting"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/sanitize"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/version"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/vulnerability"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wpcli"
)

const (
	// releaseTimeout bounds the WordPress.org release lookup (small JSON).
	releaseTimeout = 15 * time.Second
	// feedTimeout bounds the (large) vulnerability feed download.
	feedTimeout = 5 * time.Minute
)

type scanFlags struct {
	paths               []string
	format              string
	asJSON              bool
	severity            string
	failOn              string
	failOnCoverageBelow int
	exclude             []string
	excludeCheck        []string
	offline             bool
	deep                bool
	live                bool
	allowEmpty          bool
	configPath          string
	trustProjectConfig  bool
	noConfig            bool
	output              string
	baseline            string
	verifyPluginSums    bool
	timeout             time.Duration
}

func newScanCmd(globals *GlobalFlags) *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan [path...]",
		Short: "Audit WordPress installation(s) (default command)",
		Long: `Scans WordPress installations with read-only security checks.

With no path arguments, wpus discovers installations in standard locations.
Pass one or more paths to scan specific sites. Results are scored and
reported; exit code reflects the --fail-on policy.

By default the scan is purely static: the audited site's PHP is never
executed. Pass --live to additionally let WP-CLI load WordPress, which is
faster and richer but runs code the site controls.`,
		Example: `  wpus scan
  wpus scan /var/www/example.com
  wpus scan ~/Sites/example --format markdown
  wpus scan --json --fail-on high
  wpus scan --live --vulnerability-feed
  wpus scan /srv/site --format sarif --output results.sarif`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, args, f, globals)
		},
	}
	cmd.Flags().StringArrayVarP(&f.paths, "path", "p", nil, "site path(s) to scan (repeatable)")
	cmd.Flags().StringVar(&f.format, "format", "terminal", "output format: terminal, json, markdown, sarif")
	cmd.Flags().BoolVar(&f.asJSON, "json", false, "shorthand for --format json")
	cmd.Flags().StringVar(&f.output, "output", "", "write the report to a file (atomic) instead of stdout")
	cmd.Flags().StringVar(&f.baseline, "baseline", "", "compare the installation against a baseline recorded by `wpus baseline create` and report the drift")
	cmd.Flags().StringVar(&f.severity, "severity", "", "only report failed findings at or above: critical, high, medium, low, info")
	cmd.Flags().StringVar(&f.failOn, "fail-on", "", "exit 1 when findings meet or exceed: critical, high, medium, low")
	cmd.Flags().IntVar(&f.failOnCoverageBelow, "fail-on-coverage-below", 0, "exit 1 when a site's scan coverage score is below this percentage (0 disables)")
	cmd.Flags().StringArrayVar(&f.exclude, "exclude", nil, "exclude path(s) from discovery (repeatable)")
	cmd.Flags().StringArrayVar(&f.excludeCheck, "exclude-check", nil, "skip a check by ID (repeatable)")
	cmd.Flags().BoolVar(&f.offline, "offline", false, "disable all network access (release checks, REST probes, vulnerability feed)")
	cmd.Flags().BoolVar(&f.deep, "deep", false, "raise filesystem walk budgets for deeper inspection")
	cmd.Flags().BoolVar(&f.live, "live", false, "allow WP-CLI to load WordPress for extra facts (executes target-controlled PHP)")
	cmd.Flags().BoolVar(&f.allowEmpty, "allow-empty", false, "exit 0 when discovery finds no installation (explicit opt-in)")
	cmd.Flags().StringVar(&f.configPath, "config", "", "use this configuration file (overrides the user config)")
	cmd.Flags().BoolVar(&f.trustProjectConfig, "trust-project-config", false, "also allow ./.wpus.yaml from the scanned directory")
	cmd.Flags().BoolVar(&f.noConfig, "no-config", false, "ignore every configuration file")
	cmd.Flags().BoolVar(&f.verifyPluginSums, "verify-plugin-checksums", false, "verify plugin files against their WordPress.org release archives (one download per plugin)")
	cmd.Flags().DurationVar(&f.timeout, "timeout", discovery.DefaultTimeout, "discovery time budget (e.g. 30s)")
	return cmd
}

func runScan(cmd *cobra.Command, args []string, f *scanFlags, globals *GlobalFlags) error {
	start := time.Now()
	// Diagnostics go to the command's error writer (stderr in production) so
	// stdout stays a clean report stream and tests can capture them.
	verbose := func(format string, args ...any) {
		if globals.Verbose {
			fmt.Fprintf(cmd.ErrOrStderr(), "[wpus] "+format+"\n", args...)
		}
	}

	// Policy: flags + trusted configuration file.
	cfg, cfgSource, err := config.Load(config.Options{
		Explicit:     f.configPath,
		TrustProject: f.trustProjectConfig,
		NoConfig:     f.noConfig,
		ConfigDir:    platform.ConfigDir(homeDir(), os.Getenv),
	})
	if err != nil {
		return usageError{err}
	}
	if cfgSource.Path != "" {
		note := ""
		if cfgSource.ProjectLocal {
			note = " (untrusted directory, enabled by --trust-project-config)"
		}
		verbose("config: %s%s", cfgSource.Path, note)
	}

	opts, err := buildPolicy(cfg, f, verbose)
	if err != nil {
		return err
	}
	excludes := append(append([]string{}, cfg.Exclude...), f.exclude...)
	failOn := firstNonEmpty(f.failOn, cfg.FailOn)
	coverageFloor := f.failOnCoverageBelow
	if coverageFloor == 0 {
		coverageFloor = cfg.FailOnCoverageBelow
	}
	if f.asJSON {
		f.format = "json"
	}

	// Validate options early (exit 2 territory).
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
	if f.failOnCoverageBelow < 0 || f.failOnCoverageBelow > 100 {
		// A value from the config file is reported the same way.
		return usagef("invalid --fail-on-coverage-below %d (use 0-100)", f.failOnCoverageBelow)
	}
	if coverageFloor < 0 || coverageFloor > 100 {
		return usagef("invalid fail_on_coverage_below %d in %s (use 0-100)", coverageFloor, cfgSource.Path)
	}
	switch f.format {
	case "terminal", "json", "markdown", "sarif":
	default:
		return usagef("invalid --format %q (use terminal|json|markdown|sarif)", f.format)
	}

	// The baseline is loaded before any site is touched: a scan asked to
	// compare against a recorded state must fail loudly (usage error) when
	// that state is unreadable, not quietly degrade to a point-in-time audit.
	var baselineRef *baseline.Baseline
	if f.baseline != "" {
		loaded, err := baseline.Load(f.baseline)
		if err != nil {
			return usageError{err}
		}
		baselineRef = loaded
		verbose("baseline: %s (recorded %s)", sanitize.Path(f.baseline), loaded.CreatedAt.UTC().Format(time.RFC3339))
	}

	// Shared services. Each network purpose gets its own client: the release
	// API is small and fast, the vulnerability feed is large and slow, and
	// target probes are policy-checked per site.
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
	var vulns vulnerability.Provider
	if !f.offline {
		feedClient := &http.Client{Timeout: feedTimeout}
		vulns = vulnProvider(os.Getenv, platform.CacheDir(homeDir(), os.Getenv), feedClient)
	} else {
		vulns = vulnerability.Unavailable{}
	}
	var checksumSrc checksumSource
	if !f.offline {
		checksumSrc = checksumSource{
			client:   &http.Client{Timeout: releaseTimeout},
			cacheDir: platform.CacheDir(homeDir(), os.Getenv),
			plugins:  f.verifyPluginSums,
		}
	}
	var runner *wpcli.Runner
	if f.live {
		runner = wpcli.Detect(os.Getenv)
		if runner != nil {
			runner.Log = func(s string) { verbose("%s", sanitize.Log(s)) }
			fmt.Fprintln(cmd.ErrOrStderr(), "warning: --live lets WP-CLI load the audited site; target-controlled PHP will execute")
		} else {
			verbose("WP-CLI not detected; --live has no effect")
		}
	} else {
		verbose("static mode: the audited site's PHP is never executed (use --live for WP-CLI facts)")
	}

	// Resolve sites. Discovery preserves the form of the path it was given, so
	// every result is made absolute here: exclusion, traversal, and the
	// "never write a report into the audited tree" guard all compare paths,
	// and a relative/absolute mismatch silently defeats such a comparison.
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
	var found discovery.Stats
	if len(explicit) > 0 {
		results := discovery.Discover(discovery.Options{Explicit: explicit})
		for _, r := range results {
			r.Path = absPath(r.Path)
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
		var results []discovery.Result
		results, found = discovery.DiscoverWithStats(discovery.Options{Home: homeDir(), Timeout: f.timeout})
		if found.Truncated {
			verbose("discovery stopped early (%s): %d root(s), %d directories visited", found.TruncationReason, found.Roots, found.DirectoriesVisited)
		}
		for _, r := range results {
			r.Path = absPath(r.Path)
			if r.Valid && !excluded[r.Path] {
				sitePaths = append(sitePaths, r.Path)
			}
		}
	}

	if len(sitePaths) == 0 {
		// Render the (empty) report first so agents can parse the outcome,
		// then fail: a scan that scanned nothing must not look successful.
		empty := &reporting.Report{
			SchemaVersion: reporting.SchemaVersion,
			Tool:          reporting.ToolInfo{Name: version.Name, Version: version.Version},
			Environment:   plat,
			Scan: reporting.ScanInfo{
				StartedAt:  start.UTC(),
				DurationMs: time.Since(start).Milliseconds(),
				Offline:    f.offline,
				Deep:       f.deep,
				Live:       f.live,
				ConfigPath: cfgSource.Path,
				Discovery:  discoveryInfo(found),
			},
			Sites: []reporting.SiteReport{},
			Meta:  map[string]string{"note": "no WordPress installations found"},
		}
		if renderErr := renderReport(cmd, empty, f, globals, nil); renderErr != nil {
			return asRunError(renderErr)
		}
		if f.allowEmpty {
			fmt.Fprintln(cmd.ErrOrStderr(), "no WordPress installations found (--allow-empty: treating as success)")
			return nil
		}
		return exitNoTargetsError{}
	}

	// Tell a feed-backed provider which components to index before the first
	// lookup parses the (large) feed.
	if !f.offline {
		primeFeedTargets(vulns, sitePaths)
	}

	// Scan each site.
	scanInfo := reporting.ScanInfo{
		StartedAt:         start.UTC(),
		Offline:           f.offline,
		Deep:              f.deep,
		Live:              f.live,
		ConfigPath:        cfgSource.Path,
		ProjectConfig:     cfgSource.ProjectLocal,
		ChecksRun:         len(opts.Selected()),
		DisabledChecks:    sortedKeys(opts.Disabled),
		SeverityOverrides: severityOverrideStrings(opts.SeverityOverrides),
		Suppressions:      suppressionStrings(opts.Suppressions),
		Discovery:         discoveryInfo(found),
		PluginChecksums:   f.verifyPluginSums,
	}
	report := &reporting.Report{
		SchemaVersion: reporting.SchemaVersion,
		Tool:          reporting.ToolInfo{Name: version.Name, Version: version.Version},
		Environment:   plat,
		Scan:          scanInfo,
		// Lists are always arrays in machine output, including when empty.
		Sites: []reporting.SiteReport{},
	}

	for _, path := range sitePaths {
		siteReport, err := scanSite(path, scanSiteOpts{
			opts: opts, ctx: context.Background(), core: core,
			vulns: vulns, checksums: checksumSrc,
			runner: runner, offline: f.offline, deep: f.deep,
			plat: plat, verbose: verbose, baseline: baselineRef,
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
	if err := renderReport(cmd, report, f, globals, sitePaths); err != nil {
		return asRunError(err)
	}

	// Exit policy.
	if failOn != "" && meetsThreshold(report.Sites, checks.Severity(failOn)) {
		return exitFindingsError{threshold: failOn}
	}
	if coverageFloor > 0 {
		for _, s := range report.Sites {
			if s.CoverageScore < coverageFloor {
				return exitCoverageError{floor: coverageFloor, site: s.Path, coverage: s.CoverageScore}
			}
		}
	}
	return nil
}

// buildPolicy validates the effective configuration against the check
// registry and converts it into check options. Unknown IDs are errors: a
// typo must never silently disable a security check.
func buildPolicy(cfg *config.File, f *scanFlags, verbose func(string, ...any)) (checks.Options, error) {
	opts := checks.Options{Disabled: map[string]bool{}, SeverityOverrides: map[string]checks.Severity{}}
	if f.severity != "" {
		sev, ok := checks.ParseSeverity(f.severity)
		if !ok {
			return opts, usagef("invalid --severity %q (use critical|high|medium|low|info)", f.severity)
		}
		opts.MinSeverity = sev
	}

	for _, id := range append(append([]string{}, cfg.Checks.Disabled...), f.excludeCheck...) {
		if _, ok := checks.Get(id); !ok {
			return opts, usagef("unknown check ID %q in disabled checks (run `wpus checks` for valid IDs)", id)
		}
		opts.Disabled[id] = true
	}
	for id, raw := range cfg.SeverityOverrides {
		if _, ok := checks.Get(id); !ok {
			return opts, usagef("unknown check ID %q in severity_overrides", id)
		}
		sev, ok := checks.ParseSeverity(raw)
		if !ok {
			return opts, usagef("invalid severity %q for %s (use critical|high|medium|low|info)", raw, id)
		}
		opts.SeverityOverrides[id] = sev
	}
	now := time.Now()
	for _, s := range cfg.Suppressions {
		if _, ok := checks.Get(s.ID); !ok {
			return opts, usagef("unknown check ID %q in suppressions", s.ID)
		}
		if strings.TrimSpace(s.Reason) == "" {
			return opts, usagef("suppression for %s needs a reason", s.ID)
		}
		if s.Expired(now) {
			verbose("suppression for %s expired on %s and no longer applies", s.ID, s.Expires)
			continue
		}
		opts.Suppressions = append(opts.Suppressions, checks.Suppression{CheckID: s.ID, Reason: s.Reason})
	}
	return opts, nil
}

// asRunError preserves an already-classified error (a usage problem found
// while rendering, for example) and wraps anything else as a runtime failure,
// so exit codes keep their meaning.
func asRunError(err error) error {
	switch err.(type) {
	case usageError, runtimeError, permissionError, exitFindingsError, exitCoverageError, exitNoTargetsError:
		return err
	default:
		return runtimeError{err}
	}
}

// renderReport writes the report in the requested format, either to stdout or
// to --output. Report bytes are always produced by the same writers so the
// file and the stream are identical.
func renderReport(cmd *cobra.Command, report *reporting.Report, f *scanFlags, globals *GlobalFlags, sitePaths []string) error {
	write := func(w io.Writer) error {
		switch f.format {
		case "json":
			return reporting.WriteJSON(w, report)
		case "markdown":
			return reporting.WriteMarkdown(w, report)
		case "sarif":
			return reporting.WriteSARIF(w, report)
		default:
			term := reporting.Terminal{Opts: reporting.TerminalOptions{
				Color: colorEnabled(globals.NoColor), Quiet: globals.Quiet, Verbose: globals.Verbose,
			}}
			return term.Write(w, report)
		}
	}
	if f.output == "" {
		return write(cmd.OutOrStdout())
	}
	// A report must never be written into the tree being audited: the scan
	// is read-only by contract, and a report inside a web root is an
	// information-disclosure bug of our own making.
	if err := rejectOutputInsideSites(f.output, sitePaths); err != nil {
		return usageError{err}
	}
	if err := writeFileAtomic(f.output, write); err != nil {
		return runtimeError{err}
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "report written to %s\n", sanitize.Path(f.output))
	return nil
}

// absPath makes a path absolute, returning it unchanged when that is not
// possible (the caller then reports a load error for it).
func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// rejectOutputInsideSites refuses an --output path inside a scanned site.
func rejectOutputInsideSites(output string, sites []string) error {
	abs, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("--output %s: %w", output, err)
	}
	for _, site := range sites {
		rel, err := filepath.Rel(absPath(site), abs)
		if err != nil {
			continue
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("--output %s is inside the scanned site %s; write reports outside the audited tree", output, site)
		}
	}
	return nil
}

// writeFileAtomic writes via a temporary file in the destination directory and
// renames it into place, so a crashed or interrupted scan never leaves a
// half-written report behind.
func writeFileAtomic(path string, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".wpus-report-*")
	if err != nil {
		return fmt.Errorf("--output %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			os.Remove(tmp) //nolint:errcheck // best-effort cleanup on the error path
		}
	}()
	if err := write(f); err != nil {
		f.Close() //nolint:errcheck
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	tmp = ""
	return nil
}

type scanSiteOpts struct {
	opts      checks.Options
	ctx       context.Context
	core      *releases.Core
	vulns     vulnerability.Provider
	checksums checks.ChecksumSource
	runner    *wpcli.Runner
	offline   bool
	deep      bool
	plat      platform.Info
	verbose   func(string, ...any)
	// baseline is the recorded state this scan diffs against (nil = none).
	baseline *baseline.Baseline
	// observed, when non-nil, receives the loaded site model and WP-CLI
	// bundle. The report model carries only findings, so `baseline create`
	// needs this to record an inventory without loading (or running WP-CLI
	// on) the installation a second time.
	observed *observedSite
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

	// The site's secrets are known as soon as wp-config.php is parsed, which
	// is before any WP-CLI output can arrive. The runner's log is routed
	// through the same scrubber as findings: WP-CLI error text can quote
	// configuration values, and a log line is not a safe place for them.
	scrub := redaction.NewScrubber(siteSecretLiterals(site)...)

	var env *wpcli.Siteenv
	wpAvailable := false
	if o.runner != nil && o.runner.Available() {
		o.runner.Log = func(line string) { o.verbose("%s", sanitize.Log(scrub.Scrub(line))) }
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

	baseURL := firstNonEmpty(site.HomeURL, site.SiteURL)
	ctx := &checks.Context{
		Site:        site,
		WP:          env,
		WPAvailable: wpAvailable,
		Vulns:       o.vulns,
		Core:        o.core,
		Checksums:   checksumSourceOrNil(o.checksums, o.offline),
		Probe:       proberFor(baseURL, o.offline),
		BaseURL:     baseURL,
		Ctx:         o.ctx,
		Offline:     o.offline,
		Deep:        o.deep,
		Platform:    o.plat,
		Server:      checks.DetectWebServer(site.Path),
		Baseline:    o.baseline,
	}
	if o.observed != nil {
		o.observed.site = site
		o.observed.wp = env
	}

	var findings []checks.Finding
	for _, c := range o.opts.Selected() {
		// Drift is relative to the rest of the audit, so the baseline check
		// runs below with this site's complete finding set attached.
		if c.ID == checks.BaselineCheckID {
			continue
		}
		findings = append(findings, runOneCheck(c, ctx)...)
	}
	if !o.opts.Disabled[checks.BaselineCheckID] {
		ctx.Findings = findings
		if drift, ok := checks.Get(checks.BaselineCheckID); ok {
			findings = append(findings, runOneCheck(drift, ctx)...)
		}
	}
	// Policy first (severity overrides, suppressions, fingerprints), then the
	// display filter. Scoring uses the annotated set so a --severity run still
	// reports honest coverage instead of scoring only what it displayed.
	findings = o.opts.ApplyPolicy(findings)

	// Central sanitization: secrets first (redaction), then output escaping
	// and length capping (sanitize). This is the only path findings take to
	// a reporter, so no check can leak control sequences or markup.
	for i := range findings {
		findings[i] = sanitizeFinding(scrub, findings[i])
	}
	risk, coverage, cats := reporting.SiteScores(findings, ctx.WalkStats())

	shown := o.opts.FilterFindings(findings)
	checks.SortFindings(shown)
	return &reporting.SiteReport{
		Path:          sanitize.Path(site.Path),
		WordPress:     site.Version,
		Server:        sanitize.Line(ctx.Server),
		RiskScore:     risk,
		CoverageScore: coverage.Score,
		Confidence:    coverage.Confidence,
		Coverage:      coverage,
		Categories:    cats,
		Findings:      shown,
		PHP:           sanitize.Line(site.WPCLIPHPVersion),
		PHPSource:     phpSource(site),
		Notes:         siteNotes(env, wpAvailable, ctx),
	}, nil
}

// phpSource describes where the reported PHP version came from.
func phpSource(site *wordpress.Site) string {
	if site.WPCLIPHPVersion != "" {
		return "wp-cli runtime"
	}
	return ""
}

func siteNotes(env *wpcli.Siteenv, wpAvailable bool, ctx *checks.Context) []string {
	var notes []string
	if env != nil && !wpAvailable {
		notes = append(notes, "WP-CLI present but site not responding (database down?) — WP-CLI-backed checks skipped")
	}
	for _, gap := range ctx.CoverageGaps() {
		notes = append(notes, sanitize.Line(gap))
	}
	return notes
}

// proberFor builds the SSRF-safe prober for one site. Probes are restricted to
// the site's own origin(s); private and loopback destinations are permitted
// only when the site itself is configured on such a host (a local
// development install), and cloud metadata endpoints are never reachable.
func proberFor(baseURL string, offline bool) *probe.Prober {
	if offline {
		return nil
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil
	}
	origins := []string{}
	for _, scheme := range []string{"http", "https"} {
		origins = append(origins, scheme+"://"+u.Host)
	}
	return probe.New(probe.Policy{
		AllowedOrigins:            origins,
		AllowPrivate:              platform.IsLoopbackHost(u.Hostname()) || isPrivateHost(u.Hostname()),
		FollowSameOriginRedirects: true,
		MaxBodyBytes:              2 << 20,
		Timeout:                   10 * time.Second,
	})
}

// isPrivateHost reports whether host is a private, loopback, or link-local
// IP literal.
func isPrivateHost(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
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

// sanitizeFinding removes secrets and every unsafe output character from a
// finding. Everything a reporter renders passes through here.
func sanitizeFinding(scrub *redaction.Scrubber, f checks.Finding) checks.Finding {
	f.Title = sanitize.Line(scrub.Scrub(f.Title))
	f.Description = sanitize.Line(scrub.Scrub(f.Description))
	f.Recommendation = sanitize.Line(scrub.Scrub(f.Recommendation))
	f.Fingerprint = sanitize.Line(f.Fingerprint)
	f.SuppressionReason = sanitize.Line(f.SuppressionReason)
	if f.Evidence != nil {
		out := make(map[string]string, len(f.Evidence))
		for k, v := range f.Evidence {
			out[sanitize.Line(scrub.Scrub(k))] = sanitize.Text(scrub.Scrub(v), 4096)
		}
		f.Evidence = out
	}
	if f.References != nil {
		refs := make([]string, len(f.References))
		for i, r := range f.References {
			refs[i] = sanitize.Line(scrub.Scrub(r))
		}
		f.References = refs
	}
	for i := range f.Occurrences {
		occ := &f.Occurrences[i]
		occ.Slug = sanitize.Line(scrub.Scrub(occ.Slug))
		occ.Name = sanitize.Line(scrub.Scrub(occ.Name))
		occ.Version = sanitize.Line(scrub.Scrub(occ.Version))
		occ.AdvisoryID = sanitize.Line(scrub.Scrub(occ.AdvisoryID))
		occ.CVE = sanitize.Line(scrub.Scrub(occ.CVE))
		occ.Provider = sanitize.Line(scrub.Scrub(occ.Provider))
		occ.Location = sanitize.Path(scrub.Scrub(occ.Location))
	}
	return f
}

// siteSecretLiterals extracts secret values that must never appear in output.
func siteSecretLiterals(site *wordpress.Site) []string {
	if site.Config == nil {
		return nil
	}
	return site.Config.SecretLiterals
}

// meetsThreshold reports whether any non-suppressed finding meets the
// --fail-on severity.
func meetsThreshold(sites []reporting.SiteReport, threshold checks.Severity) bool {
	for _, s := range sites {
		for _, f := range s.Findings {
			if f.Status == checks.StatusFailed && !f.Suppressed && f.Severity.Rank() >= threshold.Rank() {
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

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func severityOverrideStrings(m map[string]checks.Severity) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = string(v)
	}
	return out
}

func suppressionStrings(in []checks.Suppression) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, s.CheckID+": "+s.Reason)
	}
	return out
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

// exitCoverageError signals a coverage-policy failure (exit 1).
type exitCoverageError struct {
	floor    int
	site     string
	coverage int
}

func (e exitCoverageError) Error() string {
	return fmt.Sprintf("%s: coverage %d%% is below the required %d%%", e.site, e.coverage, e.floor)
}

// exitNoTargetsError signals that nothing was scanned (exit 5).
type exitNoTargetsError struct{}

func (exitNoTargetsError) Error() string {
	return "no WordPress installations found: pass a path (e.g. `wpus scan /path/to/site`) or use --allow-empty to accept an empty run"
}
