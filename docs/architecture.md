# Architecture

## Language choice

wpus is written in **Go**. Decision factors:

- **Single static binary** for linux/amd64, linux/arm64, darwin/amd64,
  darwin/arm64 with trivial cross-compilation (`GOOS`/`GOARCH`).
- **Fast startup** — a terminal audit should begin instantly, even when run
  repeatedly by agents or cron.
- **First-class filesystem APIs** (`os.Root`-style care, `filepath.WalkDir`,
  syscall-level `Stat_t` when needed) without shelling out to GNU tools.
- **Mature CLI ecosystem** (cobra) and boring dependency hygiene.
- Alternative evaluation: Python/Node would need runtime installs on servers
  and slower startup; Rust/PHP were rejected for ecosystem/personnel fit.
  The previous TUI codebase in this repository was already Go, which made the
  conversion natural.

## Package layout

```text
cmd/wpus/                 main(): builds version info, calls app.Execute
internal/
  app/                    root/scan/baseline/discover/checks/version commands
                          scan orchestration, exit-code policy, checksum
                          adapter, SSRF-safe prober construction
  discovery/              bounded, platform-aware WordPress discovery with
                          truncation accounting (Stats)
  wordpress/              site model, static parsing (never executes PHP),
                          layout resolution, plugin/theme/MU-plugin/drop-in
                          inventory, PHP-compatible version comparison
  wpcli/                  WP-CLI provider, invoked only when --live is set
  checks/                 check framework + all check implementations
  baseline/               point-in-time inventory capture and diff model
  checksums/              WordPress.org core checksum manifest and plugin
                          release-zip digest maps
  vulnerability/          VulnerabilityProvider interface, Wordfence client
  probe/                  policy-checked HTTP prober (same-origin, capped)
  releases/               WordPress.org core release data (stable-check with
                          version-check fallback), cached 24h
  scoring/                deterministic risk scoring and weighted coverage
  redaction/              central secret scrubber applied before reporters
  sanitize/               per-output-channel escaping (terminal, Markdown,
                          paths, logs) with length caps
  reporting/              terminal, JSON, Markdown, and SARIF reporters
  platform/               OS/arch identity, per-user config/cache dirs
  config/                 strict YAML config loading with a trust model
  version/                build identity injected via -ldflags at release time
```

Dependency rule: `app → {discovery, wordpress, wpcli, checks, baseline,
checksums, releases, vulnerability, probe, scoring, redaction, sanitize,
reporting, platform, config}`. `checks` may import `wordpress`, `wpcli`,
`vulnerability`, `releases`, `probe`, `platform`; it consumes checksum data
through the narrow `checks.ChecksumSource` interface and a recorded baseline
through `checks.Context.Baseline`, both implemented/loaded by `app`, which
keeps network, cache, and file policy in the composition root. Nothing imports
`app`. Reporters depend only on the report model and `sanitize`.

## Trust boundary

The scanner treats everything about the audited site as hostile input — its
files, its `wp-config.php`, its plugin names, its URLs, and anything WP-CLI
prints. The boundary is drawn so that authoring a WordPress site cannot make
`wpus` do something the operator did not ask for.

**The static path (the default) may:**

- read files under the site (and, for a parent-directory `wp-config.php`, one
  level above it) with `os.ReadFile`/`Open`/`ReadDir`/`Stat`;
- parse PHP lexically, never executing it;
- walk the site with bounded budgets, never following symlinked directories;
- download authoritative data from WordPress.org and an optional vulnerability
  feed, and make policy-checked requests to the site's own origin only (one
  REST GET, plus a bounded set of HEAD requests that confirm exposure).

**The static path may not:** execute the site's PHP, write into the site,
follow a redirect off-origin, contact cloud metadata addresses, reach a
private/loopback destination when the site itself is not configured there, or
read a response body without a size cap. `probe.Policy` is deny-by-default: the
site URL comes from target-controlled WordPress state, so every destination is
opted in explicitly, and redirects are re-validated as same-origin.

**`--live` is a separate provider, not a mode flag on the static checks.** When
set, it detects WP-CLI and lets it load WordPress to collect live facts (the
database, active plugin state, runtime PHP settings). That executes
target-controlled PHP, so it is opt-in, prints a warning, and is the only path
in the binary that runs site code. Without it, `wpcli.Runner` is nil and those
facts are simply absent.

**Where target-controlled data is neutralised.** Before any reporter runs,
every finding passes through two stages in order: the per-site
`redaction.Scrubber` removes secrets captured from `wp-config.php` plus generic
secret shapes (PEM blocks, bearer tokens, sensitive `key=value`, long hex), then
`sanitize` applies the policy of the destination channel — stripping ANSI/OSC
escape sequences, C0/C1 control characters, and bidi overrides, and capping
length. Terminal/Markdown/SARIF reporters cannot be reached around this path,
so a hostile plugin name cannot inject terminal control sequences or
restructure a Markdown document.

## Scan pipeline

```text
wpus scan
  1. resolve configuration (config.Load):
       --config PATH (must exist)
       > user config dir ($WPUS_CONFIG_DIR or platform default)
       > ./.wpus.yaml|.wpus.yml only with --trust-project-config
       (--no-config disables loading; decoding is strict)
  2. validate the effective policy against the registry (unknown check IDs
     are usage errors); merge flags over config values
  3. shared services (once per run):
       - release client + releases.FetchCore (cached 24h), nil when --offline
       - vulnerability provider (env-configured; Unavailable by default)
       - checksum source (core manifest; plugin zips only when asked)
       - WP-CLI runner, only when --live
  4. resolve sites:
       explicit paths are bounded walk seeds; otherwise platform root list
       with discovery.Stats accounting (roots, directories visited,
       truncation reason) so an empty result is unambiguous
  5. tell a feed-backed vulnerability provider which components will be
     looked up (SetTargets) before the feed is parsed once
  6. per site:
       - wordpress.Load: version.php, static wp-config parse, resolved
         layout, plugin/theme/MU-plugin/drop-in inventory
       - wpcli.Collect (only with --live): live facts
       - build checks.Context (collected once, shared by all checks); a
         baseline loaded from --baseline is attached to the context
       - run each registered check (panic-isolated); the drift check compares
         the site against the baseline and skips when none was supplied
       - apply policy: severity overrides, suppressions, fingerprints
       - redaction, then output sanitization of every finding
       - scoring: risk score, category scores, coverage score
       - severity filter for display (scoring keeps the full set)
  7. tally + render (terminal | json | markdown | sarif), to stdout or
     --output (atomic write)
  8. exit code from the policy: findings, coverage floor, or no targets
```

The policy is applied before the display filter on purpose: a `--severity`
run still reports honest coverage instead of scoring only what it displayed.

## WordPress layout resolution

WordPress lets a site move or rename `wp-content`, the plugin directory, the
MU-plugin directory, and uploads, and accepts `wp-config.php` one directory
above the installation. Assuming the default layout would produce false
"clean" results on ordinary hardened sites, so every path is either resolved
from the site's own configuration or reported as unresolved — never guessed.

`wordpress.resolveLayout` evaluates a restricted expression subset with a
small evaluator: string literals, `__FILE__`, `__DIR__`, `ABSPATH`,
`dirname()`, and `.` concatenation. Constants `WP_CONTENT_DIR`,
`WP_PLUGIN_DIR`, `WPMU_PLUGIN_DIR` and `UPLOADS` are resolved against the
evaluated `ABSPATH` when the site defines one. Anything outside that subset
(e.g. `getenv(...)`) is recorded in `Layout.Unresolved`, which becomes a
coverage gap, and `CUSTOM_CONTENT_PATH` fails rather than implying the default
tree was examined. MU plugins (top-level `*.php` files carrying headers in the
MU directory) and the documented drop-ins are inventoried from the resolved
paths.

## Integrity sources

Two independent authorities, both fetched from WordPress.org and never
executed:

- **Core** — `https://api.wordpress.org/core/checksums/1.0/` for a version and
  locale, cached on disk for 24h. File diffs, missing files, and unexpected
  files in core directories become `CORE_INTEGRITY_MODIFIED`,
  `CORE_FILE_MISSING`, and `CORE_UNEXPECTED_FILE`. `wp-includes/version.php` is
  excluded because WordPress rewrites it on every update. Manifests are bounded
  and validated (entry count, digest shape, relative paths) before use.
- **Plugins** — `https://downloads.wordpress.org/plugin/<slug>.<version>.zip`,
  md5 per file with the map cached (release zips are immutable). The download
  is streamed to a temp file outside the site, capped at 64 MiB, and deleted;
  file contents are never retained. This path is opt-in via
  `--verify-plugin-checksums` because it costs one download per plugin.

A plugin with no WordPress.org release (custom or premium) is unverifiable and
is reported as `unknown`/`PLUGIN_CHECKSUM_UNAVAILABLE`, never as modified. A
missing checksum source, an offline run, or an unreleased core version yields a
skip rather than a guess.

## Check framework

Each check registers one `checks.Simple` — a `Meta` (stable ID, title,
category, description, references, importance) plus a `Run(*checks.Context)
[]Finding` function. There is no god-scanner: every check is independently
implemented, testable, and skippable by ID.

Findings carry `severity` (impact) and `confidence` (how sure the check is)
as separate axes, plus `status`:

- `passed` — the condition was checked and is fine
- `failed` — a real finding
- `skipped` — not applicable / cannot be determined here (with a `reason` in
  evidence)
- `unknown` — attempted but inconclusive

Aggregated findings carry structured `Occurrences` (resource type, slug,
version, location, advisory ID, CVE, CVSS, fixed versions, provider) and a
stable `Fingerprint` derived from the check ID plus its occurrence keys, so
consecutive scans can be diffed without parsing prose. The registry is
versioned by discipline: IDs and categories are stable API, and automation may
filter on them.

## Read-only guarantee

The scanner performs no writes to sites. Enforcement points:

- `wordpress` package: only `os.ReadFile`/`os.Open`/`ReadDir`/`Stat` calls.
- `checksums` downloads go to the system temp directory or the tool's own
  cache directory, never into the site.
- `wpcli`, when enabled with `--live`, runs only read-shaped commands (`core
  version`, `plugin list`, `option get`, `user list`, `cli info`, `eval` of
  pure introspection expressions). No `wp * install|update|delete` anywhere in
  the codebase.
- `--output` is reporter-level and refuses a destination inside any scanned
  site, so a report can never become an information-disclosure artifact in a
  web root. The write itself is atomic: a temp file in the destination
  directory is renamed into place.

## Redaction and output sanitization

Secrets from `wp-config.php` (DB credentials, the eight salts, table prefix)
are captured during parsing into `SecretLiterals` and registered in a per-site
`redaction.Scrubber`. Before any reporter runs, every finding passes through
`sanitizeFinding`, which scrubs the description, recommendation, evidence
values, occurrences, and references, and then applies the output policy of
each field (single-line, bounded). The scrubber also removes generic shapes: PEM
keys, `Bearer` tokens, `key=value` assignments with sensitive keys, and long
hex blobs.

`sanitize` then makes each string safe for its destination: `Line`/`Path`/`Log`
for single-line slots, `Terminal` for multi-line human output, `Text` for
bounded evidence, and Markdown-specific helpers that escape metacharacters and
neutralise raw HTML. Both stages are unavoidable — findings reach reporters
only through them, and reporters apply their own escaping as defence in depth.

## Platform isolation

- `platform.Info` carries `OS`/`Arch`; `platform.ConfigDir`/`CacheDir` pick
  XDG (`~/.config/wpus`, `~/.cache/wpus`) on Linux and
  `~/Library/Application Support/wpus` / `~/Library/Caches/wpus` on macOS.
  `WPUS_CONFIG_DIR` overrides the config directory and `WPUS_CACHE_DIR` the
  cache directory.
- Discovery root lists differ by platform; virtual filesystem prefixes
  (`/proc`, `/sys`, `/dev`, `/run`, macOS `/System/Volumes`, …) are never
  walked.
- Permission checks use plain POSIX bits, which macOS and Linux share for the
  bits we assert (world/group write/read). No `/proc` assumptions, no GNU
  tools, no systemd.

## Performance

- Discovery: bounded by depth (6), wall clock (20s default), visited-dir cap
  (300k), result cap (100); confirmed sites skip descending into their huge
  core trees (`wp-content`, `wp-admin`, `wp-includes`).
- Filesystem checks share a bounded walker: 5s / 50k files normally, 30s /
  250k with `--deep`; symlink dirs are never followed; `--deep` is the escape
  hatch, not the default.
- WP-CLI is invoked once per site with a fixed set of commands, never per
  check, and only with `--live`. Network calls are bounded by purpose: the
  release feed, the core checksum manifest, one plugin zip per plugin when
  asked, plus same-origin probe traffic: one REST request and a bounded set of
  exposure-confirmation HEAD requests.
- The vulnerability feed streams to disk and is parsed with a streaming JSON
  decoder under a decompressed byte budget (512 MiB default) — the 100 MB+
  feed never fully loads into RAM, and the index can be restricted to the
  components the scan will look up.

## Future-proofing

Extension seams already in place: `VulnerabilityProvider` (additional data
sources), `wpcli.Runner` (any target that can run wp — Docker, SSH), the check
registry (new checks are one `Register` call), `reporting` (a new format is
another `Write*` function), and `checks.Options` (policies, per-check
overrides). None of the current choices block remote scanning or compliance
profiles.
