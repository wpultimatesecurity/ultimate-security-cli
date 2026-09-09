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
  app/                    root/scan/discover/checks/version commands
                          scan orchestration, exit-code policy
  discovery/              bounded, platform-aware WordPress discovery
  wordpress/              site model + static parsing (never executes PHP)
  wpcli/                  optional WP-CLI provider (exec, read-only commands)
  checks/                 check framework + all check implementations
  vulnerability/          VulnerabilityProvider interface, Wordfence client
  releases/               WordPress.org core release data (stable-check API)
  scoring/                deterministic score computation
  redaction/              central scrubber applied before any reporter
  reporting/              terminal, JSON, and Markdown reporters
  platform/               OS/arch identity, per-user config/cache dirs
  config/                 optional YAML config file loading
```

Dependency rule: `app → {discovery, wordpress, wpcli, checks, releases,
vulnerability, scoring, redaction, reporting, platform, config}`.
`checks` may import `wordpress`, `wpcli`, `vulnerability`, `releases`,
`platform`. Nothing imports `app`. Reporters depend only on the report model.

## Scan pipeline

```text
wpus scan
  1. merge flags + config file (.wpus.yaml / user config dir)
  2. resolve sites: explicit paths validated directly, else discovery walk
  3. shared services (once per run):
       - HTTP client (nil when --offline)
       - WordPress.org release data (releases.FetchCore, cached 24h)
       - vulnerability provider (env-configured; Unavailable by default)
       - WP-CLI runner (nil when absent or --skip-wpcli)
  4. per site:
       - wordpress.Load: version.php, static wp-config parse, plugin/theme
         headers, content paths
       - wpcli.Collect (when available): core version, PHP, options,
         plugin/theme rows, admins, xmlrpc filter, ini_get
       - build checks.Context (data collected once, shared by all checks)
       - run each registered check (panic-isolated)
       - severity filter, sort
       - central redaction of every finding
       - scoring.Compute
  5. tally + render (terminal | json | markdown)
  6. exit code from --fail-on policy
```

## Check framework

Each check registers one `checks.Simple` — a `Meta` (stable ID, title,
category, description, references) plus a `Run(*checks.Context) []Finding`
function. There is no god-scanner: every check is independently implemented,
testable, and skippable by ID.

Findings carry `severity` (impact) and `confidence` (how sure the check is)
as separate axes, plus `status`:

- `passed` — the condition was checked and is fine
- `failed` — a real finding
- `skipped` — not applicable / cannot be determined here (with a `reason` in
  evidence)
- `unknown` — attempted but inconclusive

The registry is versioned by discipline: IDs and categories are stable API.
Automation may filter on them.

## Read-only guarantee

The scanner performs no writes to sites. Enforcement points:

- `wordpress` package: only `os.ReadFile`/`os.Open`/`ReadDir`/`Stat` calls.
- `wpcli`: only read-shaped commands (`core version`, `plugin list`,
  `option get`, `user list`, `cli info`, `eval` of pure introspection
  expressions). No `wp * install|update|delete` anywhere in the codebase.
- No code path takes an output file argument in V1 (`--output` is planned and
  will be reporter-level only).

`wp eval` executes read-only introspection on the live site via WP-CLI; the
expressions shipped (`apply_filters`, `ini_get`) do not mutate state. Users
who want pure static analysis can pass `--skip-wpcli`.

## Redaction

Secrets from `wp-config.php` (DB credentials, the eight salts, table prefix)
are captured during parsing into `SecretLiterals` and registered in a
per-site `redaction.Scrubber`. Before any reporter runs, every finding passes
through `redactFinding`, which scrubs description, recommendation, evidence
values, and references. The scrubber also removes generic shapes: PEM keys,
`Bearer` tokens, `key=value` assignments with sensitive keys, and long hex
blobs. Check authors cannot bypass this — findings reach reporters only
through the scrubber.

## Platform isolation

- `platform.Info` carries `OS`/`Arch`; `platform.ConfigDir`/`CacheDir` pick
  XDG (`~/.config/wpus`) on Linux and `~/Library/Application Support/wpus` on
  macOS.
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
  check; network calls are two small GETs (release feed, optional REST probe)
  with timeouts and 24h disk caches.
- The vulnerability feed (when configured) streams to disk and is parsed with
  a streaming JSON decoder — the 100 MB+ feed never fully loads into RAM.

## Future-proofing

Extension seams already in place: `VulnerabilityProvider` (additional data
sources), `wpcli.Runner` (any target that can run wp — Docker, SSH), the
check registry (new checks are one `Register` call), `reporting` (SARIF is
another `Write*` function), and `checks.Options` (policies, per-check
overrides). None of V1's choices block remote scanning or compliance
profiles.
