# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed — CI on a fresh checkout

- The PHP differential test compared against whatever PHP the machine had.
  PHP 8.4 changed `version_compare()`'s canonicalization (trailing dot now
  stripped, php-src `ext/standard/versioning.c`), which is the semantics this
  port implements, so the comparison failed on the older PHP shipped with the
  Linux runner. The test now states its baseline: it skips with that reason on
  PHP < 8.4, the divergent inputs are pinned in `TestVersionCompare` on every
  PHP, and CI installs PHP 8.4 to run the comparison.
- CI and release builds pinned the patch release named in `go.mod`
  (Go 1.25.0), so `govulncheck` failed on 25 known standard-library
  vulnerabilities that later patches fix. Builds now use the current stable
  toolchain, and a new `minimum-go` job keeps the declared Go floor working.

### Added — public repository setup

- Branch model: `dev` is the single long-lived branch — default, integration
  target, and source of release tags. CI runs on pushes to it and on every pull
  request.
- `.github/workflows/release.yml`: a `v*` tag builds all four targets plus
  `checksums.txt`, creates a draft release, and signs a build provenance
  attestation for every artifact (verifiable with `gh attestation verify`).
- Release configuration validated with `goreleaser check` and a full
  `goreleaser release --snapshot --clean` dry run; the archive naming matches
  what `scripts/install.sh` downloads.
- Homebrew packaging removed from the release configuration until its tap
  repository exists — GoReleaser deprecated `brews` in favour of casks, and a
  release would otherwise fail while publishing to a missing tap.
- Issue forms (bug report, feature/check request), a pull request template,
  and Dependabot configuration for Go modules and GitHub Actions.
- Every action pinned to a commit SHA (with the tag in a trailing comment for
  Dependabot), enforced by the repository's SHA-pinning requirement, and the
  default workflow token reduced to read-only with no PR-approval rights.
- `scripts/github-setup.sh`: idempotent `gh` configuration for description,
  topics, repository features, vulnerability alerts and automated security
  fixes, secret scanning, default branch, and branch protection. Steps that
  need a published repository are reported as `PENDING` with the reason, and
  the visibility change is behind an explicit `--public` flag because it
  cannot be undone.

### Added — repository hygiene for public release

- `.gitignore` rewritten for publication: build and release output, generated
  scan reports, coverage and profiling artefacts, local policy overrides
  (`.wpus.local.yaml`; a committed `.wpus.yaml` stays a product feature),
  secret material, OS/editor state, agent state directories, Go workspace
  files, and the maintainers' research dumps.
- Dated research folders under `docs/` are ignored by naming convention
  (`docs/11:09:2026/`, `docs/2026-09-11/`) along with `docs/research/`,
  `docs/private/`, `docs/internal/`, `*-internal.md`, and `repomix-*.xml`.
  Those documents describe this tool's own weaknesses and are maintained
  locally only.
- `.gitattributes` normalizes line endings for every checkout (a stray CR
  must never look like a modified file to an auditor) and classifies prose as
  documentation for language statistics.
- `make hygiene` (`scripts/check-public-tree.sh`) is the publish gate: it
  fails when a private, generated, or machine-specific file is tracked, when a
  tracked file leaks an absolute developer path, or when a private path in the
  working tree is no longer covered by `.gitignore`. CI runs it on every
  change; two negative controls in the script's own development proved it
  fires for a tracked research document and a planted `/Users/<name>` path.

### Changed — security audit remediation

A deep research audit of the scanner found that its own trust boundary and
reporting contract were the weakest parts, not its check list. This release
fixes those first.

**Trust boundary (breaking)**

- `wpus scan` no longer executes the audited site's PHP. WP-CLI is now opt-in
  with `--live`, which prints a warning because it loads WordPress and runs
  target-controlled code. `--skip-wpcli` is gone (it is the default now).
- Configuration is no longer loaded from the current directory by default.
  Precedence is `--config PATH` > per-user config > `./.wpus.yaml` **only**
  with `--trust-project-config`; `--no-config` disables config loading
  entirely. A directory can no longer configure the audit of itself.
- Configuration decoding is strict: unknown YAML keys, unknown check IDs, and
  suppressions without a reason are errors instead of silent no-ops.
- Site probes (`REST_USER_ENUMERATION`) go through a dedicated SSRF-safe
  prober: requests are pinned to the site's own origin, cloud metadata
  endpoints are never reachable, private/loopback targets require the site to
  be configured on such a host, redirects are same-origin and re-validated,
  and response bodies are size-capped.
- Exit codes are a documented contract and now include
  `5 = no targets scanned`; `--allow-empty` restores the old behaviour
  explicitly. A scan that inspected nothing no longer passes CI silently.
- Terminal, Markdown, and log output is escaped for its channel: target-
  controlled names, paths, URLs, and WP-CLI stderr cannot inject ANSI/OSC
  sequences, control characters, or Markdown structure. Reports are safe to
  hand to humans and to agents.

**Correctness**

- `VersionCompare` now implements PHP's `version_compare()` semantics
  (canonicalization, the special-forms ordering table, the `#` escape hatch)
  and is differential-tested against a real PHP binary over ~23,000 pairs.
  The previous comparator ranked `1.0` below `1.0-beta`; affected-version
  ranges inherited that error.
- Aggregated findings report the real count instead of the truncated display
  length (`PLUGIN_OUTDATED`, `INACTIVE_PLUGIN`, `THEME_OUTDATED`).
- `vulnLines` no longer prints "… 0 more".
- `unknown` is counted and displayed separately from `skipped`.
- A PHP version missing from the lifecycle table is reported as unknown, not
  as actively supported.
- `PLUGIN_OUTDATED` reports inactive plugins too, marked as inactive.
- The filesystem walker honours its wall-clock budget even when nothing has
  matched yet, and reports why a traversal was truncated.

**Coverage**

- WordPress layout is resolved from the site's own configuration
  (`WP_CONTENT_DIR`, `WP_PLUGIN_DIR`, `WPMU_PLUGIN_DIR`, `UPLOADS`) and
  `wp-config.php` is also found one directory above the installation. Paths
  that cannot be resolved statically become a reported coverage gap.
- New checks: `CORE_INTEGRITY_MODIFIED`, `CORE_FILE_MISSING`,
  `CORE_UNEXPECTED_FILE` (official WordPress.org core checksums),
  `PLUGIN_INTEGRITY_MODIFIED`, `PLUGIN_INTEGRITY_MISSING_FILE`,
  `PLUGIN_INTEGRITY_EXTRA_FILE`, `PLUGIN_CHECKSUM_UNAVAILABLE`,
  `MU_PLUGIN_PRESENT`, `DROPIN_PRESENT`, `CUSTOM_CONTENT_PATH`,
  `WP_CONFIG_PARENT_LOCATION`, `WP_CORE_VULNERABILITY`,
  `SENSITIVE_FILE_PUBLICLY_RETRIEVABLE`, `BASELINE_DRIFT` — 44 checks total.
- `SENSITIVE_FILE_PUBLICLY_RETRIEVABLE` confirms exposure instead of inferring
  it: up to twelve `HEAD` requests (never `GET`, never a `.php` file) to the
  site's own origin, reporting only status/content-type/length. Contents are
  never downloaded.
- Baseline and drift: `wpus baseline create <path> --output <file>` records the
  inventory and finding fingerprints; `wpus scan --baseline <file>` reports
  added/removed/version-changed plugins, themes, MU plugins, drop-ins, admins,
  and newly appeared or resolved findings through `BASELINE_DRIFT`. A baseline
  that cannot be read is a usage error, and a missing one is never treated as
  "no drift".
- Core and plugin integrity are verified without bootstrapping WordPress;
  plugin verification is opt-in (`--verify-plugin-checksums`) because it
  downloads one release archive per plugin, and plugins with no WordPress.org
  release are reported as unverifiable rather than modified.
- Score policy: informational exposure signals (`DEFAULT_DATABASE_PREFIX`,
  `XMLRPC_ENABLED`, `FILE_MODS_ALLOWED`, `FORCE_SSL_ADMIN_DISABLED`) no longer
  debit the risk score, and `REST_USER_ENUMERATION` is low rather than medium.
  `severity_overrides` raises any of them per project.

**Reporting**

- JSON schema `2.0`: `risk_score` and `coverage_score` are separate and
  always accompanied by `confidence`; per-finding `fingerprint` and structured
  `occurrences`; explicit `unknown`/`suppressed` counters; the effective
  policy (`config_path`, `project_config`, `disabled_checks`,
  `severity_overrides`, `suppressions`, `live`) is disclosed in every report.
- Coverage is scored independently of risk: skipped and unknown checks reduce
  it by their importance weight, every gap is listed with its reason, and
  reports warn whenever coverage is below 80%. `--fail-on-coverage-below`
  turns it into a CI gate.
- New `--format sarif` (SARIF 2.1.0, one run per site, suppressions and
  fingerprints mapped) and `--output FILE` (atomic write, refused inside the
  scanned tree).
- Discovery reports its own accounting (`roots`, `directories_visited`,
  `truncated`, `truncation_reason`) so "nothing found" is distinguishable from
  "search gave up".
- List fields are always arrays, never `null`, including for an empty scan, so
  machine consumers need no special case.
- `wpus checks` publishes each check's coverage importance (human table and
  JSON), matching the registry table in the documentation.

**Data layer**

- Separate HTTP clients per purpose (release API, checksum API, vulnerability
  feed, site probes). The feed previously inherited a 10-second timeout
  intended for small JSON API calls.
- Wordfence provider: scan context propagation, `CreateTemp` + atomic rename,
  a 512 MiB decompressed budget, `ETag`/`If-Modified-Since` revalidation,
  stale temporary-file sweeping, index restricted to the components the scan
  will look up, and structured advisory fields (CVSS score/vector, patched
  versions/ranges, remediation).

**Verification**

- Adversarial fixtures: a fake WP-CLI binary proves a static scan never
  executes target code and that `--live` does; a hostile `.wpus.yaml` proves
  project configuration is not trusted; a file named with escape sequences
  and backticks proves output injection is neutralised; zero-target runs fail
  the exit code.
- Five fuzz targets (`ParseWpConfig`, `VersionCompare`, `VersionBetween`,
  `Scrubber`, report sanitizers) with the PHP ordering quirks they uncovered
  documented in the tests.
- Documentation-consistency tests: `docs/checks.md` and the README check list
  are compared against the live registry (existence, category, coverage
  importance), so documentation drift fails the suite instead of shipping.
- CI: race tests on Linux and macOS, a fuzz job, `govulncheck`, the
  four-platform build matrix, and an integration job that downloads a real
  WordPress release, verifies it against the WordPress.org manifest, and
  detects a tampered file with its exact path.

### Changed — project conversion (0.1.0 baseline)

The repository was converted from `uscli` — a Bubble Tea TUI for remotely
managing the Ultimate Security WordPress plugin — into **Ultimate Security
CLI (`wpus`)**: a local, read-only WordPress security auditor.

- Product: Ultimate Security CLI; binary: `wpus`.
- Added commands: `wpus scan`, `wpus discover`, `wpus checks`,
  `wpus version`, `wpus help`.
- Added 30 security checks across 12 stable categories (core, config,
  authentication, plugins, themes, users, filesystem, database, php,
  web-server, network, hardening, exposure).
- Added deterministic scoring engine with documented weights and volume
  decay.
- Added reporting: terminal (TTY-aware color), JSON (`schema_version` 1.0),
  and Markdown.
- Added bounded cross-platform discovery (Linux + macOS layouts).
- Added optional WP-CLI integration (read-only commands only).
- Added `VulnerabilityProvider` architecture with a Wordfence Intelligence
  client (opt-in via `WPUS_VULNDB_FILE` or `WPUS_WORDFENCE_TOKEN`).
- Added central redaction layer applied to all findings before reporting.
- Added stable exit-code policy (0/1/2/3/4).
- Added installer script, Makefile, GoReleaser config, GitHub Actions CI
  (linux/macOS test matrix, four-target build matrix).
- Added documentation: README, architecture, checks reference, scoring,
  agents guide, vulnerability data, development guide, CONTRIBUTING,
  SECURITY.
- Removed: `uscli` TUI, REST API client, Bubble Tea/huh dependencies.
- Dependencies: `spf13/cobra`, `gopkg.in/yaml.v3` (runtime); everything else
  stdlib.

[Unreleased]: https://github.com/wpultimatesecurity/ultimate-security-cli/
