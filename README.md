# Ultimate Security CLI (`wpus`)

**Local, read-only WordPress security auditing for humans and AI agents.**

`wpus` discovers the WordPress installations on your machine, runs a battery of
read-only security checks, computes a deterministic risk score and a separate
coverage score, and reports results for the terminal, for documents, and for
agents.

Scans are **static by default**: the audited site's PHP is never executed.
`--live` additionally lets WP-CLI load WordPress for extra facts, at the cost
of executing target-controlled code.

```bash
wpus scan
```

## What it does

- **Discovers** WordPress installations in standard Linux and macOS locations
  (`/var/www`, `~/Sites`, `~/Local Sites`, hosting layouts, project dirs) —
  fast, bounded, and safe; or scan a path you give it (paths double as walk
  seeds, so scanning `/var/www` finds every site inside it). Discovery reports
  whether it stopped early, so "none found" is distinguishable from "gave up".
- **Inspects** WordPress core, `wp-config.php`, plugins, themes, must-use
  plugins and drop-ins, the resolved content layout, filesystem permissions,
  PHP runtime, and web-server configuration where locally readable.
- **Verifies integrity** against authoritative sources: core files against the
  WordPress.org checksum manifest, and — with `--verify-plugin-checksums` —
  plugin files against the official release archive.
- **Detects** meaningful weaknesses: insecure/outdated core, tampered or
  missing core files, debug exposure, missing salts, vulnerable
  plugins/themes (with a data provider), weak file permissions, exposed
  `.env`/`.git`/backups/debug logs, PHP in uploads, and more.
- **Scores** each site deterministically: a risk score (0–100) with
  per-category breakdowns, plus a coverage score that states how much of the
  audit actually ran.
- **Explains** every finding: what it is, why it matters, evidence, and a
  concrete recommendation.
- **Reports** for humans (terminal, TTY-aware color), for documents (Markdown),
  for machines (stable JSON), and for code-scanning systems (SARIF 2.1.0) —
  cleanly scriptable and CI-friendly.
- **Tracks drift**: record a baseline and diff later scans against it to see
  what changed on the installation since the last known-good state.

## What it does NOT do

- No exploitation, brute-force, credential attacks, or malware.
- No payloads, no destructive remediation, no "fix it" writes.
- No modification of the scanned site: **scans are strictly read-only**, and a
  report is never written inside an audited tree.
- No execution of the audited site's PHP unless `--live` is passed explicitly.
- No telemetry. No uploads of your data. Network access is limited to
  documented purposes, all disabled by `--offline`: the WordPress.org release
  feed and core checksum manifest, an optional vulnerability feed when
  configured; `--verify-plugin-checksums` adds one archive download per
  WordPress.org plugin; and policy-checked requests to the site's own origin
  only (one REST request plus at most twelve HEAD probes that confirm whether
  exposed files are actually downloadable — never a body read, never a PHP
  file).

## Supported platforms

| OS | Architectures |
|---|---|
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |

## Installation

### Install script

```bash
curl -fsSL https://raw.githubusercontent.com/wpultimatesecurity/ultimate-security-cli/main/scripts/install.sh | sh
```

The installer detects your OS/architecture, downloads the matching release,
verifies the sha256 checksum, and installs without root when possible
(`~/.local/bin` first, `/usr/local/bin` as fallback). Override anything:

```bash
WPUS_VERSION=v0.1.0 WPUS_INSTALL_DIR=/usr/local/bin sh install.sh
```

Or run the checked-in script directly after cloning: `sh scripts/install.sh`.

### Manual installation

Grab a binary from [Releases](https://github.com/wpultimatesecurity/ultimate-security-cli/releases),
unpack it, and put it on your `PATH`:

```bash
tar -xzf wpus_*_darwin_arm64.tar.gz
install -m 0755 wpus ~/.local/bin/wpus
```

### From source

```bash
git clone https://github.com/wpultimatesecurity/ultimate-security-cli
cd ultimate-security-cli
make build && ./wpus version
```

### Homebrew (planned)

`brew install --cask wpus` arrives with the project's own tap. The release
configuration deliberately ships without Homebrew packaging until that tap
exists, because a release would otherwise fail while publishing to it.

### Verifying a download

Release artifacts carry a signed build provenance attestation, so a download
can be traced back to the workflow, repository, and commit that produced it:

```bash
gh attestation verify wpus_<version>_<os>_<arch>.tar.gz \
  --repo wpultimatesecurity/ultimate-security-cli
```

## Quick start

```bash
wpus scan                     # discover + audit everything it finds
wpus scan /var/www/example.com
wpus scan ~/Sites/example --format markdown
wpus scan --json --fail-on high
wpus scan --live /srv/site                # richer facts; executes target PHP
wpus scan /srv/site --format sarif --output results.sarif
wpus discover                 # just list installations
wpus checks                   # list all security checks
wpus version
```

Try it immediately on the bundled demo fixture (an intentionally weak site):

```bash
wpus scan --offline testdata/demo-site
```

## Commands

| Command | Purpose |
|---|---|
| `wpus scan [path…]` | Audit one or more installations (or auto-discover). |
| `wpus baseline create <path>` | Record a point-in-time inventory for later drift comparison. |
| `wpus discover [path…]` | Find installations without scanning. |
| `wpus checks` | List the check registry. |
| `wpus version` | Print build information. |
| `wpus help` | Help for any command. |

### Scan flags

| Flag | Effect |
|---|---|
| `--path, -p` | Site path(s); positional paths also work. |
| `--format` | `terminal` (default), `json`, `markdown`, `sarif`. |
| `--json` | Shorthand for `--format json`. |
| `--output FILE` | Write the report to a file atomically instead of stdout. |
| `--severity` | Report only failed findings at or above this level. |
| `--fail-on` | Exit `1` when findings meet or exceed this level. |
| `--fail-on-coverage-below N` | Exit `1` when a site's coverage score is below `N` percent. |
| `--exclude` | Path(s) to skip during discovery (repeatable). |
| `--exclude-check` | Check ID(s) to skip (repeatable). |
| `--offline` | Disable all network access. |
| `--deep` | Raise filesystem walk budgets (slower, deeper). |
| `--live` | Let WP-CLI load WordPress for extra facts (executes target-controlled PHP). |
| `--allow-empty` | Exit `0` when discovery finds no installation. |
| `--config PATH` | Use this configuration file; it must exist. |
| `--baseline FILE` | Compare the site against a baseline from `wpus baseline create` and report drift. |
| `--trust-project-config` | Also allow `./.wpus.yaml` from the scanned directory. |
| `--no-config` | Ignore every configuration file. |
| `--verify-plugin-checksums` | Verify plugin files against their WordPress.org release archives (one download per plugin). |
| `--timeout` | Discovery time budget (e.g. `30s`). |
| `--no-color`, `--quiet`, `--verbose` | Output control (all commands). |

### Static by default

A default `wpus scan` never executes the audited site's PHP. That makes the
result trustworthy on an untrusted target, but it also means some facts simply
are not available:

- **What a static scan does see:** the core version (`wp-includes/version.php`),
  the parsed constants in `wp-config.php`, plugin/theme headers and versions on
  disk, must-use plugins and drop-ins, the resolved WordPress content layout,
  file permissions, local web-server configuration, and — with network access —
  vulnerabilities matching installed versions, core/plugin file integrity,
  REST user enumeration, and confirmation that exposed files are actually
  downloadable (same-origin HEAD probes only).
- **What it cannot see:** the live database, active plugin/theme state, update
  availability, and runtime PHP settings. Checks that need those report
  `skipped` with a reason instead of guessing.
- **`--live`** lets WP-CLI load WordPress to collect those facts. This executes
  target-controlled PHP, so it is opt-in and prints a warning; it is the only
  path that runs site code. It also requires WP-CLI to be installed and the
  site to answer (a database outage degrades it back to skipped checks).

Because a static scan misses part of the audit, every site carries a
**coverage score** alongside its risk score: a high risk score with low
coverage means "not examined", not "clean". Use `--fail-on-coverage-below` to
make that a hard failure in CI.

### Configuration

Configuration is optional. Precedence is:

1. `--config PATH` — an explicit file, which must exist.
2. The per-user config directory (`$WPUS_CONFIG_DIR`, else the platform
   default: `~/.config/wpus` on Linux, `~/Library/Application Support/wpus` on
   macOS), using `config.yaml` or `config.yml`.
3. `./.wpus.yaml` or `./.wpus.yml` from the directory the scan runs in — only
   when `--trust-project-config` is passed, because the audited tree must not
   be able to configure its own audit.

`--no-config` disables all config loading. Decoding is strict: an unknown key
is an error, and an unknown check ID in `checks.disabled`, `severity_overrides`
or `suppressions` is an error rather than a silent no-op.

```yaml
fail_on: high
fail_on_coverage_below: 60
exclude:
  - /var/www/archive
checks:
  disabled:
    - REST_USER_ENUMERATION
severity_overrides:
  DEFAULT_DATABASE_PREFIX: info
suppressions:
  - id: XMLRPC_ENABLED
    reason: legacy integration until Q4
    expires: 2026-12-31
```

A suppression must carry a `reason`, may carry an `expires: YYYY-MM-DD` date,
and is kept visible in the report (shown as suppressed) rather than deleted; a
malformed date counts as expired, so a typo cannot extend an accepted risk
forever. Every report discloses the effective policy — the config path, whether
it was project-local, disabled checks, severity overrides, suppressions, and
whether the run was live.

### Baselines

For the operational question "what changed since the last known-good state?":

```bash
wpus baseline create /srv/site --output /secure/site-baseline.json
wpus scan /srv/site --baseline /secure/site-baseline.json --format json
```

`wpus baseline create <path> --output <file>` records the inventory (core
version, plugins, themes, must-use plugins, drop-ins, and administrators —
the last only with `--live`) together with the fingerprints of every open
finding. It writes atomically and refuses an `--output` inside the scanned
site. `wpus scan --baseline FILE` runs the `BASELINE_DRIFT` check, which
reports components added, removed, or moved to a different version, drop-in
and administrator changes, and findings that appeared or were resolved.

Drift is a relative signal, not a verdict: an intended deployment looks
identical to an undocumented change, so treat it as a review queue. A missing
or unreadable baseline file is a usage error (exit `2`); administrator drift
requires `--live`, because a static scan cannot read the user table.

## Example scan

```text
$ wpus scan --offline testdata/demo-site

Ultimate Security CLI
WordPress Security Audit

Site
────────────────────────────────────────
Path          /home/you/sites/demo-site
WordPress     6.4.1
Platform      Linux
Risk          17/100  Coverage 43% (low confidence)

Incomplete: 24 of 44 checks could not be determined — a high risk score here does not mean the site was fully examined.

HIGH
────────────────────────────────────────

Database dumps or backup archives inside the web root
  Potential database dumps or backup archives exist inside the web root. If
  the web server serves them, the full database (users, password hashes,
  secrets) is downloadable.
  matches:    backup.sql

Recommendation
  Move backups outside the web root (or to off-site storage) and block
  archive/dump extensions in the server configuration.

Authentication keys and salts are missing or default
  8 of 8 authentication key/salt constants are missing or still hold the
  installer placeholder; cookie signing degrades without them.

Recommendation
  Generate fresh values with the WordPress.org salt service and define all
  eight constants in wp-config.php.

MEDIUM
────────────────────────────────────────

Built-in file editor is enabled
  No DISALLOW_FILE_EDIT definition was found, so wp-admin can edit plugin
  and theme PHP directly.

PHP files inside wp-content/uploads
  1 PHP file(s) were found inside wp-content/uploads.

WP_DEBUG_DISPLAY shows errors to visitors
WP_DEBUG is enabled

LOW
────────────────────────────────────────

WordPress debug log is present in the web root
wp-config.php is world-readable

INFO
────────────────────────────────────────

Default database table prefix in use
Admin file modifications are allowed

Summary
────────────────────────────────────────
Critical    0
High        2
Medium      4
Low         2
Info        2
Unknown     0
Suppressed  0
Sites       1 site(s) scanned, 10 passed, 24 skipped
```

(Output trimmed; each LOW/INFO entry carries its own evidence and
recommendation, as in the earlier sections.)

## JSON output

`--json` emits a single stable document — no decorative text, clean under `jq`:

```json
{
  "schema_version": "2.0",
  "tool": { "name": "wpus", "version": "0.1.0" },
  "environment": { "OS": "linux", "Arch": "amd64" },
  "scan": {
    "started_at": "2026-09-11T12:00:00Z",
    "duration_ms": 1234,
    "offline": true,
    "deep": false,
    "live": false,
    "checks_run": 44
  },
  "sites": [
    {
      "path": "/var/www/example.com",
      "wordpress_version": "6.8.2",
      "php_version": "8.2.10",
      "risk_score": 78,
      "coverage_score": 62,
      "confidence": "medium",
      "coverage": {
        "score": 62,
        "checks_determined": 27,
        "checks_total": 44,
        "confidence": "medium",
        "files_walked": 18422,
        "gaps": [ /* check_id, status, reason, importance */ ]
      },
      "category_scores": { "wordpress-config": 90, "plugins": 61 },
      "findings": [
        {
          "id": "EXPOSED_BACKUP_FILE",
          "title": "Database dumps or backup archives inside the web root",
          "category": "exposure",
          "severity": "high",
          "status": "failed",
          "confidence": "medium",
          "description": "Potential database dumps or backup archives exist…",
          "evidence": { "matches": "backup.sql" },
          "recommendation": "Move backups outside the web root…",
          "references": ["https://developer.wordpress.org/advanced-administration/security/security/"],
          "fingerprint": "5c013a175d717c49"
        }
        /* a vulnerability finding, when a provider is configured, carries one
           occurrence per matched advisory:
        {
          "id": "PLUGIN_VULNERABILITY",
          "severity": "critical",
          "status": "failed",
          "fingerprint": "…",
          "occurrences": [
            {
              "resource_type": "plugin", "slug": "contact-form-7",
              "version": "5.8.0", "advisory_id": "uuid",
              "cve": "CVE-2024-0000", "cvss_score": 9.8,
              "severity": "critical", "fixed_versions": ["5.8.1"],
              "provider": "wordfence"
            }
          ]
        } */
      ]
    }
  ],
  "summary": {
    "sites_scanned": 1,
    "critical": 0, "high": 1, "medium": 3, "low": 4, "info": 6,
    "passed": 12, "skipped": 15, "unknown": 0, "suppressed": 0
  }
}
```

Lists are always arrays — including on an empty result (`"sites": []`) — so
consumers never have to special-case `null`. Findings carry a `fingerprint`
(stable across reruns and independent of wording) and structured
`occurrences`, so consecutive scans can be diffed without parsing prose. `unknown` (attempted but inconclusive) and `suppressed`
(accepted risk, kept visible) are counted separately from `skipped`.

```bash
wpus scan --json | jq '.sites[].findings[] | select(.severity=="high")'
wpus scan --json | jq '.sites[] | {path, risk_score, coverage_score, confidence}'
```

The schema is versioned (`schema_version`); breaking changes bump it, and 2.0
renamed `score` to `risk_score` and added coverage, confidence, fingerprints,
and occurrences.

## SARIF, Markdown and files

```bash
wpus scan /var/www/site --format sarif --output results.sarif
wpus scan /var/www/site --format markdown --output report.md
```

SARIF 2.1.0 output emits one run per site, locates findings relative to the
site root, maps suppressions to SARIF suppressions and fingerprints to
`partialFingerprints`. `--output` writes atomically (a temp file renamed into
place), so an interrupted scan never leaves a half-written report; it refuses a
destination inside a scanned site, keeping the read-only contract.

## AI-agent usage

`wpus` is designed as an agent tool: non-interactive, machine-readable, and
exit-code driven.

**Standard workflow**

```text
1. Run wpus scan --json (add --offline for hermetic runs).
2. For each site, read risk_score AND coverage_score; never call a low risk
   score with low coverage "clean".
3. Parse .sites[].findings; filter status == "failed", note .suppressed.
4. Sort by severity; read .description, .evidence and .occurrences.
5. Explain root causes; propose remediations from .recommendation.
6. Never modify a production site without explicit user authorization.
```

**Sample prompts**

- *“Run `wpus scan --json`, review every high and critical finding, explain
  the root cause, and propose fixes. Do not modify anything.”*
- *“Run `wpus scan --json --fail-on high`. If it fails, analyze the findings
  and create an implementation plan.”*

More detail, including full schema semantics: [docs/agents.md](docs/agents.md).

## Security checks

44 checks across 13 stable categories (12 in use today; `users` is reserved) (full details and references in
[docs/checks.md](docs/checks.md)):

| ID | Category | What it catches |
|---|---|---|
| `WP_CORE_OUTDATED` | wordpress-core | Insecure/outdated core vs the official release feed |
| `WP_CORE_AUTO_UPDATES_DISABLED` | wordpress-core | Background security updates turned off |
| `WP_CORE_VULNERABILITY` | wordpress-core | Core advisories matching the installed version (needs a provider) |
| `CORE_INTEGRITY_MODIFIED` / `CORE_FILE_MISSING` / `CORE_UNEXPECTED_FILE` | wordpress-core | Core files changed, missing, or unrecognised vs the WordPress.org manifest |
| `WP_DEBUG_ENABLED` / `WP_DEBUG_DISPLAY_ENABLED` | wordpress-config | Debug leakage to logs/visitors |
| `FILE_EDITOR_ENABLED` / `FILE_MODS_ALLOWED` | wordpress-config | Admin code execution surface |
| `SECURITY_KEYS_MISSING` | wordpress-config | Missing/placeholder auth keys & salts |
| `WP_CONFIG_PARENT_LOCATION` | wordpress-config | `wp-config.php` kept above the web root (informational) |
| `FORCE_SSL_ADMIN_DISABLED` | hardening | Admin not pinned to HTTPS |
| `PHP_EXECUTION_IN_UPLOADS` | hardening | Executable PHP in the uploads tree |
| `XMLRPC_ENABLED` | hardening | XML-RPC left on when unneeded |
| `DROPIN_PRESENT` | hardening | Privileged drop-in files |
| `WP_CONFIG_PERMISSIONS` / `WEAK_FILE_PERMISSIONS` | filesystem | Overly open file modes |
| `CUSTOM_CONTENT_PATH` | filesystem | Relocated content directories; fails when a configured path cannot be resolved |
| `BASELINE_DRIFT` | filesystem | What changed since the inventory recorded by `wpus baseline create` (skips without `--baseline`) |
| `EXPOSED_ENV_FILE` / `EXPOSED_GIT_DIRECTORY` / `EXPOSED_DEBUG_LOG` / `EXPOSED_BACKUP_FILE` / `EXPOSED_EDITOR_BACKUP` | exposure | Sensitive files in the web root |
| `SENSITIVE_FILE_PUBLICLY_RETRIEVABLE` | exposure | Confirms exposed files are actually downloadable (same-origin HEAD only, no bodies) |
| `REST_USER_ENUMERATION` | exposure | Open `/wp-json/wp/v2/users` |
| `HTTPS_DISABLED` | network | Plain-HTTP site URLs |
| `PLUGIN_OUTDATED` / `PLUGIN_VULNERABILITY` / `INACTIVE_PLUGIN` | plugins | Update & vulnerability status |
| `MU_PLUGIN_PRESENT` | plugins | Must-use plugins auto-loaded on every request |
| `PLUGIN_INTEGRITY_MODIFIED` / `PLUGIN_INTEGRITY_MISSING_FILE` / `PLUGIN_INTEGRITY_EXTRA_FILE` / `PLUGIN_CHECKSUM_UNAVAILABLE` | plugins | Plugin files vs the official release archive (opt-in) |
| `THEME_OUTDATED` / `THEME_VULNERABILITY` / `INACTIVE_THEME` | themes | Same, for themes |
| `DIRECTORY_LISTING` | web-server | Auto-index enabled in readable configs |
| `ADMIN_USERNAME` | authentication | Default `admin` account |
| `DEFAULT_DATABASE_PREFIX` | database | Default `wp_` prefix |
| `PHP_OUTDATED` / `PHP_DISPLAY_ERRORS` | php | EOL runtime; error display |

Checks that cannot determine their condition report `skipped`/`unknown` —
never a guess. False-positive discipline: no “vulnerable because old”, no
findings from unreadable configs, severity reflects actual impact.

## Scoring

Two independent scores, both deterministic and documented in
[docs/scoring.md](docs/scoring.md):

- **Risk score** (0–100): each failed finding subtracts its severity weight
  (`critical 40, high 20, medium 10, low 4, info 0`) from 100, with a decay so
  that volume beyond three findings per severity counts at half weight.
  Passed, skipped, unknown and suppressed findings never change it.
  Per-category scores use the same rule, so reports show *where* the risk
  lives.
- **Coverage score** (0–100): the weighted share of checks that reached a
  conclusion, where checks carrying the security signal weigh more than
  context checks. It states how much of the audit actually ran, so a high risk
  score with low coverage can never be mistaken for a clean site.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed and the configured policy passed |
| `1` | Policy failure: findings met `--fail-on`, or a site's coverage fell below `--fail-on-coverage-below` |
| `2` | Invalid arguments or configuration |
| `3` | Runtime failure during the scan |
| `4` | Insufficient permissions for the requested operation |
| `5` | Nothing was scanned (no installation found) |

A scan that inspected nothing exits `5` by default so it cannot pass CI
silently; `--allow-empty` turns an empty run into `0`. Informational findings
alone never fail a run.

## Architecture

Go, stdlib-first, statically compiled for all four release targets.

```text
cmd/wpus/            entrypoint
internal/
  app/               command wiring, scan orchestration, exit policy, checksum adapter
  discovery/         bounded WordPress discovery with truncation accounting
  wordpress/         site model, static wp-config parser, layout resolution,
                     plugin/theme/MU-plugin/drop-in inventory
  wpcli/             WP-CLI provider, only invoked with --live
  checks/            check framework + 44 checks (each independently registered)
  checksums/         WordPress.org core manifest + plugin release-zip digests
  vulnerability/     VulnerabilityProvider interface + Wordfence feed client
  probe/             SSRF-checked HTTP prober (same-origin, size-capped)
  releases/          WordPress.org release data (stable-check → version-check fallback)
  scoring/           deterministic risk scoring + weighted coverage
  redaction/         centralized secret redaction before any output
  sanitize/          output-channel escaping (terminal/Markdown/paths/logs)
  reporting/         terminal / json / markdown / sarif reporters
  platform/          OS/arch and per-user dirs
  config/            strict YAML config loading with a trust model
  version/           build identity injected at link time
```

Every `wp-config.php` is parsed lexically; the audited site's PHP is **never
executed** unless `--live` is passed. Platform differences (Linux vs macOS
paths, permission semantics) are isolated in `platform/` and `discovery/`.
Details: [docs/architecture.md](docs/architecture.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Language decision, package layout, scan pipeline, trust boundary, layout/integrity sources, performance |
| [docs/checks.md](docs/checks.md) | Every check: registry, severities, confidence, skip rules, authoring guide |
| [docs/scoring.md](docs/scoring.md) | The risk and coverage algorithms with worked examples |
| [docs/agents.md](docs/agents.md) | JSON schema 2.0 semantics, coverage, exit codes, jq recipes, CI integration |
| [docs/vulnerability-data.md](docs/vulnerability-data.md) | Configuring vulnerability providers (Wordfence feed, offline feed files) |
| [docs/development.md](docs/development.md) | Build, test, fuzz, integration, release tooling, dependency license inventory |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Ground rules and the check-contribution checklist |
| [SECURITY.md](SECURITY.md) | Trust model (what runs, what is requested, what is written) and how to report issues in wpus itself |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Development

```bash
make build      # build ./wpus
make test       # unit tests (fixtures only, no real sites, no network)
make test-race  # tests under the race detector
make lint       # gofmt + go vet
make fuzz       # 20–30s fuzz run over the parsers that take hostile input
make vulncheck  # govulncheck over reachable code
make hygiene    # verify nothing private or generated is tracked
make integration    # scans a real WordPress release and proves integrity detection (network)
make release-local  # all four release binaries + checksums into dist/
```

Conventions and contribution flow: [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/development.md](docs/development.md).

## Contributing

Issues and pull requests welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) first — new checks must register in the
registry, carry references, respect the skip/unknown discipline, and include
tests with fixtures.

## Responsible disclosure

Found a security issue in `wpus` itself? See [SECURITY.md](SECURITY.md).
`wpus` is an auditing tool — use it only on installations you own or are
authorized to assess.

## Roadmap

- A GitHub Action wrapping `--format sarif`
- More vulnerability-data providers (interface is ready)
- Suspicious-PHP heuristics beyond the core/plugin integrity comparison
- Multisite-aware user/content checks
- Remote targets (SSH, Docker, Incus/LXC) behind the same provider seams

## License

MIT © Ultimate Security — see [LICENSE](LICENSE).
