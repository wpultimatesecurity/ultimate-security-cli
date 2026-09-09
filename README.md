# Ultimate Security CLI (`wpus`)

**Local, read-only WordPress security auditing for humans and AI agents.**

`wpus` discovers the WordPress installations on your machine, runs a battery of
read-only security checks, computes a deterministic security score, and reports
results for the terminal, for documents, and for agents.

```bash
wpus scan
```

## What it does

- **Discovers** WordPress installations in standard Linux and macOS locations
  (`/var/www`, `~/Sites`, `~/Local Sites`, hosting layouts, project dirs) —
  fast, bounded, and safely; or scans a path you give it.
- **Inspects** WordPress core, `wp-config.php`, plugins, themes, filesystem
  layout and permissions, PHP runtime, and web-server configuration where
  locally readable.
- **Detects** meaningful weaknesses: insecure/outdated core, debug exposure,
  missing salts, vulnerable plugins/themes (with a data provider), weak file
  permissions, exposed `.env`/`.git`/backups/debug logs, PHP in uploads, and
  more.
- **Scores** each site deterministically (0–100) with per-category breakdowns.
- **Explains** every finding: what it is, why it matters, evidence, and a
  concrete recommendation.
- **Reports** for humans (terminal, TTY-aware color), for documents (Markdown),
  and for machines (stable JSON) — cleanly scriptable and CI-friendly.

## What it does NOT do

- No exploitation, brute-force, credential attacks, or malware.
- No payloads, no destructive remediation, no "fix it" writes.
- No modification of the scanned site: **scans are strictly read-only.**
- No telemetry. No uploads of your data. Network access is limited to two
  small, documented lookups (WordPress.org releases; optional vulnerability
  feed) and can be disabled entirely with `--offline`.

## Supported platforms

| OS | Architectures |
|---|---|
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |

## Installation

### Install script

```bash
curl -fsSL https://example.com/install.sh | sh
```

The installer detects your OS/architecture, downloads the matching release,
verifies the sha256 checksum, and installs without root when possible
(`~/.local/bin` first, `/usr/local/bin` as fallback). Override anything:

```bash
WPUS_VERSION=v0.1.0 WPUS_INSTALL_DIR=/usr/local/bin sh install.sh
```

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

```bash
brew install wpus   # packaging is goreleaser-compatible; tap lands with the first release
```

## Quick start

```bash
wpus scan                     # discover + audit everything it finds
wpus scan /var/www/example.com
wpus scan ~/Sites/example --format markdown
wpus scan --json --fail-on high
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
| `wpus discover [path…]` | Find installations without scanning. |
| `wpus checks` | List the check registry. |
| `wpus version` | Print build information. |
| `wpus help` | Help for any command. |

### Scan flags

| Flag | Effect |
|---|---|
| `--path, -p` | Site path(s); positional paths also work. |
| `--format` | `terminal` (default), `json`, `markdown`. |
| `--json` | Shorthand for `--format json`. |
| `--severity` | Report only failed findings at or above this level. |
| `--fail-on` | Exit `1` when findings meet or exceed this level. |
| `--exclude` | Path(s) to skip during discovery (repeatable). |
| `--exclude-check` | Check ID(s) to skip (repeatable). |
| `--offline` | Disable all network access. |
| `--deep` | Raise filesystem walk budgets (slower, deeper). |
| `--skip-wpcli` | Don't use WP-CLI even if installed. |
| `--timeout` | Discovery time budget (e.g. `30s`). |
| `--no-color`, `--quiet`, `--verbose` | Output control (all commands). |

## Example scan

```text
Ultimate Security CLI
WordPress Security Audit

Site
────────────────────────────────────────
Path          /var/www/example.com
WordPress     6.8.2
PHP           8.2.10
Server        nginx
Platform      Linux
Security      78/100

HIGH
────────────────────────────────────────

Plugins with known vulnerabilities
  1 installed plugin(s) match known vulnerabilities.
  matches:    contact-form-7 5.8.0: CVE-2024-0000 (critical) fixed in: 5.8.1

Recommendation
  Update every affected plugin to the fixed version. …

Summary
────────────────────────────────────────
Critical    0
High        1
Medium      3
Low         4
Info        6
```

## JSON output

`--json` emits a single stable document — no decorative text, clean under `jq`:

```json
{
  "schema_version": "1.0",
  "tool": { "name": "wpus", "version": "0.1.0" },
  "environment": { "os": "darwin", "arch": "arm64" },
  "scan": { "started_at": "2026-09-10T12:00:00Z", "duration_ms": 1234 },
  "sites": [
    {
      "path": "/var/www/example.com",
      "wordpress_version": "6.8.2",
      "score": 78,
      "findings": [ /* id, title, category, severity, status,
                       confidence, description, evidence,
                       recommendation, references */ ]
    }
  ],
  "summary": { "sites_scanned": 1, "critical": 0, "high": 1, "medium": 3, "low": 4, "info": 6 }
}
```

```bash
wpus scan --json | jq '.sites[].findings[] | select(.severity=="high")'
```

The schema is versioned (`schema_version`); breaking changes bump it.

## AI-agent usage

`wpus` is designed as an agent tool: non-interactive, machine-readable, and
exit-code driven.

**Standard workflow**

```text
1. Run wpus scan --json (add --offline for hermetic runs).
2. Parse .sites[].findings; sort by severity.
3. Read .description and .evidence for each finding; check .confidence.
4. Explain root causes; propose remediations from .recommendation.
5. Never modify a production site without explicit user authorization.
```

**Sample prompts**

- *“Run `wpus scan --json`, review every high and critical finding, explain
  the root cause, and propose fixes. Do not modify anything.”*
- *“Run `wpus scan --json --fail-on high`. If it fails, analyze the findings
  and create an implementation plan.”*

More detail, including full schema semantics: [docs/agents.md](docs/agents.md).

## Security checks

30 checks across 12 stable categories (full details and references in
[docs/checks.md](docs/checks.md)):

| ID | Category | What it catches |
|---|---|---|
| `WP_CORE_OUTDATED` | wordpress-core | Insecure/outdated core vs the official release feed |
| `WP_CORE_AUTO_UPDATES_DISABLED` | wordpress-core | Background security updates turned off |
| `WP_DEBUG_ENABLED` / `WP_DEBUG_DISPLAY_ENABLED` | wordpress-config | Debug leakage to logs/visitors |
| `FILE_EDITOR_ENABLED` / `FILE_MODS_ALLOWED` | wordpress-config | Admin code execution surface |
| `SECURITY_KEYS_MISSING` | wordpress-config | Missing/placeholder auth keys & salts |
| `FORCE_SSL_ADMIN_DISABLED` | hardening | Admin not pinned to HTTPS |
| `WP_CONFIG_PERMISSIONS` / `WEAK_FILE_PERMISSIONS` | filesystem | Overly open file modes |
| `EXPOSED_ENV_FILE` / `EXPOSED_GIT_DIRECTORY` / `EXPOSED_DEBUG_LOG` / `EXPOSED_BACKUP_FILE` / `EXPOSED_EDITOR_BACKUP` | exposure | Sensitive files in the web root |
| `PHP_EXECUTION_IN_UPLOADS` | hardening | Executable PHP in `wp-content/uploads` |
| `XMLRPC_ENABLED` | hardening | XML-RPC left on when unneeded |
| `HTTPS_DISABLED` | network | Plain-HTTP site URLs |
| `REST_USER_ENUMERATION` | exposure | Open `/wp-json/wp/v2/users` |
| `PLUGIN_OUTDATED` / `PLUGIN_VULNERABILITY` / `INACTIVE_PLUGIN` | plugins | Update & vulnerability status |
| `THEME_OUTDATED` / `THEME_VULNERABILITY` / `INACTIVE_THEME` | themes | Same, for themes |
| `DIRECTORY_LISTING` | web-server | Auto-index enabled in readable configs |
| `ADMIN_USERNAME` | authentication | Default `admin` account |
| `DEFAULT_DATABASE_PREFIX` | database | Default `wp_` prefix |
| `PHP_OUTDATED` / `PHP_DISPLAY_ERRORS` | php | EOL runtime; error display |

Checks that cannot determine their condition report `skipped`/`unknown` —
never a guess. False-positive discipline: no “vulnerable because old”, no
findings from unreadable configs, severity reflects actual impact.

## Scoring

Deterministic and documented (see [docs/scoring.md](docs/scoring.md)):
each failed finding subtracts its severity weight
(`critical 40, high 20, medium 10, low 4, info 0`) from 100, with a decay so
that volume beyond three findings per severity counts at half weight. Passed,
skipped and unknown findings never change the score. Per-category scores use
the same rule, so reports show *where* the risk lives.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; the configured policy passed |
| `1` | Findings met or exceeded `--fail-on` (or `discover` found nothing) |
| `2` | Invalid arguments or configuration |
| `3` | Scan/runtime error |
| `4` | Insufficient permissions for the requested operation |

Informational findings alone never fail a run.

## Architecture

Go, stdlib-first, statically compiled for all four release targets.

```text
cmd/wpus/            entrypoint
internal/
  app/               command wiring, scan orchestration, exit policy
  discovery/         bounded WordPress discovery
  wordpress/         site model, static wp-config parser, plugin/theme headers
  wpcli/             optional WP-CLI provider (read-only)
  checks/            check framework + 30 checks (each independently registered)
  vulnerability/     VulnerabilityProvider interface + Wordfence feed client
  releases/          WordPress.org release data (core currency)
  scoring/           deterministic scoring engine
  redaction/         centralized secret redaction before any output
  reporting/         terminal / json / markdown reporters
  platform/          OS/arch and per-user directories
  config/            optional YAML config file
```

Every `wp-config.php` is parsed lexically — site PHP is **never executed**.
Platform differences (Linux vs macOS paths, permission semantics) are isolated
in `platform/` and `discovery/`. Details: [docs/architecture.md](docs/architecture.md).

## Development

```bash
make build      # build ./wpus
make test       # unit tests (fixtures only, no real sites, no network)
make lint       # gofmt + go vet
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

- SARIF output and a GitHub Action
- `--output <file>` for reports
- More vulnerability-data providers (interface is ready)
- Deep-scan file-integrity and suspicious-PHP heuristics
- Multisite-aware user/content checks
- Remote targets (SSH, Docker, Incus/LXC) behind the same provider seams

## License

MIT © Ultimate Security — see [LICENSE](LICENSE).
