# Security checks

Every check has a stable ID and category, reports a standardized finding, and
follows the skip discipline: **when the condition cannot be determined, the
check is skipped or unknown — never guessed.**

The registry currently holds **44 checks**.

Categories are stable API: `wordpress-core`, `wordpress-config`,
`authentication`, `plugins`, `themes`, `users`, `filesystem`, `database`,
`php`, `web-server`, `network`, `hardening`, `exposure`. Twelve are in use
today; `users` is reserved — administrator-account checks report under
`authentication`.

Each check also carries a **coverage importance** (`core`, `standard`,
`context`). Coverage is scored separately from risk, and a skipped `core` check
costs more coverage than a skipped `context` check — see
[scoring.md](scoring.md).

## Registry

| ID | Category | Importance | Default |
|---|---|---|---|
| `WP_CORE_OUTDATED` | wordpress-core | standard | enabled |
| `WP_CORE_AUTO_UPDATES_DISABLED` | wordpress-core | context | enabled |
| `WP_CORE_VULNERABILITY` | wordpress-core | core | enabled |
| `CORE_INTEGRITY_MODIFIED` | wordpress-core | core | enabled |
| `CORE_FILE_MISSING` | wordpress-core | core | enabled |
| `CORE_UNEXPECTED_FILE` | wordpress-core | core | enabled |
| `WP_DEBUG_ENABLED` | wordpress-config | context | enabled |
| `WP_DEBUG_DISPLAY_ENABLED` | wordpress-config | context | enabled |
| `FILE_EDITOR_ENABLED` | wordpress-config | standard | enabled |
| `FILE_MODS_ALLOWED` | wordpress-config | context | enabled |
| `SECURITY_KEYS_MISSING` | wordpress-config | core | enabled |
| `WP_CONFIG_PARENT_LOCATION` | wordpress-config | context | enabled |
| `FORCE_SSL_ADMIN_DISABLED` | hardening | context | enabled |
| `WP_CONFIG_PERMISSIONS` | filesystem | core | enabled |
| `WEAK_FILE_PERMISSIONS` | filesystem | standard | enabled |
| `CUSTOM_CONTENT_PATH` | filesystem | core | enabled |
| `EXPOSED_ENV_FILE` | exposure | core | enabled |
| `EXPOSED_GIT_DIRECTORY` | exposure | standard | enabled |
| `EXPOSED_DEBUG_LOG` | exposure | context | enabled |
| `EXPOSED_BACKUP_FILE` | exposure | core | enabled |
| `EXPOSED_EDITOR_BACKUP` | exposure | standard | enabled |
| `SENSITIVE_FILE_PUBLICLY_RETRIEVABLE` | exposure | core | enabled |
| `BASELINE_DRIFT` | filesystem | standard | enabled |
| `PHP_EXECUTION_IN_UPLOADS` | hardening | core | enabled |
| `XMLRPC_ENABLED` | hardening | context | enabled |
| `HTTPS_DISABLED` | network | core | enabled |
| `REST_USER_ENUMERATION` | exposure | context | enabled |
| `PLUGIN_OUTDATED` | plugins | standard | enabled |
| `PLUGIN_VULNERABILITY` | plugins | core | enabled |
| `PLUGIN_INTEGRITY_MODIFIED` | plugins | core | enabled |
| `PLUGIN_INTEGRITY_MISSING_FILE` | plugins | standard | enabled |
| `PLUGIN_INTEGRITY_EXTRA_FILE` | plugins | standard | enabled |
| `PLUGIN_CHECKSUM_UNAVAILABLE` | plugins | context | enabled |
| `MU_PLUGIN_PRESENT` | plugins | core | enabled |
| `INACTIVE_PLUGIN` | plugins | standard | enabled |
| `THEME_OUTDATED` | themes | standard | enabled |
| `THEME_VULNERABILITY` | themes | core | enabled |
| `INACTIVE_THEME` | themes | standard | enabled |
| `DROPIN_PRESENT` | hardening | core | enabled |
| `DIRECTORY_LISTING` | web-server | context | enabled |
| `ADMIN_USERNAME` | authentication | core | enabled |
| `DEFAULT_DATABASE_PREFIX` | database | context | enabled |
| `PHP_OUTDATED` | php | core | enabled |
| `PHP_DISPLAY_ERRORS` | php | standard | enabled |

Individual checks can be excluded per run:

```bash
wpus scan --exclude-check XMLRPC_ENABLED --exclude-check REST_USER_ENUMERATION
```

or by policy. Unknown IDs are rejected — a typo cannot silently disable a
check:

```yaml
checks:
  disabled:
    - REST_USER_ENUMERATION
```

## Check details

### WordPress core

**WP_CORE_OUTDATED** — medium/high. Compares the installed version (parsed
from `wp-includes/version.php`, WP-CLI fallback) against the official
WordPress.org release APIs. The primary source is the stable-check feed
(`insecure` → high, `outdated` → medium); when it is unavailable, wpus falls
back to the version-check endpoint and derives the same classification from
per-branch upgrade offers (a version behind its own branch's fix releases is
`insecure`; a maintained-branch tip that is not the newest release is
`outdated`). Skipped offline or when both endpoints are unreachable.
Reference: [WordPress hardening](https://developer.wordpress.org/advanced-administration/security/).

**WP_CORE_VULNERABILITY** — severity from the provider's rating. Matches the
installed core version against a vulnerability provider. This is deliberately
different from `WP_CORE_OUTDATED` (maintenance state) and
`CORE_INTEGRITY_MODIFIED` (local file tampering): it reports advisories that
affect this exact version. Requires a provider; skipped otherwise.

**CORE_INTEGRITY_MODIFIED** — high, confidence medium. Verifies every core
file in `wp-admin/` and `wp-includes/` plus the root-level core files against
the official WordPress.org checksum manifest for the installed version and
locale. Extended or patched files are reported with their path in
`occurrences`. Altered core files are either tampering or a host-side patch;
the wording says so, and the recommendation is to compare against the official
release before restoring. `wp-includes/version.php` is excluded — every update
rewrites it. Performed statically: no WordPress bootstrap, no PHP execution,
and the manifest is cached for 24 hours.

**CORE_FILE_MISSING** — medium. Manifest files absent from disk. Missing core
files break updates and are a common aftermath of incomplete malware cleanup.

**CORE_UNEXPECTED_FILE** — medium. Files in `wp-admin/` or `wp-includes/` that
the official release does not contain — the shape of injected code. Extra
files in the *site root* are reported as context only, because deploy scripts
and server configuration legitimately live there.

### wp-config.php

All config checks statically parse `wp-config.php` (comments stripped,
`define()`/`const`/`$table_prefix` matched lexically). The file is **never
executed**, and parsed secret values never leave the process — they are
seeded into the central redaction scrubber instead. The file is found in the
installation root or, as WordPress allows, one directory above it.

- **WP_DEBUG_ENABLED** — medium (low on declared local/dev/staging
  environments). Debug output leaks internals.
- **WP_DEBUG_DISPLAY_ENABLED** — medium (same dev downgrade). Note the
  WordPress default: when `WP_DEBUG` is on and `WP_DEBUG_DISPLAY` is
  undefined, display is ON. The check models that default.
- **FILE_EDITOR_ENABLED** — medium. The built-in editor is admin-level code
  execution waiting for a compromised account.
- **FILE_MODS_ALLOWED** — info. Reported as a policy signal, not a universal
  deduction: `DISALLOW_FILE_MODS` is right for immutable or
  deployment-managed sites and wrong for others.
- **SECURITY_KEYS_MISSING** — high. Any of the 8 salt/key constants missing
  or still the `put your unique phrase here` placeholder.
- **FORCE_SSL_ADMIN_DISABLED** — info, confidence medium. Only evaluated when
  the site URL is HTTPS; modern WordPress already forces HTTPS for admin in
  that case.
- **WP_CONFIG_PARENT_LOCATION** — info. Records whether `wp-config.php` was
  found above the web root, so the layout is visible in the report.

### Layout

**CUSTOM_CONTENT_PATH** — core importance. Reports the resolved content,
plugin, MU-plugin, and uploads directories and where each path came from
(`default` or the constant that overrode it). WordPress supports relocated and
renamed directories, so the scanner resolves `WP_CONTENT_DIR`, `WP_PLUGIN_DIR`,
`WPMU_PLUGIN_DIR`, and `UPLOADS` statically (string literals, `__FILE__`,
`__DIR__`, `ABSPATH`, `dirname()`, concatenation). When a constant cannot be
evaluated, the check reports **unknown** and the site records a coverage gap
instead of silently scanning the default location and implying full coverage.

### Database

**DEFAULT_DATABASE_PREFIX** — info. The `wp_` prefix marks default
configuration. A prefix is not a security control and changing it on a live
site is invasive, so this is reported without a score deduction.

### Filesystem

- **WP_CONFIG_PERMISSIONS** — high if world-writable, medium if
  group-writable, low if world-readable; `600/640/660` pass.
- **WEAK_FILE_PERMISSIONS** — medium. Counts world-writable files and
  directories under the web root with the bounded walker; reports counts,
  truncation reason, and unreadable/unexamined entries.

### Exposure

- **EXPOSED_ENV_FILE** — high, confidence medium (depends on whether the
  server serves dotfiles). Contents are never read.
- **EXPOSED_GIT_DIRECTORY** — medium, confidence medium. `.git` in the web
  root can expose history and committed secrets.
- **EXPOSED_DEBUG_LOG** — low. Non-empty `wp-content/debug.log`.
- **EXPOSED_BACKUP_FILE** — high, confidence medium. SQL dumps and
  backup-named archives inside the web root.
- **EXPOSED_EDITOR_BACKUP** — low. `wp-config.php~`, `*.bak`, `*.orig`,
  `*.swp` in the web root.
- **SENSITIVE_FILE_PUBLICLY_RETRIEVABLE** — high when confirmed, confidence
  high. Turns the exposure leads above into evidence: it asks the site itself
  (through the SSRF-restricted prober) whether each candidate is actually
  downloadable. Only files that exist on disk are probed, only with `HEAD`
  (never `GET`, and never a `.php` file — that would execute it), capped at 12
  requests per scan: `.env`, `.env.local`, `.git/HEAD`, the resolved
  `debug.log`, the four `wp-config.php` backup names, and backup/dump archives
  in the site root. `200` → confirmed exposure (evidence carries the response
  status, content type, and length — contents are never downloaded or stored);
  `401/403/404/410` → not retrievable; anything else → `unknown`. A content
  directory outside the web root has no derivable URL, so its files are not
  probed at a guessed path.

### Hardening

- **PHP_EXECUTION_IN_UPLOADS** — medium. PHP files under the resolved uploads
  directory are practically always bad news. `--deep` also inspects hidden
  subdirectories there.
- **XMLRPC_ENABLED** — info. Determined from the live `xmlrpc_enabled` filter
  via WP-CLI (`--live`); file presence alone proves nothing, so without it the
  check skips. XML-RPC on is *not* automatically critical — the wording and
  the severity say so.
- **DROPIN_PRESENT** — info, status failed when any exist. Inventories
  `object-cache.php`, `advanced-cache.php`, `db.php`, `db-error.php`,
  `install.php`, `maintenance.php`, `php-error.php`,
  `fatal-error-handler.php`, and `sunrise.php` with their documented load
  points, and flags ones modified in the last 14 days.

### Network

- **HTTPS_DISABLED** — medium (info for loopback/`.local`/`.test` dev hosts).
  Reads `home`/`siteurl` from WP-CLI, falling back to `WP_HOME`/`WP_SITEURL`
  constants.
- **REST_USER_ENUMERATION** — low, network-backed. One unauthenticated
  `GET /wp-json/wp/v2/users` through the policy-checked prober: the request is
  pinned to the site's own origin, cloud metadata endpoints are unreachable,
  and a probe blocked by policy is reported as `unknown` with the reason
  rather than silently skipped. 200 with users → failed (the finding carries
  one `occurrence` per exposed login); 401/403/404 → passed; `--offline` →
  skipped.

### Plugins

- **PLUGIN_OUTDATED** — low, aggregated. Requires WP-CLI (`--live`). Inactive
  plugins are reported too, marked as inactive: their PHP stays
  web-reachable, so update availability is not hidden by activation state.
  Counts describe the finding, not the truncated display list.
- **PLUGIN_VULNERABILITY** — severity from the data provider's CVSS rating
  (critical→critical, …; unknown rating maps to high). Each advisory becomes a
  structured `occurrence` (slug, version, advisory ID, CVE, CVSS, fixed
  versions, provider) instead of a joined string. Requires a configured
  provider; with none, the check reports skipped rather than pretending. See
  [vulnerability-data.md](vulnerability-data.md).
- **PLUGIN_INTEGRITY_MODIFIED** — high. Compares plugin files against the
  official WordPress.org release archive for the installed version. Opt-in
  (`--verify-plugin-checksums`) because it downloads one archive per plugin.
- **PLUGIN_INTEGRITY_MISSING_FILE** — medium. Files shipped in the release but
  absent on disk.
- **PLUGIN_INTEGRITY_EXTRA_FILE** — low, or medium when any extra file is PHP.
  Explains the distinction: caches and compiled translations are normal, and
  `.git`/`node_modules`/`.DS_Store` are excluded from the list.
- **PLUGIN_CHECKSUM_UNAVAILABLE** — info, status **unknown**. Custom and
  premium plugins have no public release to compare against. This is a
  coverage statement: "unverifiable" is not "modified", and the check never
  reports the former as the latter.
- **MU_PLUGIN_PRESENT** — info, status failed when any exist. Must-use plugins
  load on every request and never appear in the admin plugin list, which makes
  them a favoured persistence location. Top-level `*.php` files in the MU
  directory are inventoried with their parsed headers.
- **INACTIVE_PLUGIN** — low, aggregated. Requires WP-CLI.

### Baselines and drift

**BASELINE_DRIFT** — medium for newly appeared components/findings, low for
version changes, info for removals and resolved findings. Compares the current
installation against a baseline recorded earlier:

```bash
wpus baseline create /srv/site --output baseline.json
wpus scan /srv/site --baseline baseline.json
```

Drift covers plugins, themes, MU plugins, drop-ins, administrator accounts
(only with `--live`), and the finding set (compared by fingerprint, so
rewording does not register as a change). Without `--baseline` the check
skips and the site records a coverage gap. A baseline that cannot be read is a
usage error rather than a silent full scan.

### Themes

- **THEME_OUTDATED** — low, aggregated. Requires WP-CLI.
- **THEME_VULNERABILITY** — as `PLUGIN_VULNERABILITY`, with structured
  occurrences.
- **INACTIVE_THEME** — info.

### Users

**ADMIN_USERNAME** — medium. Requires WP-CLI (`--live`). Never outputs emails
or IDs beyond the user number of the flagged account.

### PHP

- **PHP_OUTDATED** — high (EOL) / low (security-only tail). Source is the
  WP-CLI runtime's PHP version; evidence labels that source explicitly so
  web-SAPI differences are visible. A PHP line missing from the lifecycle table
  is reported as **unknown**, never as "actively supported" — an unrecognised
  version string is exactly where a false pass would hide. Lifecycle dates from
  [php.net/supported-versions](https://www.php.net/supported-versions.php); a
  maintenance test fails once the table has not been reviewed in a year.
- **PHP_DISPLAY_ERRORS** — low, confidence low by design (CLI ini ≠ web ini).

### Web server

**DIRECTORY_LISTING** — low. Only decided from readable local configuration:
`.htaccess` (`Options ±Indexes`) or readable `nginx.conf` (`autoindex on`).
Unreadable host configs yield `unknown`/`skipped`, never findings.

## Statuses

| Status | Meaning |
|---|---|
| `passed` | The check ran and the condition is good. |
| `failed` | The check ran and found a problem. |
| `skipped` | Not applicable or not available under this policy (no provider, offline, no WP-CLI). |
| `unknown` | Attempted but inconclusive (unparsable version, probe blocked by policy, unverifiable plugin). |

`skipped` and `unknown` both reduce the coverage score, and both are counted
separately in the report summary. Suppressed findings keep their status,
carry `suppressed: true` plus a reason, and are excluded from scoring and the
exit policy.

## Severity and confidence

Severity describes impact *if the finding is real*: `critical`, `high`,
`medium`, `low`, `info`. Confidence describes epistemic certainty:
`high`, `medium`, `low`. A finding can be low-severity/high-confidence
(`DEFAULT_DATABASE_PREFIX`) or high-severity/medium-confidence
(`EXPOSED_ENV_FILE`).

## Adding a check

1. Pick a stable ID and category; register with `checks.Register` in the
   matching file under `internal/checks/`.
2. Set `Importance` deliberately: `ImpCore` for checks whose absence is a
   blind spot, `ImpContext` for advisory/policy checks.
3. Respect the skip discipline; put the reason in evidence.
4. Record coverage gaps with `ctx.AddGap` when you knowingly could not examine
   something.
5. Emit `Occurrences` for anything a consumer might want to address
   individually (one per file, plugin, advisory, or user).
6. Include authoritative references.
7. Add table tests with fixtures (see `internal/checks/checks_test.go` and
   `internal/checks/integrity_test.go`), and add the row to the registry table
   above.
