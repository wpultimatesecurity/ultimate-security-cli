# Security checks

Every check has a stable ID and category, reports a standardized finding, and
follows the skip discipline: **when the condition cannot be determined, the
check is skipped or unknown — never guessed.**

Categories are stable API: `wordpress-core`, `wordpress-config`,
`authentication`, `plugins`, `themes`, `users`, `filesystem`, `database`,
`php`, `web-server`, `network`, `hardening`, `exposure`.

## Registry

| ID | Category | Default |
|---|---|---|
| `WP_CORE_OUTDATED` | wordpress-core | enabled |
| `WP_CORE_AUTO_UPDATES_DISABLED` | wordpress-core | enabled |
| `WP_DEBUG_ENABLED` | wordpress-config | enabled |
| `WP_DEBUG_DISPLAY_ENABLED` | wordpress-config | enabled |
| `FILE_EDITOR_ENABLED` | wordpress-config | enabled |
| `FILE_MODS_ALLOWED` | wordpress-config | enabled |
| `SECURITY_KEYS_MISSING` | wordpress-config | enabled |
| `FORCE_SSL_ADMIN_DISABLED` | hardening | enabled |
| `WP_CONFIG_PERMISSIONS` | filesystem | enabled |
| `WEAK_FILE_PERMISSIONS` | filesystem | enabled |
| `EXPOSED_ENV_FILE` | exposure | enabled |
| `EXPOSED_GIT_DIRECTORY` | exposure | enabled |
| `EXPOSED_DEBUG_LOG` | exposure | enabled |
| `EXPOSED_BACKUP_FILE` | exposure | enabled |
| `EXPOSED_EDITOR_BACKUP` | exposure | enabled |
| `PHP_EXECUTION_IN_UPLOADS` | hardening | enabled |
| `XMLRPC_ENABLED` | hardening | enabled |
| `HTTPS_DISABLED` | network | enabled |
| `REST_USER_ENUMERATION` | exposure | enabled |
| `PLUGIN_OUTDATED` | plugins | enabled |
| `PLUGIN_VULNERABILITY` | plugins | enabled |
| `INACTIVE_PLUGIN` | plugins | enabled |
| `THEME_OUTDATED` | themes | enabled |
| `THEME_VULNERABILITY` | themes | enabled |
| `INACTIVE_THEME` | themes | enabled |
| `DIRECTORY_LISTING` | web-server | enabled |
| `ADMIN_USERNAME` | authentication | enabled |
| `DEFAULT_DATABASE_PREFIX` | database | enabled |
| `PHP_OUTDATED` | php | enabled |
| `PHP_DISPLAY_ERRORS` | php | enabled |

Individual checks can be excluded per run:

```bash
wpus scan --exclude-check XMLRPC_ENABLED --exclude-check REST_USER_ENUMERATION
```

or permanently:

```yaml
# .wpus.yaml
checks:
  disabled:
    - REST_USER_ENUMERATION
```

## Check details

### WordPress core

**WP_CORE_OUTDATED** — medium/high. Compares the installed version (parsed
from `wp-includes/version.php`, WP-CLI fallback) against the official
WordPress.org stable-check feed. The feed's `insecure` classification yields
high; plain `outdated` medium. Skipped offline or when the feed is
unreachable. Reference: [WordPress hardening](https://developer.wordpress.org/advanced-administration/security/).

**WP_CORE_AUTO_UPDATES_DISABLED** — low. Fails when `AUTOMATIC_UPDATER_DISABLED`
is true or `WP_AUTO_UPDATE_CORE` is `false`; minor updates are on by default.

### wp-config.php

All config checks statically parse `wp-config.php` (comments stripped,
`define()`/`const`/`$table_prefix` matched lexically). The file is **never
executed**, and parsed secret values never leave the process — they are
seeded into the central redaction scrubber instead.

- **WP_DEBUG_ENABLED** — medium (low on declared local/dev/staging
  environments). Debug output leaks internals.
- **WP_DEBUG_DISPLAY_ENABLED** — medium (same dev downgrade). Note the
  WordPress default: when `WP_DEBUG` is on and `WP_DEBUG_DISPLAY` is
  undefined, display is ON. The check models that default.
- **FILE_EDITOR_ENABLED** — medium. The built-in editor is admin-level code
  execution waiting for a compromised account.
- **FILE_MODS_ALLOWED** — low. Hardening recommendation for sites managed via
  WP-CLI/CI.
- **SECURITY_KEYS_MISSING** — high. Any of the 8 salt/key constants missing
  or still the `put your unique phrase here` placeholder.
- **FORCE_SSL_ADMIN_DISABLED** — low, confidence medium. Only evaluated when
  the site URL is HTTPS; otherwise `HTTPS_DISABLED` owns the problem.

### Database

**DEFAULT_DATABASE_PREFIX** — low. `wp_` prefix marks default configuration.
Low impact by design; changing prefixes on live sites is invasive, so the
recommendation is honest about the tradeoff.

### Filesystem

- **WP_CONFIG_PERMISSIONS** — high if world-writable, medium if
  group-writable, low if world-readable; `600/640/660` pass.
- **WEAK_FILE_PERMISSIONS** — medium. Counts world-writable files and
  directories under the web root with the bounded walker; reports counts and
  a note when the walk truncated.

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

### Hardening

- **PHP_EXECUTION_IN_UPLOADS** — medium. PHP files under
  `wp-content/uploads` are practically always bad news.
- **XMLRPC_ENABLED** — low. Determined from the live `xmlrpc_enabled` filter
  via WP-CLI; file presence alone proves nothing, so without WP-CLI this
  check skips. XML-RPC on is *not* automatically critical — the wording says
  so.

### Network

- **HTTPS_DISABLED** — medium (info for loopback/`.local`/`.test` dev hosts).
  Reads `home`/`siteurl` from WP-CLI, falling back to `WP_HOME`/`WP_SITEURL`
  constants.
- **REST_USER_ENUMERATION** — medium, network-backed. One unauthenticated
  `GET /wp-json/wp/v2/users`. 200 with users → failed (the finding includes
  how many logins leak); 401/403/404 → passed; offline → skipped. Disable
  with `--offline` or `--exclude-check`.

### Plugins & themes

- **PLUGIN_OUTDATED / THEME_OUTDATED** — low, aggregated. Requires WP-CLI
  (the official update API): skipped otherwise.
- **PLUGIN_VULNERABILITY / THEME_VULNERABILITY** — severity from the data
  provider's CVSS rating (critical→critical, …; unknown rating maps to high).
  Requires a configured vulnerability provider; with none, the check reports
  skipped rather than pretending. See [vulnerability-data.md](vulnerability-data.md).
- **INACTIVE_PLUGIN** — low, aggregated. **INACTIVE_THEME** — info.

### Users

**ADMIN_USERNAME** — medium. Requires WP-CLI. Never outputs emails or IDs
beyond the user number of the flagged account.

### PHP

- **PHP_OUTDATED** — high (EOL) / low (security-only tail). Source is the
  WP-CLI runtime's PHP version; evidence labels that source explicitly so
  web-SAPI differences are visible. Lifecycle dates from
  [php.net/supported-versions](https://www.php.net/supported-versions.php).
- **PHP_DISPLAY_ERRORS** — low, confidence low by design (CLI ini ≠ web ini).

### Web server

**DIRECTORY_LISTING** — low. Only decided from readable local configuration:
`.htaccess` (`Options ±Indexes`) or readable `nginx.conf` (`autoindex on`).
Unreadable host configs yield `unknown`/`skipped`, never findings.

## Severity and confidence

Severity describes impact *if the finding is real*: `critical`, `high`,
`medium`, `low`, `info`. Confidence describes epistemic certainty:
`high`, `medium`, `low`. A finding can be low-severity/high-confidence
(`DEFAULT_DATABASE_PREFIX`) or high-severity/medium-confidence
(`EXPOSED_ENV_FILE`).

## Adding a check

1. Pick a stable ID and category; register with `checks.Register` in the
   matching file under `internal/checks/`.
2. Respect the skip discipline; put the reason in evidence.
3. Include authoritative references.
4. Add table tests with fixtures (see existing `internal/checks/checks_test.go`).
5. Add a row to the registry table above and update `README.md` count.
