# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| latest release | yes |
| older releases | best effort |

## Reporting a vulnerability

Please report security issues in `wpus` itself privately:

1. Use GitHub "Security advisories → Report a vulnerability" on this
   repository, **or**
2. Email the maintainers (see the repository owner profile) with
   `[security]` in the subject.

Include: affected version (`wpus version`), OS/arch, reproduction steps, and
impact assessment. Please do not open public issues for security problems.

We aim to acknowledge reports within 7 days and will coordinate disclosure
timing with you.

## Scope

In scope: the `wpus` binary, its installer script, release packaging, and
anything that could make the tool leak scanned secrets, execute site code
unintentionally, modify scanned sites, or reach a host the operator did not
intend.

Out of scope: vulnerabilities in WordPress itself, plugins, or themes that
`wpus` merely *reports on* — use responsible-disclosure channels of the
affected project (for WordPress core, see
https://hackerone.com/wordpress).

## Design commitments relevant to security review

### Execution of the audited site's code

- **A default scan never executes the audited site's PHP.** `wp-config.php`,
  `version.php`, and plugin/theme headers are parsed lexically; the file
  contents are data, never code.
- **`--live` is the one exception, and it is opt-in.** It lets WP-CLI load
  WordPress so that database-backed facts (active plugins, administrator
  accounts, update state, runtime ini values) can be collected. That executes
  target-controlled PHP and is only safe against a site you trust. The flag
  prints a warning, is recorded in the report (`scan.live`), and no check may
  require it.
- Integrity verification, vulnerability matching, and filesystem checks are
  implemented statically so that they work on an untrusted and even
  unreachable site.

### Network behaviour

All network access is disabled by `--offline`. Otherwise:

| Purpose | Destination | Notes |
|---|---|---|
| WordPress core release data | `api.wordpress.org` | Small JSON; cached 24 h |
| Core checksum manifest | `api.wordpress.org` | Only the manifest; file contents never leave the machine |
| Vulnerability data | `wordfence.com` (or a local feed file) | Only when `WPUS_WORDFENCE_TOKEN`/`WPUS_VULNDB_FILE` is configured |
| Plugin integrity | `downloads.wordpress.org` | Only with `--verify-plugin-checksums`; one archive download per WordPress.org plugin |
| Site probes | the site's own origin | See below |

Site probes go through `internal/probe`, which enforces:

- requests are restricted to the audited site's own origin (scheme + host +
  port); a compromised `home`/`siteurl` cannot redirect the scanner elsewhere;
- cloud metadata addresses and hostnames (`169.254.169.254`,
  `metadata.google.internal`, …) are unreachable even when the site itself is
  local;
- loopback/RFC1918/ULA destinations are allowed only when the site is
  configured on such a host (a local development install);
- every resolved address is validated at connect time, so DNS rebinding cannot
  slip past the origin check;
- redirects are never followed cross-origin, and every hop is re-validated;
- response bodies are size-capped, proxy environment variables are ignored,
  and no cookie jar exists.

The exposure check sends `HEAD` only (no bodies are read), never requests a
`.php` file, and caps itself at twelve requests per site.

### Secrets

- Values that look secret-shaped while parsing `wp-config.php` (database
  password and user, salts and keys, the table prefix) are held in memory,
  registered with the central scrubber in `internal/redaction`, and removed
  from every field of every finding before a reporter can see it.
- Findings additionally pass through `internal/sanitize`, which strips control
  characters and escape sequences per output channel, so a hostile plugin
  name, path, or WP-CLI error line cannot inject ANSI/OSC sequences or
  Markdown structure into a report. WP-CLI output is scrubbed before it can
  reach a diagnostic log line.
- File contents are never uploaded, and the tool has no telemetry.

### Release artifacts

- Release archives are built by `.github/workflows/release.yml` from a tag,
  and every artifact carries a signed build provenance attestation
  (`gh attestation verify <artifact> --repo wpultimatesecurity/ultimate-security-cli`).
- `checksums.txt` is published with the release and the installer verifies it
  before installing; provenance verification is an additional, independent
  check that does not depend on the release channel being honest.
- Releases are created as drafts and published by a human.

### Modifying the audited site

- Scans are strictly read-only.
- Report output is refused if the destination lies inside a scanned site, and
  `--output` writes atomically, so the audited tree is never written to — not
  even by an accident of argument order.
- Caches (release data, checksum manifests, vulnerability feed) live in the
  per-user cache directory, never in the site.

### Operating on a hostile target

The scanner assumes the audited site may already be compromised:

- configuration is loaded from an explicit `--config` path or the operator's
  own config directory; a `./.wpus.yaml` inside the scanned tree is ignored
  unless `--trust-project-config` is passed, so a target cannot disable its own
  checks, lower its own severity levels, or silence findings;
- unknown YAML keys and unknown check IDs are hard errors rather than silent
  no-ops;
- every report states the policy that produced it (config path, whether it was
  project-local, disabled checks, severity overrides, suppressions, live mode),
  and a scan that inspected nothing exits `5` instead of reporting success.
