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
anything that could make the tool leak scanned secrets, execute site code, or
modify scanned sites.

Out of scope: vulnerabilities in WordPress itself, plugins, or themes that
`wpus` merely *reports on* — use responsible-disclosure channels of the
affected project (for WordPress core, see
https://hackerone.com/wordpress).

## Design commitments relevant to security review

- Scans are read-only; site PHP (including `wp-config.php`) is never
  executed — parsing is lexical only.
- Secrets observed while parsing are held in memory and scrubbed centrally
  before any output; see `internal/redaction`.
- Network behavior is minimal and documented: WordPress.org release checks
  and the optional Wordfence feed. `--offline` disables all of it.
- No telemetry. Nothing is uploaded, ever.
