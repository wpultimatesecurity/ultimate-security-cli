# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
