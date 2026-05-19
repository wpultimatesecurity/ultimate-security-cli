# Ultimate Security CLI (`uscli`)

A terminal user interface (TUI) for managing [Ultimate Security](https://wordpress.org/plugins/ultimate-security/) WordPress sites. Built with Go and [Bubble Tea](https://github.com/charmbracelet/bubbletea).

## Quick Start

```bash
brew install wpultimatesecurity/uscli/uscli
uscli
```

On first launch, the setup wizard will guide you through connecting to your WordPress site. You will need:

- Site URL
- WordPress administrator username + Application Password
- (Optional) SSH key for WP-CLI operations

## Features

- Security dashboard with live score and threat summary
- Manage 2FA providers (Email, TOTP, HOTP, SMS, WebAuthn)
- Configure login protection, rate limiting, password policies
- View and filter activity logs and failed login attempts
- Configure CAPTCHA (reCAPTCHA, Turnstile)
- Apply security hardening (salt rotation, headers, recommendations)
- Manage Cloudflare WAF rules
- Import/export settings across sites
- Toggle Pro modules on/off

## How It Works

`uscli` connects to your WordPress site via two channels:

1. **REST API** — Primary data channel. Reads settings, scores, logs, user data. Writes configuration changes.
2. **SSH + WP-CLI** — Server-side operations. Runs salt rotation, file integrity scans, malware scans, cache purges, and migrations.

Both channels are optional. The TUI works in degraded mode if SSH is unavailable.

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Phase 1 Plan](docs/phase-1/README.md)
  - [Detailed Specifications](docs/phase-1/spec.md)
  - [API Reference](docs/phase-1/api-reference.md)
  - [Component Library](docs/phase-1/components.md)
  - [Config System](docs/phase-1/config.md)
  - [Data Flow](docs/phase-1/data-flow.md)
  - [Keybindings](docs/phase-1/keybindings.md)
  - [Project Timeline](docs/phase-1/timeline.md)

## Distribution

| Platform | Method |
|----------|--------|
| macOS | `brew install wpultimatesecurity/uscli/uscli` |
| Linux | Download binary from [GitHub Releases](https://github.com/wpultimatesecurity/ultimate-security-cli/releases) |
| Windows | Download binary from [GitHub Releases](https://github.com/wpultimatesecurity/ultimate-security-cli/releases) |

## License

MIT © Ultimate Security
