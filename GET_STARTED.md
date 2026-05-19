# Getting Started with `uscli`

`uscli` is a terminal UI for monitoring and managing a WordPress site running
the [Ultimate Security](https://wordpress.org/plugins/ultimate-security/)
plugin. It runs locally, connects over HTTPS, and is fully keyboard-driven.

## Prerequisites

- **Go 1.26+** if building from source
- **WordPress site** with Ultimate Security (v1.0.19+) installed and active
- **WordPress Application Password** for a user with administrator privileges

## Installation

### From source (current)

```bash
git clone https://github.com/wpultimatesecurity/ultimate-security-cli.git
cd ultimate-security-cli
go build -o uscli ./cmd/uscli
./uscli
```

### Via Homebrew (once released)

```bash
brew install wpultimatesecurity/tap/uscli
```

## Setting Up WordPress

`uscli` authenticates via **WordPress Application Passwords**. Generate one:

1. Log into your WordPress admin dashboard
2. Go to **Users → Profile**
3. Scroll to **Application Passwords**
4. Enter a name (e.g., "uscli") and click **Add New**
5. Copy the generated password (format: `xxxx xxxx xxxx xxxx xxxx xxxx`)

The WordPress user must have the `manage_options` capability. Administrator and
Editor roles work. Subscriber and Contributor roles will fail with a 403 error.

The Ultimate Security plugin must be **installed and active** on the site.

## First Run

Run `uscli` with no arguments:

```bash
./uscli
```

On first launch (or when no sites are configured), the **Connect** form opens:

| Field | Required | Notes |
|-------|----------|-------|
| Site name | No | Defaults to the domain name |
| Site URL | Yes | Site root — not `/wp-admin` or `/wp-login.php` |
| Username | Yes | WordPress username |
| Application Password | Yes | Masked input; spaces optional |
| Verify SSL | Yes | Leave on. Disabling shows a warning |

### Testing the Connection

Press `Ctrl+T` to test. `uscli` calls two REST endpoints to verify:

1. `/plugin-info` — confirms Ultimate Security is reachable
2. `/system-info` — reads WordPress and server details

| Result | Meaning |
|--------|---------|
| **Connected! v1.0.x** | Everything works. The site is saved locally. |
| **Auth failed (401/403)** | Username or Application Password is wrong, or user lacks permissions. |
| **Plugin not reachable** | Ultimate Security is not installed or active on this site. |
| **Network error / timeout** | URL is wrong, SSL issue, or site is down. |

A successful test saves the site to your local config and opens the Dashboard.

## Navigation

`uscli` is keyboard-first. No mouse is required.

### Global Keys

| Key | Action |
|-----|--------|
| `1`–`6` | Switch pages |
| `q`, `Ctrl+C` | Quit |
| `?` | Toggle help overlay |
| `r` | Refresh current page (uses cache) |
| `Ctrl+R` | Force refresh (bypasses cache) |
| `Ctrl+L` | Redraw screen |
| `Esc` | Go back / cancel / dismiss |

### Pages

| Key | Page | Purpose |
|-----|------|---------|
| `1` | Dashboard | Score, failed logins, online users, site status |
| `2` | Security Score | Tier breakdown, check details, manual recalculate |
| `3` | Login Protection | Read/edit login limits, password policies, IP blocking |
| `4` | 2FA Management | Email, TOTP, HOTP setup, verify, disable |
| `5` | Settings | Export/import settings, raw tree viewer, reset, cache purge |
| `6` | Activity Logs | Browse, search, filter, paginate audit logs |

### Table Navigation

| Key | Action |
|-----|--------|
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `Enter` | Open detail / expand |
| `n` / `→` | Next page |
| `p` / `←` | Previous page |
| `g` / `Home` | First row |
| `G` / `End` | Last row |

## Config File

Sites and preferences are stored in the local YAML config:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/uscli/config.yaml` |
| Linux | `~/.config/uscli/config.yaml` |
| Windows | `%AppData%/uscli/config.yaml` |

Permissions are set to `0600`. Application Passwords are stored as plain text
in this file — keep it secure. Do not share it or check it into version control.

To start fresh, delete the config file:

```bash
rm ~/Library/Application\ Support/uscli/config.yaml  # macOS
rm ~/.config/uscli/config.yaml                        # Linux
```

## Environment Variables

For scripting and CI, you can override the first site via environment variables:

| Variable | Overrides |
|----------|-----------|
| `USCLI_SITE_URL` | First site URL |
| `USCLI_SITE_USERNAME` | First site username |
| `USCLI_SITE_APP_PASSWORD` | First site Application Password |
| `USCLI_VERIFY_SSL` | First site SSL verification (`true` or `false`) |
| `USCLI_THEME` | UI theme (`dark`, `light`, or `auto`) |
| `USCLI_DEBUG` | Debug mode (`true` or `false`) |

If all three connection variables are present and no sites are saved, `uscli`
creates an in-memory site named `env`.

## Flags

```bash
uscli --version          # Print version and exit
uscli --debug            # Enable debug logging (sanitized)
uscli --config /path/to/config.yaml  # Use a custom config path
```

## Terminal Compatibility

- Works in 16-color terminals (colors degrade gracefully)
- No special fonts required (Nerd Fonts optional)
- Minimum width: 80 columns
- No mouse requirement
- Never relies on emoji for meaning

## Security Notes

- Application Passwords are masked in the UI and never logged
- Authorization headers are never written to debug logs
- TOTP and HOTP secrets are never logged
- Settings keys containing `password`, `secret`, `token`, `api_key`, or
  `webhook` are redacted in the settings tree viewer
- Destructive actions (reset, cleanup, import) always require confirmation
  and name the remote site in the prompt
