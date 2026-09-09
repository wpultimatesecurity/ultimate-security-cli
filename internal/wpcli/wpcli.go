// Package wpcli wraps WP-CLI (`wp`) as an optional, non-mandatory insight
// source. Every command runs read-only; nothing here performs updates or
// writes. All failures are soft: callers degrade to filesystem-only facts.
package wpcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DefaultTimeout bounds a single wp invocation.
const DefaultTimeout = 12 * time.Second

// Runner executes WP-CLI against one site path.
type Runner struct {
	Bin     string
	Timeout time.Duration
	// Log receives one line per invocation when verbose logging is on.
	Log func(string)
}

// Detect finds a usable wp binary. WPUS_WP_CLI overrides PATH lookup so
// users with unusual installs (or tests) can point at a specific binary.
func Detect(getenv func(string) string) *Runner {
	bin := ""
	if getenv != nil {
		bin = getenv("WPUS_WP_CLI")
	}
	if bin == "" {
		p, err := exec.LookPath("wp")
		if err != nil {
			return nil
		}
		bin = p
	}
	return &Runner{Bin: bin, Timeout: DefaultTimeout}
}

// Available reports whether a runner exists (WP-CLI found).
func (r *Runner) Available() bool { return r != nil && r.Bin != "" }

// ErrUnavailable is returned by typed accessors when WP-CLI cannot answer.
var ErrUnavailable = errors.New("wpcli: unavailable")

// ExtStatus mirrors `wp plugin list` / `wp theme list` JSON rows.
type ExtStatus struct {
	Name          string `json:"name"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	Update        string `json:"update"`
	UpdateVersion string `json:"update_version"`
}

// User mirrors `wp user list` JSON rows (metadata only).
type WPUser struct {
	ID         int64  `json:"ID"`
	Login      string `json:"user_login"`
	Email      string `json:"user_email"`
	Roles      string `json:"roles"`
	Registered string `json:"user_registered"`
}

func (r *Runner) run(site string, timeout time.Duration, args ...string) ([]byte, error) {
	if !r.Available() {
		return nil, ErrUnavailable
	}
	if timeout <= 0 {
		timeout = r.Timeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := append([]string{"--path=" + site, "--no-color", "--quiet"}, args...)
	cmd := exec.CommandContext(ctx, r.Bin, full...) //nolint:gosec // bin from LookPath or explicit env override
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if r.Log != nil {
			r.Log("wp " + strings.Join(args, " ") + " failed: " + firstLine(msg))
		}
		return nil, fmt.Errorf("wp %s: %s", strings.Join(args, " "), firstLine(msg))
	}
	return out, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// CoreVersion returns the running WordPress version per WP-CLI.
func (r *Runner) CoreVersion(site string) (string, error) {
	out, err := r.run(site, 0, "core", "version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ExtensionList returns plugin or theme rows for the site.
func (r *Runner) ExtensionList(site, kind string) ([]ExtStatus, error) {
	out, err := r.run(site, 0, kind, "list", "--format=json", "--fields=name,status,version,update,update_version")
	if err != nil {
		return nil, err
	}
	var rows []ExtStatus
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("wp %s list: %w", kind, err)
	}
	return rows, nil
}

// Option reads a single wp_options value.
func (r *Runner) Option(site, key string) (string, error) {
	out, err := r.run(site, 0, "option", "get", key)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// AdminUsers lists administrator accounts.
func (r *Runner) AdminUsers(site string) ([]WPUser, error) {
	out, err := r.run(site, 0, "user", "list", "--role=administrator", "--format=json",
		"--fields=ID,user_login,user_email,roles,user_registered")
	if err != nil {
		return nil, err
	}
	var users []WPUser
	if err := json.Unmarshal(out, &users); err != nil {
		return nil, fmt.Errorf("wp user list: %w", err)
	}
	return users, nil
}

// CLIPHPVersion returns the PHP version of the WP-CLI runtime.
func (r *Runner) CLIPHPVersion(site string) (string, error) {
	out, err := r.run(site, 0, "cli", "info", "--format=json")
	if err != nil {
		return "", err
	}
	var info struct {
		PHPVersion string `json:"php_version"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return "", fmt.Errorf("wp cli info: %w", err)
	}
	if info.PHPVersion == "" {
		return "", fmt.Errorf("wp cli info: php_version missing")
	}
	return info.PHPVersion, nil
}

// EvalExpr runs a read-only PHP expression via wp eval and returns stdout.
// Only pure introspection expressions are used by this package.
func (r *Runner) EvalExpr(site, expr string) (string, error) {
	out, err := r.run(site, 0, "eval", expr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// FilterBool evaluates `apply_filters(name, default)` on the live site.
func (r *Runner) FilterBool(site, filter string) (*bool, error) {
	expr := fmt.Sprintf(`var_export( apply_filters( %q, true ), true );`, filter)
	out, err := r.EvalExpr(site, expr)
	if err != nil {
		return nil, err
	}
	v, err := strconv.ParseBool(strings.TrimSpace(out))
	if err != nil {
		return nil, fmt.Errorf("wp eval %s: unexpected output %q", filter, firstLine(out))
	}
	return &v, nil
}

// IniGet reads a PHP ini setting from the WP-CLI runtime.
func (r *Runner) IniGet(site, key string) (string, error) {
	expr := fmt.Sprintf(`echo (string) ini_get( %q );`, key)
	return r.EvalExpr(site, expr)
}

// Siteenv gathers everything wpus uses from WP-CLI in one call-site helper,
// keeping the number of spawned processes predictable.
type Siteenv struct {
	Version  string
	PHP      string
	SiteURL  string
	HomeURL  string
	Plugins  []ExtStatus
	Themes   []ExtStatus
	Admins   []WPUser
	XMLRPC   *bool
	DispErrs string
}

// Collect gathers all WP-CLI-backed facts for a site. Individual failures
// are recorded per-field and do not abort the rest.
func (r *Runner) Collect(site string) *Siteenv {
	e := &Siteenv{}
	e.Version, _ = r.CoreVersion(site)
	e.PHP, _ = r.CLIPHPVersion(site)
	e.SiteURL, _ = r.Option(site, "siteurl")
	e.HomeURL, _ = r.Option(site, "home")
	e.Plugins, _ = r.ExtensionList(site, "plugin")
	e.Themes, _ = r.ExtensionList(site, "theme")
	e.Admins, _ = r.AdminUsers(site)
	e.XMLRPC, _ = r.FilterBool(site, "xmlrpc_enabled")
	e.DispErrs, _ = r.IniGet(site, "display_errors")
	return e
}
