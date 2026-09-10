package probe

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ErrBlocked is the sentinel returned (wrapped) by every policy refusal, so a
// caller can tell "the scanner refused to make this request" apart from a
// transient network failure.
var ErrBlocked = errors.New("probe: destination blocked")

// BlockedError reports that a URL, origin, or resolved address was refused by
// prober policy. It unwraps to ErrBlocked.
type BlockedError struct {
	// Target is the refused URL, host, or address.
	Target string
	// Reason explains which rule fired.
	Reason string
}

// Error implements error.
func (e *BlockedError) Error() string {
	return fmt.Sprintf("probe: destination blocked: %s: %s", e.Target, e.Reason)
}

// Unwrap exposes ErrBlocked so callers can use errors.Is.
func (e *BlockedError) Unwrap() error { return ErrBlocked }

// Policy defines what a Prober is allowed to reach. The zero value denies
// everything, which is the safe default: the site URL a scan probes comes from
// target-controlled WordPress state, so every destination must be opted in.
type Policy struct {
	// AllowedOrigins lists exact origins (for example "https://example.com")
	// the prober may contact. Only scheme, host, and effective port are
	// compared; a missing or empty list denies every request.
	AllowedOrigins []string
	// AllowPrivate permits loopback, RFC1918, CGNAT, and ULA targets so local
	// development sites can be scanned. It never permits link-local or cloud
	// metadata addresses — those are blocked unconditionally.
	AllowPrivate bool
	// FollowSameOriginRedirects follows redirects that stay on the request's
	// own origin. Cross-origin redirects are always blocked.
	FollowSameOriginRedirects bool
	// MaxRedirects caps same-origin hops. Zero uses DefaultMaxRedirects; it
	// only applies when FollowSameOriginRedirects is set.
	MaxRedirects int
	// MaxBodyBytes caps how much of a response body is retained. Zero uses
	// DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// Timeout bounds one request including dial, redirects, and body read.
	// Zero uses DefaultTimeout. A shorter caller context still wins.
	Timeout time.Duration
}

// metadataHosts are cloud instance-metadata names that must never be resolved
// or contacted. They are refused by name so the check does not depend on DNS
// being available (or on the name resolving to the "expected" address).
var metadataHosts = map[string]bool{
	"metadata.google.internal": true,
	"metadata.goog":            true,
}

// blockedRange pairs an address range with a human-readable reason.
type blockedRange struct {
	prefix netip.Prefix
	reason string
}

// blockedAlways holds ranges that are refused even with AllowPrivate: they
// host cloud metadata services or are otherwise never a WordPress site.
var blockedAlways = []blockedRange{
	{netip.MustParsePrefix("0.0.0.0/8"), "unspecified network"},
	{netip.MustParsePrefix("169.254.0.0/16"), "IPv4 link-local (cloud metadata)"},
	{netip.MustParsePrefix("100.100.100.200/32"), "cloud metadata address"},
	{netip.MustParsePrefix("255.255.255.255/32"), "IPv4 broadcast"},
	{netip.MustParsePrefix("fe80::/10"), "IPv6 link-local"},
	{netip.MustParsePrefix("fd00:ec2::254/128"), "cloud metadata address"},
}

// blockedPrivate holds ranges allowed only when AllowPrivate is set, because
// local development sites live there but so do internal networks the scanner
// must not be able to pivot into.
var blockedPrivate = []blockedRange{
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback address"},
	{netip.MustParsePrefix("10.0.0.0/8"), "private address"},
	{netip.MustParsePrefix("172.16.0.0/12"), "private address"},
	{netip.MustParsePrefix("192.168.0.0/16"), "private address"},
	{netip.MustParsePrefix("100.64.0.0/10"), "carrier-grade NAT address"},
	{netip.MustParsePrefix("::1/128"), "loopback address"},
	{netip.MustParsePrefix("fc00::/7"), "unique local address"},
}

// normalizeOrigin reduces a URL to a comparison key of scheme://host[:port],
// lowercasing the host and dropping the default port for the scheme. Two URLs
// with the same key are the same origin for policy purposes.
func normalizeOrigin(u *url.URL) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("missing host")
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" {
		return scheme + "://" + host, nil
	}
	return scheme + "://" + host + ":" + port, nil
}

// parseAddr parses a host that may be a bracketed IPv6 literal.
func parseAddr(host string) (netip.Addr, error) {
	return netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
}

// checkHost refuses obviously hostile hosts before any DNS lookup happens:
// literal IPs are classified directly, and metadata hostnames are refused by
// name even though they would (or might not) resolve to a blocked address.
func (p *Prober) checkHost(host string) error {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return &BlockedError{Target: host, Reason: "empty host"}
	}
	if metadataHosts[host] {
		return &BlockedError{Target: host, Reason: "cloud metadata hostname"}
	}
	if addr, err := parseAddr(host); err == nil {
		return p.checkAddr(addr)
	}
	return nil
}

// checkAddr validates one resolved address. IPv4-mapped IPv6 forms are
// unmapped first so ::ffff:127.0.0.1 is judged by the IPv4 rules.
func (p *Prober) checkAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return &BlockedError{Target: addr.String(), Reason: "invalid address"}
	}
	addr = addr.WithZone("").Unmap()
	if addr.IsUnspecified() {
		return &BlockedError{Target: addr.String(), Reason: "unspecified address"}
	}
	if addr.IsMulticast() {
		return &BlockedError{Target: addr.String(), Reason: "multicast address"}
	}
	for _, r := range blockedAlways {
		if r.prefix.Contains(addr) {
			return &BlockedError{Target: addr.String(), Reason: r.reason}
		}
	}
	if p.allowPrivate {
		return nil
	}
	for _, r := range blockedPrivate {
		if r.prefix.Contains(addr) {
			return &BlockedError{Target: addr.String(), Reason: r.reason}
		}
	}
	return nil
}
