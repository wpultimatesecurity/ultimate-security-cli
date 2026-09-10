// Package probe performs the scanner's own outbound HTTP requests against the
// audited site. The site URL originates in WordPress state, which an attacker
// with admin access can usually influence, so this package treats every
// destination as untrusted: requests are pinned to an allow-list of origins
// and every resolved address is re-validated at dial time, making the scanner
// unusable as an SSRF pivot into the local network or cloud metadata services.
package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/version"
)

// Defaults applied when a Policy leaves the corresponding field zero.
const (
	DefaultMaxRedirects = 3
	DefaultMaxBodyBytes = 1 << 20 // 1 MiB
	DefaultTimeout      = 10 * time.Second
	// dialStepTimeout bounds each individual network step (dial, TLS
	// handshake, response headers) so a stalled peer cannot hold a
	// connection open past the overall request deadline.
	dialStepTimeout = 5 * time.Second
)

// Response is the bounded result of one probe request.
type Response struct {
	// StatusCode is the final response status.
	StatusCode int
	// Header is the final response header.
	Header http.Header
	// Body holds the response body, capped at Policy.MaxBodyBytes. It is nil
	// for Head requests.
	Body []byte
	// FinalURL is the URL that produced the response, after any redirects.
	FinalURL string
	// Truncated reports that the body exceeded Policy.MaxBodyBytes.
	Truncated bool
}

// Prober issues policy-checked HTTP requests. A Prober is safe for concurrent
// use; it owns one transport and reuses connections within it.
type Prober struct {
	allowed         map[string]bool
	allowPrivate    bool
	followRedirects bool
	maxRedirects    int
	maxBodyBytes    int64
	timeout         time.Duration

	dialer    *net.Dialer
	transport *http.Transport
}

// New builds a Prober from p, filling in defaults. Origins that are not
// absolute http/https URLs are ignored rather than rejected, so a typo in one
// entry cannot silently widen what the prober may reach.
func New(p Policy) *Prober {
	if p.MaxBodyBytes <= 0 {
		p.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if p.Timeout <= 0 {
		p.Timeout = DefaultTimeout
	}
	if p.FollowSameOriginRedirects && p.MaxRedirects <= 0 {
		p.MaxRedirects = DefaultMaxRedirects
	}

	allowed := make(map[string]bool, len(p.AllowedOrigins))
	for _, raw := range p.AllowedOrigins {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		origin, err := normalizeOrigin(u)
		if err != nil {
			continue
		}
		allowed[origin] = true
	}

	pr := &Prober{
		allowed:         allowed,
		allowPrivate:    p.AllowPrivate,
		followRedirects: p.FollowSameOriginRedirects,
		maxRedirects:    p.MaxRedirects,
		maxBodyBytes:    p.MaxBodyBytes,
		timeout:         p.Timeout,
		dialer:          &net.Dialer{Timeout: dialStepTimeout, KeepAlive: -1},
	}
	pr.transport = &http.Transport{
		// A nil Proxy ignores HTTP_PROXY/HTTPS_PROXY: honoring them would
		// let the environment redirect a "safe" request somewhere else.
		Proxy:                 nil,
		DialContext:           pr.dialContext,
		TLSHandshakeTimeout:   dialStepTimeout,
		ResponseHeaderTimeout: dialStepTimeout,
	}
	return pr
}

// OriginAllowed reports whether rawURL uses http/https and its origin is on
// the allow-list. Checks use it to pre-flight a candidate URL without
// spending a request on it.
func (p *Prober) OriginAllowed(rawURL string) bool {
	_, err := p.originOf(rawURL)
	return err == nil
}

// originOf returns the normalized origin of rawURL or a *BlockedError
// explaining why the URL is not permitted.
func (p *Prober) originOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", &BlockedError{Target: rawURL, Reason: "unparseable URL"}
	}
	origin, err := normalizeOrigin(u)
	if err != nil {
		return "", &BlockedError{Target: rawURL, Reason: err.Error()}
	}
	if !p.allowed[origin] {
		return "", &BlockedError{Target: rawURL, Reason: "origin not allowed: " + origin}
	}
	return origin, nil
}

// Get performs a GET request, returning a body capped at MaxBodyBytes.
func (p *Prober) Get(ctx context.Context, rawURL string, header http.Header) (*Response, error) {
	return p.do(ctx, http.MethodGet, rawURL, header)
}

// Head performs a HEAD request. The response body is never read.
func (p *Prober) Head(ctx context.Context, rawURL string, header http.Header) (*Response, error) {
	return p.do(ctx, http.MethodHead, rawURL, header)
}

// do is the shared request path for Get and Head.
func (p *Prober) do(ctx context.Context, method, rawURL string, header http.Header) (*Response, error) {
	origin, err := p.originOf(rawURL)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, &BlockedError{Target: rawURL, Reason: "unparseable URL"}
	}
	// Refuse literal metadata hosts and IPs before opening a socket; the
	// dialer repeats the check for everything that needs DNS.
	if err := p.checkHost(u.Hostname()); err != nil {
		return nil, err
	}

	// WithTimeout keeps whichever deadline is earlier: the caller's or ours.
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, &BlockedError{Target: rawURL, Reason: "unusable request URL"}
	}
	if header != nil {
		req.Header = header.Clone()
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", version.UserAgent())
	}

	client := &http.Client{
		Transport:     p.transport,
		CheckRedirect: p.redirectPolicy(origin),
	}
	resp, err := client.Do(req)
	if err != nil {
		var blocked *BlockedError
		if errors.As(err, &blocked) {
			return nil, blocked
		}
		return nil, fmt.Errorf("probe %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	out := &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		FinalURL:   resp.Request.URL.String(),
	}
	if method == http.MethodHead {
		return out, nil
	}
	body, truncated, err := readCapped(resp.Body, p.maxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("probe %s: read body: %w", rawURL, err)
	}
	out.Body = body
	out.Truncated = truncated
	return out, nil
}

// redirectPolicy returns the CheckRedirect hook for a request whose initial
// origin is origin. Every hop must be on the allow-list and on the same
// origin; the hook runs before the hop is dialed, and the transport re-runs
// address validation when it is.
func (p *Prober) redirectPolicy(origin string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		next, err := normalizeOrigin(req.URL)
		if err != nil {
			return &BlockedError{Target: req.URL.String(), Reason: "redirect to unsupported scheme"}
		}
		if !p.allowed[next] {
			return &BlockedError{Target: req.URL.String(), Reason: "redirect origin not allowed: " + next}
		}
		if next != origin {
			return &BlockedError{Target: req.URL.String(), Reason: "cross-origin redirect blocked"}
		}
		if !p.followRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) > p.maxRedirects {
			return &BlockedError{Target: req.URL.String(), Reason: "too many redirects"}
		}
		return nil
	}
}

// dialContext resolves the target, validates every candidate address, and
// dials a validated IP literal. Dialing the IP rather than the name closes the
// DNS-rebinding window between the check and the connect: the address that was
// validated is the address connected to.
func (p *Prober) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, &BlockedError{Target: addr, Reason: "malformed dial address"}
	}
	if err := p.checkHost(host); err != nil {
		return nil, err
	}
	addrs, err := p.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &BlockedError{Target: host, Reason: "no addresses resolved"}
	}
	// Refuse the whole target if any candidate is blocked: a name that mixes
	// a public and a private address is a rebinding attempt, not a site.
	for _, a := range addrs {
		if err := p.checkAddr(a); err != nil {
			return nil, err
		}
	}
	var lastErr error
	for _, a := range addrs {
		conn, derr := p.dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, fmt.Errorf("dial %s: %w", host, lastErr)
}

// resolve turns a host into candidate addresses without performing the dial,
// so each one can be policy-checked first. Literal IPs skip DNS entirely.
func (p *Prober) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := parseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	return addrs, nil
}

// readCapped reads at most max+1 bytes so hitting the cap can be detected
// without ever buffering an unbounded body.
func readCapped(r io.Reader, max int64) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > max {
		return body[:max], true, nil
	}
	return body, false, nil
}
