package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// mustOrigin returns the normalized origin of rawURL, failing the test if the
// URL is unusable. Tests use it to build a policy that admits the target
// origin, so a block can only come from the rule under test.
func mustOrigin(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	origin, err := normalizeOrigin(u)
	if err != nil {
		t.Fatalf("normalizeOrigin(%q): %v", rawURL, err)
	}
	return origin
}

// assertBlocked requires err to be a policy refusal.
func assertBlocked(t *testing.T, err error) *BlockedError {
	t.Helper()
	if err == nil {
		t.Fatal("expected a BlockedError, got nil")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("error %v does not wrap ErrBlocked", err)
	}
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("error %v is not a *BlockedError", err)
	}
	return be
}

func TestOriginAllowed(t *testing.T) {
	t.Parallel()
	p := New(Policy{AllowedOrigins: []string{
		"https://example.com",
		"http://allowed.example:8080",
		"https://[2001:db8::1]:8443",
	}})

	tests := []struct {
		name   string
		rawURL string
		want   bool
	}{
		{"exact origin", "https://example.com/wp-json/", true},
		{"uppercase host", "https://EXAMPLE.com/x", true},
		{"default https port elided", "https://Example.COM:443/x", true},
		{"explicit non-default port", "http://allowed.example:8080/x", true},
		{"case-insensitive allowed entry", "http://Allowed.Example:8080/", true},
		{"ipv6 origin", "https://[2001:db8::1]:8443/", true},
		{"scheme mismatch", "http://example.com/", false},
		{"port mismatch", "https://example.com:8443/", false},
		{"unlisted origin", "https://evil.example/", false},
		{"subdomain is not the origin", "https://a.example.com/", false},
		{"non-http scheme", "ftp://example.com/", false},
		{"file scheme", "file:///etc/passwd", false},
		{"relative URL", "/wp-json/", false},
		{"empty URL", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := p.OriginAllowed(tc.rawURL); got != tc.want {
				t.Fatalf("OriginAllowed(%q) = %v, want %v", tc.rawURL, got, tc.want)
			}
		})
	}
}

func TestEmptyPolicyDeniesEverything(t *testing.T) {
	t.Parallel()
	for _, origins := range [][]string{nil, {}} {
		p := New(Policy{AllowedOrigins: origins, AllowPrivate: true})
		if p.OriginAllowed("http://127.0.0.1/") {
			t.Fatal("empty allow-list admitted an origin")
		}
		_, err := p.Get(context.Background(), "http://127.0.0.1/", nil)
		assertBlocked(t, err)
	}
}

func TestMalformedAllowedOriginsAreIgnored(t *testing.T) {
	t.Parallel()
	p := New(Policy{AllowedOrigins: []string{
		"example.com", // no scheme
		"https://",    // no host
		"https://ok.example",
	}})
	if !p.OriginAllowed("https://ok.example/") {
		t.Fatal("valid origin was not admitted")
	}
	if p.OriginAllowed("https://example.com/") {
		t.Fatal("schemeless entry was admitted")
	}
}

func TestOriginPolicyBlocksRequests(t *testing.T) {
	t.Parallel()
	p := New(Policy{AllowedOrigins: []string{"https://example.com"}})

	tests := []struct {
		name   string
		rawURL string
	}{
		{"unlisted origin", "http://example.com/"},
		{"other origin", "https://evil.example/"},
		{"non-http scheme", "ftp://example.com/"},
		{"file scheme", "file:///etc/passwd"},
		{"relative URL", "/wp-json/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := p.Get(context.Background(), tc.rawURL, nil)
			assertBlocked(t, err)
		})
	}
}

// TestAlwaysBlockedAddresses covers destinations refused even for local
// development scans.
func TestAlwaysBlockedAddresses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		rawURL string
	}{
		{"ipv4 metadata", "http://169.254.169.254/latest/meta-data/"},
		{"ipv4 link-local", "http://169.254.1.1/"},
		{"alibaba metadata", "http://100.100.100.200/"},
		{"aws ipv6 metadata", "http://[fd00:ec2::254]/"},
		{"ipv6 link-local", "http://[fe80::1]/"},
		{"ipv6 link-local upper range", "http://[febf::1]/"},
		{"unspecified ipv4", "http://0.0.0.0/"},
		{"unspecified network", "http://0.1.2.3/"},
		{"unspecified ipv6", "http://[::]/"},
		{"ipv4 multicast", "http://224.0.0.1/"},
		{"ipv6 multicast", "http://[ff02::1]/"},
		{"ipv4 broadcast", "http://255.255.255.255/"},
		{"mapped metadata", "http://[::ffff:169.254.169.254]/"},
		{"mapped alibaba metadata", "http://[::ffff:100.100.100.200]/"},
		{"mapped link-local", "http://[::ffff:169.254.1.1]/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// AllowedOrigins admits the target so the block can only come
			// from address policy.
			p := New(Policy{
				AllowedOrigins: []string{mustOrigin(t, tc.rawURL)},
				AllowPrivate:   true,
			})
			_, err := p.Get(context.Background(), tc.rawURL, nil)
			assertBlocked(t, err)
		})
	}
}

// TestPrivateAddressesBlockedByDefault covers destinations refused unless the
// operator opts into private networks.
func TestPrivateAddressesBlockedByDefault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		rawURL string
	}{
		{"loopback", "http://127.0.0.1/"},
		{"loopback other", "http://127.1.2.3/"},
		{"rfc1918 10/8", "http://10.0.0.1/"},
		{"rfc1918 172.16/12", "http://172.16.5.5/"},
		{"rfc1918 192.168/16", "http://192.168.1.1/"},
		{"cgnat", "http://100.64.0.1/"},
		{"ipv6 loopback", "http://[::1]/"},
		{"ipv6 ula", "http://[fc00::1]/"},
		{"ipv6 ula fd", "http://[fd12:3456::1]/"},
		{"mapped loopback", "http://[::ffff:127.0.0.1]/"},
		{"mapped rfc1918", "http://[::ffff:10.0.0.1]/"},
		{"mapped cgnat", "http://[::ffff:100.64.0.1]/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := New(Policy{AllowedOrigins: []string{mustOrigin(t, tc.rawURL)}})
			_, err := p.Get(context.Background(), tc.rawURL, nil)
			assertBlocked(t, err)
		})
	}
}

func TestMetadataHostnamesBlocked(t *testing.T) {
	t.Parallel()
	tests := []string{
		"http://metadata.google.internal/",
		"http://METADATA.GOOG/",
		"http://metadata.google.internal.:80/",
	}
	for _, rawURL := range tests {
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			p := New(Policy{
				AllowedOrigins: []string{mustOrigin(t, rawURL)},
				AllowPrivate:   true,
			})
			_, err := p.Get(context.Background(), rawURL, nil)
			assertBlocked(t, err)
		})
	}
}

// TestLoopbackPolicy proves the AllowPrivate switch against a live local
// server, using the localhost name (not a literal) so resolution is exercised.
func TestLoopbackPolicy(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-UA", r.Header.Get("User-Agent"))
		w.Header().Set("X-Seen-Custom", r.Header.Get("X-Custom"))
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", srv.URL, err)
	}
	base := "http://localhost:" + u.Port()

	t.Run("blocked without AllowPrivate", func(t *testing.T) {
		p := New(Policy{AllowedOrigins: []string{base}})
		_, err := p.Get(context.Background(), base+"/ping", nil)
		assertBlocked(t, err)
	})

	t.Run("allowed with AllowPrivate", func(t *testing.T) {
		p := New(Policy{AllowedOrigins: []string{base}, AllowPrivate: true})
		header := http.Header{"X-Custom": {"abc"}}
		resp, err := p.Get(context.Background(), base+"/ping", header)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
		}
		if got := string(resp.Body); got != "ok" {
			t.Fatalf("Body = %q, want %q", got, "ok")
		}
		if resp.Truncated {
			t.Fatal("Truncated = true, want false")
		}
		if resp.FinalURL != base+"/ping" {
			t.Fatalf("FinalURL = %q, want %q", resp.FinalURL, base+"/ping")
		}
		if ua := resp.Header.Get("X-Seen-UA"); !strings.HasPrefix(ua, "wpus") {
			t.Fatalf("User-Agent = %q, want wpus prefix", ua)
		}
		if got := resp.Header.Get("X-Seen-Custom"); got != "abc" {
			t.Fatalf("custom header not forwarded: %q", got)
		}
	})
}

func TestRedirects(t *testing.T) {
	t.Parallel()
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "final")
	}))
	t.Cleanup(final.Close)
	crossOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/end", http.StatusFound)
	}))
	t.Cleanup(crossOrigin.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/end", http.StatusFound)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "same-origin")
	})
	same := httptest.NewServer(mux)
	t.Cleanup(same.Close)

	t.Run("cross-origin blocked with redirects off", func(t *testing.T) {
		// Both origins are allowed, so the block must be the cross-origin
		// rule, not a missing allow-list entry.
		p := New(Policy{
			AllowedOrigins: []string{crossOrigin.URL, final.URL},
			AllowPrivate:   true,
		})
		_, err := p.Get(context.Background(), crossOrigin.URL, nil)
		be := assertBlocked(t, err)
		if !strings.Contains(be.Reason, "cross-origin") {
			t.Fatalf("Reason = %q, want cross-origin refusal", be.Reason)
		}
	})

	t.Run("cross-origin blocked with redirects on", func(t *testing.T) {
		p := New(Policy{
			AllowedOrigins:            []string{crossOrigin.URL, final.URL},
			AllowPrivate:              true,
			FollowSameOriginRedirects: true,
		})
		_, err := p.Get(context.Background(), crossOrigin.URL, nil)
		be := assertBlocked(t, err)
		if !strings.Contains(be.Reason, "cross-origin") {
			t.Fatalf("Reason = %q, want cross-origin refusal", be.Reason)
		}
	})

	t.Run("same-origin redirect followed when on", func(t *testing.T) {
		p := New(Policy{
			AllowedOrigins:            []string{same.URL},
			AllowPrivate:              true,
			FollowSameOriginRedirects: true,
		})
		resp, err := p.Get(context.Background(), same.URL+"/start", nil)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
		}
		if got := string(resp.Body); got != "same-origin" {
			t.Fatalf("Body = %q, want %q", got, "same-origin")
		}
		if resp.FinalURL != same.URL+"/end" {
			t.Fatalf("FinalURL = %q, want %q", resp.FinalURL, same.URL+"/end")
		}
	})

	t.Run("same-origin redirect not followed when off", func(t *testing.T) {
		p := New(Policy{AllowedOrigins: []string{same.URL}, AllowPrivate: true})
		resp, err := p.Get(context.Background(), same.URL+"/start", nil)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("StatusCode = %d, want 302", resp.StatusCode)
		}
		if resp.FinalURL != same.URL+"/start" {
			t.Fatalf("FinalURL = %q, want %q", resp.FinalURL, same.URL+"/start")
		}
	})
}

func TestRedirectLoopBlocked(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	p := New(Policy{
		AllowedOrigins:            []string{srv.URL},
		AllowPrivate:              true,
		FollowSameOriginRedirects: true,
		MaxRedirects:              2,
	})
	_, err := p.Get(context.Background(), srv.URL+"/loop", nil)
	be := assertBlocked(t, err)
	if !strings.Contains(be.Reason, "redirect") {
		t.Fatalf("Reason = %q, want redirect refusal", be.Reason)
	}
}

func TestBodyCap(t *testing.T) {
	t.Parallel()
	payload := bytes.Repeat([]byte("a"), 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)

	tests := []struct {
		name      string
		maxBytes  int64
		wantLen   int
		wantTrunc bool
	}{
		{"default cap", 0, len(payload), false},
		{"under cap", 8192, len(payload), false},
		{"exactly cap", 4096, len(payload), false},
		{"over cap", 1024, 1024, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := New(Policy{
				AllowedOrigins: []string{srv.URL},
				AllowPrivate:   true,
				MaxBodyBytes:   tc.maxBytes,
			})
			resp, err := p.Get(context.Background(), srv.URL, nil)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if len(resp.Body) != tc.wantLen {
				t.Fatalf("len(Body) = %d, want %d", len(resp.Body), tc.wantLen)
			}
			if resp.Truncated != tc.wantTrunc {
				t.Fatalf("Truncated = %v, want %v", resp.Truncated, tc.wantTrunc)
			}
		})
	}
}

func TestHeadDoesNotReadBody(t *testing.T) {
	t.Parallel()
	payload := bytes.Repeat([]byte("b"), 2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)

	p := New(Policy{AllowedOrigins: []string{srv.URL}, AllowPrivate: true})
	resp, err := p.Head(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if len(resp.Body) != 0 {
		t.Fatalf("len(Body) = %d, want 0", len(resp.Body))
	}
	if resp.Truncated {
		t.Fatal("Truncated = true, want false")
	}
}

func TestRequestTimeout(t *testing.T) {
	t.Parallel()
	// The handler parks until the request context is cancelled, so a client
	// that enforces its deadline returns immediately while the server can
	// still shut down promptly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)

	tests := []struct {
		name    string
		timeout time.Duration
		useCtx  bool
	}{
		{"policy timeout", 50 * time.Millisecond, false},
		{"caller context wins", 5 * time.Second, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := New(Policy{
				AllowedOrigins: []string{srv.URL},
				AllowPrivate:   true,
				Timeout:        tc.timeout,
			})
			ctx := context.Background()
			if tc.useCtx {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			}
			_, err := p.Get(ctx, srv.URL, nil)
			if err == nil {
				t.Fatal("expected a timeout error, got nil")
			}
			if errors.Is(err, ErrBlocked) {
				t.Fatalf("timeout reported as a policy block: %v", err)
			}
		})
	}
}

func TestReadCapped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     string
		max       int64
		wantBody  string
		wantTrunc bool
	}{
		{"under", "abc", 10, "abc", false},
		{"exact", "abcd", 4, "abcd", false},
		{"over", "abcde", 4, "abcd", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body, truncated, err := readCapped(strings.NewReader(tc.input), tc.max)
			if err != nil {
				t.Fatalf("readCapped: %v", err)
			}
			if string(body) != tc.wantBody {
				t.Fatalf("body = %q, want %q", body, tc.wantBody)
			}
			if truncated != tc.wantTrunc {
				t.Fatalf("truncated = %v, want %v", truncated, tc.wantTrunc)
			}
		})
	}
}
