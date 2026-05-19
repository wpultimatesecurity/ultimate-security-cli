package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/config"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/version"
)

type Client struct {
	httpClient *http.Client
	site       *config.SiteConfig
	baseURL    string
	authHeader string
	configDir  string
	debug      bool
	logger     *slog.Logger
}

type ClientOption func(*Client)

func WithDebug(enabled bool) ClientOption {
	return func(c *Client) { c.debug = enabled }
}

func WithLogger(l *slog.Logger) ClientOption {
	return func(c *Client) { c.logger = l }
}

func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) { c.httpClient.Timeout = d }
}

func WithConfigDir(dir string) ClientOption {
	return func(c *Client) { c.configDir = dir }
}

func NewClient(site *config.SiteConfig, apiCfg config.APIConfig, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: apiCfg.Timeout},
		site:       site,
		baseURL:    site.BaseURL(),
		authHeader: site.AuthHeader(),
		logger:     slog.Default(),
	}

	for _, opt := range opts {
		opt(c)
	}

	c.applyTLS()
	return c
}

func (c *Client) applyTLS() {
	tlsCfg := &tls.Config{}
	switch {
	case !c.site.VerifyEnabled():
		tlsCfg.InsecureSkipVerify = true
	case c.site.CACert != "":
		if pool, err := c.loadCACertPool(); err == nil && pool != nil {
			tlsCfg.RootCAs = pool
		}
	}
	c.httpClient.Transport = &http.Transport{TLSClientConfig: tlsCfg}
}

func (c *Client) loadCACertPool() (*x509.CertPool, error) {
	path, err := c.site.ResolveCACertPath(c.configDir)
	if err != nil || path == "" {
		return nil, err
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certs in %s", path)
	}
	return pool, nil
}

func (c *Client) Site() *config.SiteConfig {
	return c.site
}

func (c *Client) BaseURL() string {
	return c.baseURL
}

func (c *Client) Get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	return c.doRequest(ctx, http.MethodGet, path, query, nil)
}

func (c *Client) Post(ctx context.Context, path string, query url.Values, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	return c.doRequest(ctx, http.MethodPost, path, query, bodyReader)
}

func (c *Client) Delete(ctx context.Context, path string, query url.Values) ([]byte, error) {
	return c.doRequest(ctx, http.MethodDelete, path, query, nil)
}

func (c *Client) doRequest(ctx context.Context, method, path string, query url.Values, body io.Reader) ([]byte, error) {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("building URL: %w", err)
	}
	if query != nil && len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "uscli/"+version.Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	start := time.Now()
	resp, err := c.httpClient.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		if c.debug && c.logger != nil {
			c.logger.Debug("request failed",
				"method", method,
				"path", path,
				"error", err,
				"duration", elapsed,
			)
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, TimeoutError("request timed out", err)
		}
		ne := NetworkError("request failed", err)
		var ua x509.UnknownAuthorityError
		var hn x509.HostnameError
		var ci x509.CertificateInvalidError
		var rh tls.RecordHeaderError
		switch {
		case errors.As(err, &ua), errors.As(err, &ci):
			ne.Hint = "TLS certificate not trusted. For a local/self-signed site set ca_cert to your dev CA (mkcert/Traefik/Local root) or set verify_ssl: false."
		case errors.As(err, &hn):
			ne.Hint = "TLS certificate hostname mismatch. The URL must match the cert SAN, or set ca_cert / verify_ssl: false for local dev."
		case errors.As(err, &rh):
			ne.Hint = "Server spoke plain HTTP on an HTTPS request. Use http:// in the site URL for this local site."
		default:
			if strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
				ne.Hint = "Server spoke plain HTTP on an HTTPS request. Use http:// in the site URL for this local site."
			}
		}
		return nil, ne
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NetworkError("reading response body", err)
	}

	if c.debug && c.logger != nil {
		c.logger.Debug("request completed",
			"method", method,
			"path", path,
			"status", resp.StatusCode,
			"duration", elapsed,
		)
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		ae := AuthError(resp.StatusCode, fmt.Sprintf("authentication failed (HTTP %d)", resp.StatusCode))
		if strings.HasPrefix(c.baseURL, "http://") && config.IsLoopbackOrDevHost(c.baseURL) {
			ae.Hint = "WordPress rejects Application Passwords over plain HTTP unless WP_ENVIRONMENT_TYPE=local is set (or the site uses HTTPS). Set it in wp-config.php for local dev."
		}
		return nil, ae
	case resp.StatusCode == http.StatusNotFound && isNamespacePath(path):
		return nil, PluginMissingError("Ultimate Security plugin is not reachable at this site")
	case resp.StatusCode >= 400:
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return nil, APIError(resp.StatusCode, msg)
	}

	return data, nil
}

func isNamespacePath(path string) bool {
	return !strings.Contains(path, "/2fa/") &&
		!strings.Contains(path, "/audit-logs") &&
		!strings.Contains(path, "/security-score")
}

func addQueryParam(params url.Values, key, value string) {
	if value != "" {
		params.Set(key, value)
	}
}

func addQueryInt(params url.Values, key string, value int) {
	if value > 0 {
		params.Set(key, strconv.Itoa(value))
	}
}

func addQueryBool(params url.Values, key string, value bool) {
	params.Set(key, strconv.FormatBool(value))
}
