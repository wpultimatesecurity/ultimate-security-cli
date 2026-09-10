// Package checksums obtains authoritative file-integrity data for a WordPress
// installation from WordPress.org: the official core checksum manifest for a
// version and locale, and per-file md5 hashes derived from the official plugin
// release zip.
//
// Everything here is static. Nothing is executed, and nothing is ever written
// into the audited site — caches live in the tool's own cache directory and
// downloads in the system temp directory. The WordPress.org responses are
// remote input, so every parsed document is bounded and sanitized before it
// reaches a caller: entry counts, digest shape, and relative paths are all
// validated, and a manifest that tries to reference a file outside the
// WordPress root is dropped rather than trusted.
package checksums

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	wpver "github.com/wpultimatesecurity/ultimate-security-cli/internal/version"
)

// ErrUnavailable reports that no authoritative checksum data exists for the
// requested version, locale, or plugin. Callers treat it as "cannot verify"
// rather than as a scan failure: custom and premium plugins legitimately have
// no WordPress.org checksums, and an unreleased core version has no manifest.
var ErrUnavailable = errors.New("checksums: unavailable")

// DefaultLocale is the locale used when a site's locale is unknown.
const DefaultLocale = "en_US"

const (
	// coreAPITimeout bounds a core manifest request.
	coreAPITimeout = 30 * time.Second
	// pluginHTTPTimeout bounds a plugin zip download, which can be tens of
	// megabytes.
	pluginHTTPTimeout = 5 * time.Minute
	// maxCoreManifestBytes caps the core API response body; the real
	// manifest is under a megabyte.
	maxCoreManifestBytes = 32 << 20
	// maxManifestEntries rejects absurd manifests from the remote feed.
	maxManifestEntries = 200_000
	// md5HexLen is the exact length of a lowercase md5 hex digest.
	md5HexLen = 32
	// coreCacheTTL is how long a cached core manifest stays usable. A
	// version's published checksums never change, but the cache is re-read
	// so a locale's manifest that appeared later can still be picked up.
	coreCacheTTL = 24 * time.Hour
	// maxCacheKeyLen bounds a cache filename component.
	maxCacheKeyLen = 100
)

// coreAPIBase and pluginZipBase are the official WordPress.org endpoints.
// They are variables only so tests can point them at a local server; the
// exported API does not expose them.
var (
	coreAPIBase   = "https://api.wordpress.org/core/checksums/1.0/"
	pluginZipBase = "https://downloads.wordpress.org/plugin/"
)

// Core is the WordPress.org core checksum manifest for one version and locale.
type Core struct {
	// Version is the base WordPress version the manifest describes, without
	// any locale suffix.
	Version string
	// Locale is the locale the manifest was requested for.
	Locale string
	// Checksums maps a path relative to the WordPress root to a lowercase
	// md5 hex digest.
	Checksums map[string]string
	// FetchedAt is when the manifest was retrieved, or when its cache file
	// was last written.
	FetchedAt time.Time
}

// coreResponse is the core checksums API document. The API answers an unknown
// version or locale with HTTP 200 and {"checksums": false}, so Checksums is
// decoded leniently and judged empty instead of failing the decode.
type coreResponse struct {
	Checksums checksumObject `json:"checksums"`
}

// checksumObject decodes the API's "checksums" member, which is an object for
// a known version and locale and literally false for an unknown one.
type checksumObject map[string]string

// UnmarshalJSON accepts an object and treats every other JSON value as an
// absent manifest.
func (c *checksumObject) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' {
		*c = nil
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*c = m
	return nil
}

// FetchCore fetches the official core checksum manifest for version and
// locale, reusing a cached copy in cacheDir when it is less than 24h old.
// cacheDir may be "" to disable caching.
//
// A version may carry a WordPress locale suffix, e.g. "6.5.2-de_DE": the
// suffix (recognized only when it contains "_", so qualifiers such as "-RC1"
// stay part of the version) supplies the locale and the base version is
// requested. An empty locale falls back to DefaultLocale.
//
// A version or locale WordPress.org does not know, an HTTP failure, and an
// empty manifest all return an error wrapping ErrUnavailable.
func FetchCore(ctx context.Context, client *http.Client, version, locale, cacheDir string) (*Core, error) {
	base, loc := splitVersionLocale(version, locale)
	if base == "" {
		return nil, fmt.Errorf("%w: empty core version", ErrUnavailable)
	}
	var cachePath string
	if cacheDir != "" {
		cachePath = filepath.Join(cacheDir, "core-"+cacheKey(base, loc)+".json")
		if c, err := readCachedCore(cachePath); err == nil {
			return c, nil
		}
	}
	if client == nil {
		client = &http.Client{Timeout: coreAPITimeout}
	}
	c, err := fetchCoreManifest(ctx, client, base, loc)
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		writeCachedCore(cachePath, c)
	}
	return c, nil
}

// splitVersionLocale separates a locale suffix from a version
// ("6.5.2-de_DE" -> "6.5.2", "de_DE"). Only a suffix containing "_" is
// treated as a locale, so release qualifiers such as "-RC1" stay part of the
// version. An empty locale falls back to DefaultLocale.
func splitVersionLocale(version, locale string) (string, string) {
	version = strings.TrimSpace(version)
	if i := strings.IndexByte(version, '-'); i > 0 {
		if suffix := version[i+1:]; strings.ContainsRune(suffix, '_') {
			version = version[:i]
			if locale == "" {
				locale = suffix
			}
		}
	}
	locale = strings.TrimSpace(locale)
	if locale == "" {
		locale = DefaultLocale
	}
	return version, locale
}

// fetchCoreManifest performs the request and validation for FetchCore.
func fetchCoreManifest(ctx context.Context, client *http.Client, version, locale string) (*Core, error) {
	reqURL := coreAPIBase + "?version=" + url.QueryEscape(version) + "&locale=" + url.QueryEscape(locale)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: core request: %w", ErrUnavailable, err)
	}
	req.Header.Set("User-Agent", userAgent())
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: core request: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: core API returned HTTP %d for version %s locale %s", ErrUnavailable, resp.StatusCode, version, locale)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxCoreManifestBytes))
	var doc coreResponse
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("checksums: core manifest for version %s locale %s: %w", version, locale, err)
	}
	// Reject trailing data: only a single JSON document is a manifest.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("checksums: core manifest for version %s locale %s: trailing data", version, locale)
	}
	sums, err := sanitizeManifest(doc.Checksums)
	if err != nil {
		return nil, err
	}
	if len(sums) == 0 {
		return nil, fmt.Errorf("%w: no core checksums for version %s locale %s", ErrUnavailable, version, locale)
	}
	return &Core{
		Version:   version,
		Locale:    locale,
		Checksums: sums,
		FetchedAt: time.Now().UTC(),
	}, nil
}

// sanitizeManifest validates a remote path-to-digest map, dropping entries
// that could name a file outside the WordPress root or that do not carry an
// md5 digest, and refusing absurdly large manifests.
func sanitizeManifest(raw map[string]string) (map[string]string, error) {
	if len(raw) > maxManifestEntries {
		return nil, fmt.Errorf("checksums: manifest has %d entries (limit %d)", len(raw), maxManifestEntries)
	}
	out := make(map[string]string, len(raw))
	for p, sum := range raw {
		rel, ok := sanitizeRelPath(p)
		if !ok {
			continue
		}
		digest, ok := normalizeMD5(sum)
		if !ok {
			continue
		}
		out[rel] = digest
	}
	return out, nil
}

// sanitizeRelPath returns p as a clean path relative to a WordPress root, or
// ok=false when p is absolute, contains a ".." segment, or is otherwise not a
// plain relative path. Remote manifests are input: a hostile entry must never
// be able to name /etc/passwd or escape the root.
func sanitizeRelPath(p string) (string, bool) {
	p = strings.TrimSpace(p)
	if p == "" || strings.ContainsRune(p, '\x00') {
		return "", false
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if strings.HasPrefix(p, "/") || strings.ContainsRune(p, ':') {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", false
		}
	}
	clean := path.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", false
	}
	return clean, true
}

// normalizeMD5 returns a lowercase 32-character md5 hex digest, truncating a
// longer value to the digest width first. A value that is not hexadecimal is
// rejected, so a feed cannot smuggle arbitrary text into a checksum.
func normalizeMD5(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > md5HexLen {
		s = s[:md5HexLen]
	}
	if len(s) != md5HexLen {
		return "", false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", false
	}
	return s, true
}

// readCachedCore returns a cached manifest that is still fresh, and its
// validation is re-applied on read so a tampered cache cannot inject paths.
func readCachedCore(path string) (*Core, error) {
	info, err := os.Stat(path)
	if err != nil || time.Since(info.ModTime()) > coreCacheTTL {
		return nil, errors.New("checksums: no fresh core cache")
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is built from our own cache dir
	if err != nil {
		return nil, err
	}
	var c Core
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	sums, err := sanitizeManifest(c.Checksums)
	if err != nil || len(sums) == 0 {
		return nil, errors.New("checksums: unusable core cache")
	}
	c.Checksums = sums
	if c.FetchedAt.IsZero() {
		c.FetchedAt = info.ModTime()
	}
	return &c, nil
}

// writeCachedCore stores the manifest; a cache failure never fails a fetch,
// because the manifest itself is already in hand.
func writeCachedCore(path string, c *Core) {
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	_ = writeFileAtomic(path, data)
}

// writeFileAtomic writes data to path through a temp file in the same
// directory plus a rename, so a reader never observes a partial file.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()     //nolint:errcheck
		os.Remove(name) //nolint:errcheck
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name) //nolint:errcheck
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name) //nolint:errcheck
		return err
	}
	return nil
}

// cacheKey builds a filesystem-safe cache filename component from remote
// identifiers such as versions, locales, and plugin slugs.
func cacheKey(parts ...string) string {
	joined := strings.Join(parts, "-")
	var b strings.Builder
	b.Grow(len(joined))
	for _, r := range joined {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := b.String()
	if len(name) > maxCacheKeyLen {
		sum := sha256.Sum256([]byte(joined))
		name = name[:maxCacheKeyLen] + "-" + hex.EncodeToString(sum[:4])
	}
	return name
}

// userAgent identifies wpus to WordPress.org.
func userAgent() string { return wpver.UserAgent() }
