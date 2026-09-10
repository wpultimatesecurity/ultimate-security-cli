package checksums

import (
	"archive/zip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// maxPluginZipBytes caps a plugin release zip. WordPress.org refuses uploads
// far below this; the cap exists so a tampered or hostile response cannot fill
// the disk.
const maxPluginZipBytes = 64 << 20

// FetchPluginChecksums returns the md5 of every regular file in the official
// WordPress.org release zip for slug@version, keyed by a path relative to the
// plugin directory. The zip's single top-level "<slug>/" directory is
// stripped.
//
// Released zips are immutable, so the computed map is cached under cacheDir
// keyed by slug and version with no TTL. cacheDir may be "" to disable
// caching.
//
// A plugin that is not on WordPress.org (custom or premium), a failed
// download, and a zip larger than 64 MiB all return an error wrapping
// ErrUnavailable: such a plugin cannot be verified rather than being a scan
// error. The zip is streamed to a temporary file outside the audited site,
// hashed, and deleted — it is never written into the site, and file contents
// are never retained.
func FetchPluginChecksums(ctx context.Context, client *http.Client, slug, version, cacheDir string) (map[string]string, error) {
	slug = strings.TrimSpace(slug)
	version = strings.TrimSpace(version)
	if !validRemoteComponent(slug) || !validRemoteComponent(version) {
		return nil, fmt.Errorf("%w: invalid plugin identity %q@%q", ErrUnavailable, slug, version)
	}
	var cachePath string
	if cacheDir != "" {
		cachePath = filepath.Join(cacheDir, "plugin-"+cacheKey(slug, version)+".json")
		if sums, err := readCachedPluginChecksums(cachePath); err == nil {
			return sums, nil
		}
	}
	if client == nil {
		client = &http.Client{Timeout: pluginHTTPTimeout}
	}
	sums, err := downloadPluginChecksums(ctx, client, slug, version)
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		writeCachedPluginChecksums(cachePath, sums)
	}
	return sums, nil
}

// validRemoteComponent reports whether s can appear as a single path segment
// in a WordPress.org URL. Slugs and versions with separators or dot segments
// are refused so a crafted identity cannot escape the download directory.
func validRemoteComponent(s string) bool {
	if s == "" || s == "." || s == ".." || strings.Contains(s, "..") {
		return false
	}
	return !strings.ContainsAny(s, `/\:`) && !strings.ContainsRune(s, '\x00')
}

// downloadPluginChecksums downloads and hashes the release zip. The download
// is capped while streaming to a temp file, then read with archive/zip.
func downloadPluginChecksums(ctx context.Context, client *http.Client, slug, version string) (map[string]string, error) {
	zipURL := pluginZipBase + url.PathEscape(slug) + "." + url.PathEscape(version) + ".zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zipURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: plugin request: %w", ErrUnavailable, err)
	}
	req.Header.Set("User-Agent", userAgent())
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: plugin download: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: plugin %s@%s: HTTP %d", ErrUnavailable, slug, version, resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "wpus-plugin-*.zip")
	if err != nil {
		return nil, fmt.Errorf("%w: temp file: %w", ErrUnavailable, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck // best-effort cleanup outside the site
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxPluginZipBytes+1))
	if err != nil {
		tmp.Close() //nolint:errcheck
		return nil, fmt.Errorf("%w: plugin download: %w", ErrUnavailable, err)
	}
	if n > maxPluginZipBytes {
		tmp.Close() //nolint:errcheck
		return nil, fmt.Errorf("%w: plugin %s@%s zip exceeds %d bytes", ErrUnavailable, slug, version, maxPluginZipBytes)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("%w: plugin zip: %w", ErrUnavailable, err)
	}
	sums, err := zipChecksums(tmpName)
	if err != nil {
		return nil, fmt.Errorf("%w: plugin %s@%s zip: %w", ErrUnavailable, slug, version, err)
	}
	if len(sums) == 0 {
		return nil, fmt.Errorf("%w: plugin %s@%s zip contains no files", ErrUnavailable, slug, version)
	}
	return sums, nil
}

// zipChecksums hashes every regular file in the zip at path, keyed by its path
// relative to the zip's single top-level directory. Directory entries,
// symlinks, absolute paths, and paths containing ".." are skipped: the zip is
// remote input, and a hostile entry must never appear to live outside the
// plugin directory.
func zipChecksums(path string) (map[string]string, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close() //nolint:errcheck
	top := topLevelDir(zr.File)
	sums := make(map[string]string, len(zr.File))
	for _, f := range zr.File {
		if !f.Mode().IsRegular() {
			continue
		}
		name := strings.ReplaceAll(f.Name, `\`, "/")
		if top != "" {
			if !strings.HasPrefix(name, top+"/") {
				continue
			}
			name = name[len(top)+1:]
		}
		rel, ok := sanitizeRelPath(name)
		if !ok {
			continue
		}
		digest, err := md5ZipEntry(f)
		if err != nil {
			return nil, err
		}
		sums[rel] = digest
	}
	return sums, nil
}

// topLevelDir returns the single directory WordPress.org wraps a plugin's
// files in ("akismet/" -> "akismet"), or "" when no entry has one.
func topLevelDir(files []*zip.File) string {
	for _, f := range files {
		name := strings.ReplaceAll(f.Name, `\`, "/")
		if i := strings.IndexByte(name, '/'); i > 0 {
			return name[:i]
		}
	}
	return ""
}

// md5ZipEntry streams one entry through md5 without buffering its contents.
func md5ZipEntry(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close() //nolint:errcheck
	h := md5.New()
	if _, err := io.Copy(h, rc); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readCachedPluginChecksums returns a cached digest map, re-validating it so a
// tampered cache cannot inject paths or non-md5 values.
func readCachedPluginChecksums(path string) (map[string]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is built from our own cache dir
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	sums, err := sanitizeManifest(raw)
	if err != nil || len(sums) == 0 {
		return nil, errors.New("checksums: unusable plugin cache")
	}
	return sums, nil
}

// writeCachedPluginChecksums stores the digest map; a cache failure never
// fails a fetch, because the map itself is already in hand.
func writeCachedPluginChecksums(path string, sums map[string]string) {
	data, err := json.Marshal(sums)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	_ = writeFileAtomic(path, data)
}
