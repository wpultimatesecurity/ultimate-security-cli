package checksums

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These tests mutate the package-level endpoint bases, so none of them may
// call t.Parallel.

// stubCoreAPI points the core checksum API at a local server for one test.
func stubCoreAPI(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := coreAPIBase
	coreAPIBase = srv.URL + "/"
	t.Cleanup(func() { coreAPIBase = old })
}

// stubPluginZip points the plugin download base at a local server.
func stubPluginZip(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := pluginZipBase
	pluginZipBase = srv.URL + "/plugin/"
	t.Cleanup(func() { pluginZipBase = old })
}

// counting wraps a handler and counts the requests that reach it.
func counting(h http.HandlerFunc) (http.HandlerFunc, *atomic.Int32) {
	var n atomic.Int32
	return func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h(w, r)
	}, &n
}

// coreManifestJSON is a well-formed API document with two entries.
func coreManifestJSON() string {
	return `{"checksums":{"wp-admin/admin.php":"0123456789abcdef0123456789abcdef",` +
		`"index.php":"ffeeddccbbaa99887766554433221100"},"version":"6.4.1"}`
}

func TestFetchCoreParsesManifest(t *testing.T) {
	stubCoreAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("version"); got != "6.4.1" {
			t.Errorf("version param = %q, want 6.4.1", got)
		}
		if got := r.URL.Query().Get("locale"); got != "en_US" {
			t.Errorf("locale param = %q, want en_US", got)
		}
		if r.Header.Get("User-Agent") == "" {
			t.Error("no User-Agent set")
		}
		fmt.Fprint(w, coreManifestJSON())
	})

	c, err := FetchCore(context.Background(), nil, "6.4.1", "", "")
	if err != nil {
		t.Fatalf("FetchCore: %v", err)
	}
	if c.Version != "6.4.1" || c.Locale != "en_US" {
		t.Errorf("got version %q locale %q, want 6.4.1 en_US", c.Version, c.Locale)
	}
	if len(c.Checksums) != 2 {
		t.Fatalf("checksums = %d entries, want 2: %v", len(c.Checksums), c.Checksums)
	}
	if got := c.Checksums["wp-admin/admin.php"]; got != "0123456789abcdef0123456789abcdef" {
		t.Errorf("wp-admin/admin.php = %q", got)
	}
	if time.Since(c.FetchedAt) > time.Minute {
		t.Errorf("FetchedAt = %v, want recent", c.FetchedAt)
	}
}

func TestFetchCoreUnavailable(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"http 404":         {http.StatusNotFound, `{"error":"not found"}`},
		"http 500":         {http.StatusInternalServerError, ``},
		"checksums false":  {http.StatusOK, `{"checksums":false}`},
		"checksums empty":  {http.StatusOK, `{"checksums":{}}`},
		"checksums null":   {http.StatusOK, `{"checksums":null}`},
		"checksums string": {http.StatusOK, `{"checksums":"nope"}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			stubCoreAPI(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			_, err := FetchCore(context.Background(), nil, "9.9.99", "en_US", "")
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestFetchCoreMalformedJSON(t *testing.T) {
	bodies := map[string]string{
		"truncated":     `{"checksums":`,
		"not json":      `<!DOCTYPE html>`,
		"wrong value":   `{"checksums":{"a.php":123}}`,
		"wrong root":    `["checksums"]`,
		"trailing junk": `{"checksums":{"a.php":"0123456789abcdef0123456789abcdef"}} unexpected`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			stubCoreAPI(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, body)
			})
			_, err := FetchCore(context.Background(), nil, "6.4.1", "en_US", "")
			if err == nil {
				t.Fatal("err = nil, want parse error")
			}
			if errors.Is(err, ErrUnavailable) {
				t.Errorf("err = %v, want an operational error rather than ErrUnavailable", err)
			}
		})
	}
}

// TestFetchCoreVersionLocaleSuffix checks that a locale suffix is split off the
// version and sent as the locale parameter.
func TestFetchCoreVersionLocaleSuffix(t *testing.T) {
	cases := []struct {
		version, locale string
		wantVersion     string
		wantLocale      string
	}{
		{"6.5.2-de_DE", "", "6.5.2", "de_DE"},
		{"6.5.2-de_DE", "fr_FR", "6.5.2", "fr_FR"},
		{"6.5.2-RC1", "", "6.5.2-RC1", "en_US"},
		{"6.5.2", "ja", "6.5.2", "ja"},
		{"  6.5.2  ", "  ", "6.5.2", "en_US"},
	}
	for _, tc := range cases {
		var gotVersion, gotLocale string
		stubCoreAPI(t, func(w http.ResponseWriter, r *http.Request) {
			gotVersion = r.URL.Query().Get("version")
			gotLocale = r.URL.Query().Get("locale")
			fmt.Fprint(w, coreManifestJSON())
		})
		c, err := FetchCore(context.Background(), nil, tc.version, tc.locale, "")
		if err != nil {
			t.Fatalf("FetchCore(%q, %q): %v", tc.version, tc.locale, err)
		}
		if gotVersion != tc.wantVersion || gotLocale != tc.wantLocale {
			t.Errorf("FetchCore(%q, %q) requested version=%q locale=%q, want %q %q",
				tc.version, tc.locale, gotVersion, gotLocale, tc.wantVersion, tc.wantLocale)
		}
		if c.Version != tc.wantVersion || c.Locale != tc.wantLocale {
			t.Errorf("FetchCore(%q, %q) = %q/%q, want %q/%q",
				tc.version, tc.locale, c.Version, c.Locale, tc.wantVersion, tc.wantLocale)
		}
	}
}

func TestFetchCoreCacheHit(t *testing.T) {
	handler, n := counting(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, coreManifestJSON())
	})
	stubCoreAPI(t, handler)
	dir := t.TempDir()

	first, err := FetchCore(context.Background(), nil, "6.4.1", "en_US", dir)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	second, err := FetchCore(context.Background(), nil, "6.4.1", "en_US", dir)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got := n.Load(); got != 1 {
		t.Errorf("HTTP requests = %d, want 1", got)
	}
	if len(second.Checksums) != len(first.Checksums) {
		t.Errorf("cached checksums = %d entries, want %d", len(second.Checksums), len(first.Checksums))
	}
	for path, sum := range first.Checksums {
		if second.Checksums[path] != sum {
			t.Errorf("cached %s = %q, want %q", path, second.Checksums[path], sum)
		}
	}
	if second.FetchedAt.IsZero() {
		t.Error("cached FetchedAt is zero")
	}
}

func TestFetchCoreCacheStaleRefetched(t *testing.T) {
	handler, n := counting(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, coreManifestJSON())
	})
	stubCoreAPI(t, handler)
	dir := t.TempDir()

	if _, err := FetchCore(context.Background(), nil, "6.4.1", "en_US", dir); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	cachePath := filepath.Join(dir, "core-6.4.1-en_US.json")
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatalf("age cache: %v", err)
	}
	if _, err := FetchCore(context.Background(), nil, "6.4.1", "en_US", dir); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got := n.Load(); got != 2 {
		t.Errorf("HTTP requests = %d, want 2 after cache expiry", got)
	}
}

// TestCoreCacheWrittenAtomically checks that a fetch leaves exactly one cache
// file behind — no partial or temp files — and that it is valid JSON.
func TestCoreCacheWrittenAtomically(t *testing.T) {
	stubCoreAPI(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, coreManifestJSON())
	})
	dir := t.TempDir()
	if _, err := FetchCore(context.Background(), nil, "6.4.1", "en_US", dir); err != nil {
		t.Fatalf("FetchCore: %v", err)
	}
	assertOnlyCacheFile(t, dir, "core-6.4.1-en_US.json")

	data, err := os.ReadFile(filepath.Join(dir, "core-6.4.1-en_US.json"))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	var cached Core
	if err := json.Unmarshal(data, &cached); err != nil {
		t.Fatalf("cache is not valid JSON: %v", err)
	}
	if len(cached.Checksums) != 2 {
		t.Errorf("cached checksums = %d entries, want 2", len(cached.Checksums))
	}
}

func TestWriteFileAtomicReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writeFileAtomic(path, []byte("new")); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	assertOnlyCacheFile(t, dir, "fixture.json")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
}

// assertOnlyCacheFile fails when dir holds anything besides want, which is how
// a leftover temp file from a non-atomic write would show up.
func assertOnlyCacheFile(t *testing.T, dir, want string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != want {
		t.Errorf("cache dir contains %v, want exactly [%s]", names, want)
	}
}

func TestFetchCoreSanitizesManifest(t *testing.T) {
	digest := "0123456789abcdef0123456789abcdef"
	manifest, err := json.Marshal(map[string]any{"checksums": map[string]string{
		"wp-admin/admin.php": digest,
		"/etc/passwd":        digest,
		"../../evil.php":     digest,
		`..\evil.php`:        digest,
		"a/../../b.php":      digest,
		"wp-config.php":      "not-a-digest",
		"short.php":          "abc",
		"upper.php":          strings.ToUpper(digest),
		"long.php":           strings.Repeat("ab", 20),
		"nul.php":            "abc\x00def",
	}})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	stubCoreAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(manifest) //nolint:errcheck
	})
	c, err := FetchCore(context.Background(), nil, "6.4.1", "en_US", "")
	if err != nil {
		t.Fatalf("FetchCore: %v", err)
	}
	want := map[string]string{
		"wp-admin/admin.php": digest,
		"upper.php":          digest,
		"long.php":           strings.Repeat("ab", 16),
	}
	if len(c.Checksums) != len(want) {
		t.Fatalf("checksums = %v, want %v", c.Checksums, want)
	}
	for path, sum := range want {
		if c.Checksums[path] != sum {
			t.Errorf("%s = %q, want %q", path, c.Checksums[path], sum)
		}
	}
}

func TestFetchCoreRejectsOversizedManifest(t *testing.T) {
	big := make(map[string]string, maxManifestEntries+1)
	for i := 0; i <= maxManifestEntries; i++ {
		big[fmt.Sprintf("file-%06d.php", i)] = "0123456789abcdef0123456789abcdef"
	}
	body, err := json.Marshal(map[string]any{"checksums": big})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	stubCoreAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(body) //nolint:errcheck
	})
	if _, err := FetchCore(context.Background(), nil, "6.4.1", "en_US", ""); err == nil {
		t.Fatal("err = nil, want rejection of an oversized manifest")
	}
}

func TestFetchCoreContextCanceled(t *testing.T) {
	stubCoreAPI(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("server reached despite a canceled context")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := FetchCore(ctx, nil, "6.4.1", "en_US", "")
	if err == nil {
		t.Fatal("err = nil, want context cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestSplitVersionLocale(t *testing.T) {
	cases := []struct {
		version, locale string
		wantVersion     string
		wantLocale      string
	}{
		{"6.5.2-de_DE", "", "6.5.2", "de_DE"},
		{"6.5.2-de_DE", "fr_FR", "6.5.2", "fr_FR"},
		{"6.9-beta2", "", "6.9-beta2", "en_US"},
		{"", "", "", DefaultLocale},
		{"6.5.2", "", "6.5.2", "en_US"},
	}
	for _, tc := range cases {
		gotVersion, gotLocale := splitVersionLocale(tc.version, tc.locale)
		if gotVersion != tc.wantVersion || gotLocale != tc.wantLocale {
			t.Errorf("splitVersionLocale(%q, %q) = %q/%q, want %q/%q",
				tc.version, tc.locale, gotVersion, gotLocale, tc.wantVersion, tc.wantLocale)
		}
	}
}

func TestSanitizeRelPath(t *testing.T) {
	ok := map[string]string{
		"index.php":             "index.php",
		"wp-admin/admin.php":    "wp-admin/admin.php",
		"a/./b.php":             "a/b.php",
		`wp-admin\admin.php`:    "wp-admin/admin.php",
		"./wp-login.php":        "wp-login.php",
		"wp-content//a.php":     "wp-content/a.php",
		"wp-includes/./x/a.php": "wp-includes/x/a.php",
	}
	for in, want := range ok {
		got, valid := sanitizeRelPath(in)
		if !valid || got != want {
			t.Errorf("sanitizeRelPath(%q) = %q, %v; want %q, true", in, got, valid, want)
		}
	}
	bad := []string{
		"",
		"   ",
		"/etc/passwd",
		`\etc\passwd`,
		"../evil.php",
		"a/../../b.php",
		`..\evil.php`,
		"..",
		"./..",
		"a/b/..",
		"C:/windows/system32",
		"file:///etc/passwd",
		"nul\x00.php",
	}
	for _, in := range bad {
		if got, valid := sanitizeRelPath(in); valid {
			t.Errorf("sanitizeRelPath(%q) = %q, true; want rejected", in, got)
		}
	}
}

type zipEntry struct {
	name string
	body string
	mode os.FileMode
}

// buildZip writes an in-memory zip fixture with explicit per-entry modes.
func buildZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		hdr.SetMode(e.mode)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", e.name, err)
		}
		if e.mode.IsDir() {
			continue
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("write zip entry %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// assertZipContains guards the premise of the hostile-entry test: an entry the
// writer silently dropped would make the assertion on the result vacuous.
func assertZipContains(t *testing.T, body []byte, names ...string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("open fixture zip: %v", err)
	}
	have := make(map[string]bool, len(zr.File))
	for _, f := range zr.File {
		have[f.Name] = true
	}
	for _, n := range names {
		if !have[n] {
			t.Errorf("fixture zip is missing entry %q", n)
		}
	}
}

// TestFetchPluginChecksums covers the release zip path: keys are relative to
// the plugin directory, and hostile entries are dropped.
func TestFetchPluginChecksums(t *testing.T) {
	pluginPHP := "<?php\n// plugin\n"
	helperPHP := "<?php\nfunction helper() {}\n"
	zipBody := buildZip(t,
		zipEntry{name: "myplugin/", mode: os.ModeDir | 0o755},
		zipEntry{name: "myplugin/myplugin.php", body: pluginPHP, mode: 0o644},
		zipEntry{name: "myplugin/includes/", mode: os.ModeDir | 0o755},
		zipEntry{name: "myplugin/includes/helper.php", body: helperPHP, mode: 0o644},
		zipEntry{name: "myplugin/link.php", body: "/etc/passwd", mode: os.ModeSymlink | 0o777},
		zipEntry{name: "myplugin/../evil.php", body: "evil", mode: 0o644},
		zipEntry{name: "/etc/passwd", body: "root", mode: 0o644},
		zipEntry{name: "other/root.php", body: "other", mode: 0o644},
	)
	stubPluginZip(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/plugin/myplugin.1.2.3.zip" {
			t.Errorf("path = %q, want /plugin/myplugin.1.2.3.zip", r.URL.Path)
		}
		if r.Header.Get("User-Agent") == "" {
			t.Error("no User-Agent set")
		}
		w.Write(zipBody) //nolint:errcheck
	})
	// The fixture must really contain the hostile entries, or their absence
	// from the result would prove nothing.
	assertZipContains(t, zipBody, "myplugin/../evil.php", "/etc/passwd", "myplugin/link.php", "other/root.php")

	sums, err := FetchPluginChecksums(context.Background(), nil, "myplugin", "1.2.3", "")
	if err != nil {
		t.Fatalf("FetchPluginChecksums: %v", err)
	}
	want := map[string]string{
		"myplugin.php":        md5Hex(pluginPHP),
		"includes/helper.php": md5Hex(helperPHP),
	}
	if len(sums) != len(want) {
		t.Fatalf("checksums = %v, want %v", sums, want)
	}
	for path, sum := range want {
		if sums[path] != sum {
			t.Errorf("%s = %q, want %q", path, sums[path], sum)
		}
	}
	for _, bad := range []string{"../evil.php", "evil.php", "/etc/passwd", "other/root.php", "link.php"} {
		if _, ok := sums[bad]; ok {
			t.Errorf("hostile or foreign entry %q present in checksums", bad)
		}
	}
}

func TestFetchPluginChecksumsUnavailable(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError} {
		stubPluginZip(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		})
		_, err := FetchPluginChecksums(context.Background(), nil, "custom-plugin", "1.0.0", "")
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("HTTP %d: err = %v, want ErrUnavailable", status, err)
		}
	}
}

func TestFetchPluginChecksumsInvalidIdentity(t *testing.T) {
	stubPluginZip(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("request made for an invalid identity: %s", r.URL)
	})
	cases := [][2]string{
		{"", "1.0.0"},
		{"myplugin", ""},
		{"../evil", "1.0.0"},
		{"a/b", "1.0.0"},
		{"myplugin", "1.0/0"},
		{"myplugin", ".."},
		{"myplugin", `1.0\0`},
	}
	for _, tc := range cases {
		_, err := FetchPluginChecksums(context.Background(), nil, tc[0], tc[1], "")
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("FetchPluginChecksums(%q, %q) err = %v, want ErrUnavailable", tc[0], tc[1], err)
		}
	}
}

func TestFetchPluginChecksumsCacheHit(t *testing.T) {
	zipBody := buildZip(t, zipEntry{name: "myplugin/myplugin.php", body: "<?php\n", mode: 0o644})
	handler, n := counting(func(w http.ResponseWriter, r *http.Request) {
		w.Write(zipBody) //nolint:errcheck
	})
	stubPluginZip(t, handler)
	dir := t.TempDir()

	first, err := FetchPluginChecksums(context.Background(), nil, "myplugin", "1.2.3", dir)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	second, err := FetchPluginChecksums(context.Background(), nil, "myplugin", "1.2.3", dir)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got := n.Load(); got != 1 {
		t.Errorf("HTTP requests = %d, want 1", got)
	}
	if len(second) != len(first) || second["myplugin.php"] != first["myplugin.php"] {
		t.Errorf("cached map = %v, want %v", second, first)
	}
	// The zip itself must not be kept, only its checksum map.
	assertOnlyCacheFile(t, dir, "plugin-myplugin-1.2.3.json")
}

func TestFetchPluginChecksumsRejectsOversizedZip(t *testing.T) {
	stubPluginZip(t, func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 1<<20)
		remaining := int64(maxPluginZipBytes + 1)
		for remaining > 0 {
			n := int64(len(chunk))
			if n > remaining {
				n = remaining
			}
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
			remaining -= n
		}
	})
	_, err := FetchPluginChecksums(context.Background(), nil, "huge-plugin", "1.0.0", "")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable for a zip over the cap", err)
	}
}

func TestFetchPluginChecksumsContextCanceled(t *testing.T) {
	stubPluginZip(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("server reached despite a canceled context")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := FetchPluginChecksums(ctx, nil, "myplugin", "1.2.3", "")
	if err == nil {
		t.Fatal("err = nil, want context cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestCacheKeyIsFilesystemSafe(t *testing.T) {
	got := cacheKey("../weird slug/1.0", "en_US")
	if got == "" || strings.ContainsAny(got, `/\`) || strings.ContainsRune(got, '\x00') {
		t.Errorf("cacheKey = %q, want a safe single filename component", got)
	}
	if filepath.Base(got) != got {
		t.Errorf("cacheKey = %q, want a single path element", got)
	}
	long := cacheKey(strings.Repeat("a", 500), "en_US")
	if len(long) > maxCacheKeyLen+9 {
		t.Errorf("cacheKey length = %d, want bounded", len(long))
	}
	if long == cacheKey(strings.Repeat("a", 499)+"b", "en_US") {
		t.Error("distinct long inputs collided")
	}
}
