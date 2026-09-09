// Package releases talks to the official WordPress.org release API to answer
// "is this core version current?". Data is tiny, unauthenticated, and cached
// on disk for a day. All failures degrade to "unknown" — never a guess.
//
// Two official endpoints are used, in order:
//  1. core/stable-check/1.7 — per-version statuses ("latest"/"stable"/
//     "outdated"/"insecure"); preferred for its richer classification.
//  2. core/version-check/1.7 — upgrade offers per maintained branch; used as
//     a fallback. Branch-aware classification derives insecure/outdated from
//     the offer list.
package releases

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/version"
)

// StableCheckURL is the official WordPress.org stable-check endpoint.
const StableCheckURL = "https://api.wordpress.org/core/stable-check/1.7/"

// VersionCheckURL is the official WordPress.org version-check endpoint.
const VersionCheckURL = "https://api.wordpress.org/core/version-check/1.7/"

// Refresh is the cache lifetime.
const Refresh = 24 * time.Hour

// Core is the parsed release dataset.
type Core struct {
	// Latest is the newest released version.
	Latest string
	// Status maps version -> "latest" | "stable" | "outdated" | "insecure".
	Status map[string]string
	// FetchedAt is when the data was downloaded (cache hits).
	FetchedAt time.Time

	// raw preserves the source document for the disk cache.
	raw map[string]string
}

// FetchCore returns current release data, using a cached copy when fresh.
// cacheDir may be "" to disable caching.
func FetchCore(ctx context.Context, client *http.Client, cacheDir string) (*Core, error) {
	var cachePath string
	if cacheDir != "" {
		cachePath = filepath.Join(cacheDir, "core-stable-check.json")
		if c, err := readCachedCore(cachePath); err == nil {
			return c, nil
		}
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	core, err := fetchStableCheck(ctx, client)
	if err != nil {
		// Fallback: derive statuses from the version-check offers.
		core, err = fetchVersionCheck(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("stable-check: %v; version-check fallback: %v", err, err)
		}
	}
	if cachePath != "" && core.raw != nil {
		writeCachedCore(cachePath, core.raw)
	}
	return core, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, limit int64, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(into); err != nil {
		return err
	}
	return nil
}

func fetchStableCheck(ctx context.Context, client *http.Client) (*Core, error) {
	var raw map[string]string
	if err := getJSON(ctx, client, StableCheckURL, 4<<20, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", StableCheckURL, err)
	}
	core := buildCore(raw)
	core.raw = raw
	return core, nil
}

type versionCheckResponse struct {
	Offers []struct {
		Version  string `json:"version"`
		Response string `json:"response"`
	} `json:"offers"`
}

func fetchVersionCheck(ctx context.Context, client *http.Client) (*Core, error) {
	var parsed versionCheckResponse
	if err := getJSON(ctx, client, VersionCheckURL, 4<<20, &parsed); err != nil {
		return nil, fmt.Errorf("%s: %w", VersionCheckURL, err)
	}
	if len(parsed.Offers) == 0 {
		return nil, fmt.Errorf("no offers returned")
	}
	status := map[string]string{}
	for i, offer := range parsed.Offers {
		v := strings.TrimSpace(offer.Version)
		if v == "" {
			continue
		}
		if i == 0 {
			status[v] = "latest"
		} else if _, dup := status[v]; !dup {
			status[v] = "stable" // tip of a maintained branch
		}
	}
	latest := strings.TrimSpace(parsed.Offers[0].Version)
	core := &Core{Latest: latest, Status: status}
	core.raw = map[string]string{}
	for v := range status {
		core.raw[v] = status[v]
	}
	return core, nil
}

// buildCore derives the dataset from a stable-check document.
func buildCore(raw map[string]string) *Core {
	c := &Core{Status: make(map[string]string, len(raw))}
	for v, st := range raw {
		if st == "" {
			continue
		}
		c.Status[v] = st
		if st == "latest" {
			c.Latest = v
		}
	}
	if c.Latest == "" {
		// Fall back: highest "stable" entry when the feed lacks "latest".
		for v, st := range c.Status {
			if st != "stable" {
				continue
			}
			if c.Latest == "" || compareVersionStrings(v, c.Latest) > 0 {
				c.Latest = v
			}
		}
	}
	return c
}

// Classify returns "latest", "stable" (maintained branch tip), "outdated"
// (behind the latest release, branch maintained), "insecure" (missed
// in-branch security updates or branch dropped), or "" (unknown) for an
// installed version.
func (c *Core) Classify(installed string) string {
	if c == nil || len(c.Status) == 0 {
		return ""
	}
	if st, ok := c.Status[installed]; ok {
		return st
	}
	// Version not offered as-is. Decide via its release branch
	// (first two dot components): if that branch has a newer offered tip,
	// security updates were missed → insecure; if the branch is absent
	// entirely, it is no longer offered → insecure as well.
	branch := branchOf(installed)
	if branch != "" {
		for offered := range c.Status {
			if branchOf(offered) == branch && compareVersionStrings(offered, installed) > 0 {
				return "insecure"
			}
		}
	}
	return "insecure"
}

// branchOf returns the "major.minor" prefix of a dotted version.
func branchOf(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return digitsOnly(parts[0]) + "." + digitsOnly(parts[1])
}

// digitsOnly trims trailing non-digit characters (e.g. "8-RC" -> "8").
func digitsOnly(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

func compareVersionStrings(a, b string) int {
	if a == b {
		return 0
	}
	if wordpressLess(a, b) {
		return -1
	}
	return 1
}

func wordpressLess(a, b string) bool {
	pa, pb := split(a), split(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := range n {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func split(v string) []int {
	var out []int
	n := 0
	has := false
	for _, r := range v {
		if r >= '0' && r <= '9' {
			n = n*10 + int(r-'0')
			has = true
			continue
		}
		if r == '.' {
			out = append(out, n)
			n, has = 0, false
		} else {
			break // suffix like -RC1: stop
		}
	}
	if has {
		out = append(out, n)
	}
	return out
}

func readCachedCore(path string) (*Core, error) {
	info, err := os.Stat(path)
	if err != nil || time.Since(info.ModTime()) > Refresh {
		return nil, fmt.Errorf("cache stale")
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is built from our cache dir
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	c := buildCore(raw)
	c.raw = raw
	c.FetchedAt = info.ModTime()
	return c, nil
}

func writeCachedCore(path string, raw map[string]string) {
	if data, err := json.Marshal(raw); err == nil {
		_ = os.WriteFile(path, data, 0o644)
	}
}
