package app

import (
	"context"
	"net/http"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checksums"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/discovery"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/reporting"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
)

// checksumSource adapts the WordPress.org checksum client to the narrow
// interface the integrity checks consume, keeping HTTP clients and cache
// policy in the composition root where the rest of the network policy lives.
type checksumSource struct {
	client   *http.Client
	cacheDir string
	plugins  bool
}

// CoreChecksums returns the official manifest for one core version+locale.
func (s checksumSource) CoreChecksums(ctx context.Context, version, locale string) (map[string]string, error) {
	c, err := checksums.FetchCore(ctx, s.client, version, locale, s.cacheDir)
	if err != nil {
		return nil, err
	}
	return c.Checksums, nil
}

// PluginChecksums returns the file digests of one WordPress.org plugin release.
func (s checksumSource) PluginChecksums(ctx context.Context, slug, version string) (map[string]string, error) {
	return checksums.FetchPluginChecksums(ctx, s.client, slug, version, s.cacheDir)
}

// PluginsEnabled reports whether plugin verification was requested.
func (s checksumSource) PluginsEnabled() bool { return s.plugins }

var _ checks.ChecksumSource = checksumSource{}

// discoveryInfo converts discovery accounting into the report model.
func discoveryInfo(s discovery.Stats) *reporting.DiscoveryInfo {
	if s.Roots == 0 && s.DirectoriesVisited == 0 {
		return nil
	}
	return &reporting.DiscoveryInfo{
		Roots:              s.Roots,
		DirectoriesVisited: s.DirectoriesVisited,
		Truncated:          s.Truncated,
		TruncationReason:   s.TruncationReason,
	}
}

// feedTargetSetter is implemented by vulnerability providers that can restrict
// a large feed parse to the components actually installed. It is an optional
// capability: providers that cannot do it stay correct, just heavier.
type feedTargetSetter interface {
	SetTargets(keys []string)
}

// primeFeedTargets tells the provider which components the coming scan will
// look up, so a 100 MB+ feed is indexed for the installed set only. The slugs
// are collected up front because the feed is parsed once, on first lookup.
func primeFeedTargets(v any, sites []string) {
	setter, ok := v.(feedTargetSetter)
	if !ok {
		return
	}
	seen := map[string]bool{}
	var keys []string
	add := func(kind, slug string) {
		if slug == "" {
			return
		}
		key := kind + "/" + slug
		if seen[key] {
			return
		}
		seen[key] = true
		keys = append(keys, key)
	}
	for _, path := range sites {
		site, err := wordpress.Load(path)
		if err != nil {
			continue // the scan itself will report the load failure
		}
		for _, p := range site.Plugins {
			add("plugin", p.Slug)
		}
		for _, t := range site.Themes {
			add("theme", t.Slug)
		}
		for _, p := range site.MuPlugins {
			add("plugin", p.Slug)
		}
	}
	add("core", "wordpress")
	setter.SetTargets(keys)
}

// checksumSourceOrNil hides the adapter when the scan is offline, so checks
// report "not verified" rather than attempting a request.
func checksumSourceOrNil(src checks.ChecksumSource, offline bool) checks.ChecksumSource {
	if offline {
		return nil
	}
	return src
}
