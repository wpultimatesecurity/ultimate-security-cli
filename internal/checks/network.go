package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/platform"
)

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "HTTPS_DISABLED",
			Title:       "Site URL does not use HTTPS",
			Category:    CatNetwork,
			Description: "The configured site/home URL uses plain HTTP. Logins and admin sessions travel unencrypted; on public hosts that is a direct credential exposure. Loopback/dev hosts are reported at info severity only.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/https/",
			},
		},
		Run: runHTTPSDisabled,
	})
	Register(Simple{
		Meta: Meta{
			ID:          "REST_USER_ENUMERATION",
			Title:       "REST API exposes the user list",
			Category:    CatExposure,
			Description: "GET /wp-json/wp/v2/users returning the full user list gives attackers valid login names. Network-backed check: performs one unauthenticated request to the site's own URL; skipped in --offline mode.",
			References: []string{
				"https://developer.wordpress.org/rest-api/",
			},
		},
		Run: runRESTUserEnumeration,
	})
}

// siteURLs returns the best-known site URLs (home first).
func siteURLs(ctx *Context) []string {
	var out []string
	if ctx.WP != nil {
		if ctx.WP.HomeURL != "" {
			out = append(out, ctx.WP.HomeURL)
		}
		if ctx.WP.SiteURL != "" && ctx.WP.SiteURL != ctx.WP.HomeURL {
			out = append(out, ctx.WP.SiteURL)
		}
	}
	if ctx.Site != nil {
		if ctx.Site.HomeURL != "" {
			out = append(out, ctx.Site.HomeURL)
		}
		if ctx.Site.SiteURL != "" && ctx.Site.SiteURL != ctx.Site.HomeURL {
			out = append(out, ctx.Site.SiteURL)
		}
	}
	return out
}

func runHTTPSDisabled(ctx *Context) []Finding {
	m := Meta{ID: "HTTPS_DISABLED", Title: "Site URL does not use HTTPS", Category: CatNetwork,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/https/"}}
	urls := siteURLs(ctx)
	if len(urls) == 0 {
		return []Finding{m.skipf("site URL unknown (needs wp-config constants or WP-CLI)")}
	}
	primary := urls[0]
	u, err := url.Parse(primary)
	if err != nil || u.Scheme == "" {
		return []Finding{Finding{ID: m.ID, Title: "Site URL not parseable", Category: m.Category,
			Severity: SevInfo, Status: StatusUnknown, Confidence: ConfLow,
			Description: "The configured site URL could not be parsed: " + primary,
			Evidence:    map[string]string{"siteurl": primary}}}
	}
	ev := map[string]string{"siteurl": primary}
	if u.Scheme == "https" {
		return []Finding{Finding{ID: m.ID, Title: "HTTPS enforced", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "The site URL uses HTTPS.",
			Evidence:    ev}}
	}
	host := u.Hostname()
	sev := SevMedium
	note := ""
	if platform.IsLoopbackHost(host) {
		sev = SevInfo
		note = "loopback/dev host; plain HTTP is expected in local development"
	}
	if note != "" {
		ev["note"] = note
	}
	return []Finding{Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: sev, Status: StatusFailed, Confidence: ConfHigh,
		Description:    "The site is configured with a plain-HTTP URL. Credentials and admin pages travel unencrypted unless a proxy terminates TLS and redirects.",
		Evidence:       ev,
		Recommendation: "Install TLS and update the WordPress and Site URLs to https (update hardcoded URLs in content too).",
		References:     m.References,
	}}
}

func runRESTUserEnumeration(ctx *Context) []Finding {
	m := Meta{ID: "REST_USER_ENUMERATION", Title: "REST API exposes the user list", Category: CatExposure,
		References: []string{"https://developer.wordpress.org/rest-api/"}}
	if ctx.Offline || ctx.HTTP == nil {
		return []Finding{m.skipf("network-backed check disabled (--offline or no HTTP client)")}
	}
	base := ""
	for _, u := range siteURLs(ctx) {
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			base = u
			break
		}
	}
	if base == "" {
		return []Finding{m.skipf("site URL unknown")}
	}
	endpoint := strings.TrimRight(base, "/") + "/wp-json/wp/v2/users?per_page=100"
	client := ctx.HTTP
	if client.Timeout == 0 {
		client = &http.Client{Timeout: httpTimeout()}
	}
	cctx, cancel := context.WithTimeout(ctx.Ctx, httpTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return []Finding{m.skipf("request build failed: " + err.Error())}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return []Finding{Finding{ID: m.ID, Title: "User enumeration not verifiable", Category: m.Category,
			Severity: SevInfo, Status: StatusUnknown, Confidence: ConfLow,
			Description: "The request to the REST users endpoint failed; the site may be down or unreachable from here.",
			Evidence:    map[string]string{"endpoint": endpoint, "error": err.Error()}}}
	}
	defer resp.Body.Close() //nolint:errcheck
	ev := map[string]string{"endpoint": endpoint, "http_status": fmt.Sprint(resp.StatusCode)}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusOK:
		var users []map[string]any
		if err := json.Unmarshal(body, &users); err != nil {
			return []Finding{Finding{ID: m.ID, Title: "Unexpected REST response", Category: m.Category,
				Severity: SevInfo, Status: StatusUnknown, Confidence: ConfLow,
				Description: "The endpoint answered 200 but the body is not a user list; a plugin may already alter it.",
				Evidence:    ev}}
		}
		if len(users) == 0 {
			return []Finding{Finding{ID: m.ID, Title: "No users exposed", Category: m.Category,
				Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
				Description: "The REST users endpoint returned an empty list.",
				Evidence:    ev}}
		}
		ev["users_returned"] = fmt.Sprint(len(users))
		var names []string
		for i, u := range users {
			if slug, ok := u["slug"].(string); ok && slug != "" {
				names = append(names, slug)
			}
			if i >= 9 {
				break
			}
		}
		if len(names) > 0 {
			ev["exposed_logins"] = strings.Join(names, ", ")
		}
		return []Finding{Finding{
			ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevMedium, Status: StatusFailed, Confidence: ConfHigh,
			Description:    "An unauthenticated request to /wp-json/wp/v2/users returns the site's user list, handing attackers valid login names for brute-force campaigns.",
			Evidence:       ev,
			Recommendation: "Restrict REST user routes for unauthenticated visitors (e.g. a small plugin or filter blocking user enumeration when the requester lacks auth).",
			References:     m.References,
		}}
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusNotFound:
		return []Finding{Finding{ID: m.ID, Title: "User list not exposed", Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: fmt.Sprintf("The endpoint answered HTTP %d; the user list is not served to anonymous visitors.", resp.StatusCode),
			Evidence:    ev}}
	default:
		return []Finding{Finding{ID: m.ID, Title: "Unexpected REST response", Category: m.Category,
			Severity: SevInfo, Status: StatusUnknown, Confidence: ConfLow,
			Description: fmt.Sprintf("The endpoint answered HTTP %d; result inconclusive.", resp.StatusCode),
			Evidence:    ev}}
	}
}

// consumedImport keeps the time import even if probes change.
var _ = time.Second
