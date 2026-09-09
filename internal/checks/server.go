package checks

import (
	"os"
	"regexp"
	"strings"
)

// nginxConfigPaths lists standard nginx config locations that are often
// world-readable. Detection is best-effort and never requires root.
var nginxConfigPaths = []string{
	"/etc/nginx/nginx.conf",
	"/usr/local/etc/nginx/nginx.conf",
	"/opt/homebrew/etc/nginx/nginx.conf",
	"/usr/local/openresty/nginx/conf/nginx.conf",
}

// DetectWebServer guesses the serving web server from readable local
// configuration. It returns "", "nginx", "apache", or "litespeed".
// A .htaccess file implies Apache or a LiteSpeed-compatible server; nginx
// never reads .htaccess.
func DetectWebServer(sitePath string) string {
	for _, p := range nginxConfigPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return "nginx"
		}
	}
	if st, err := os.Stat("/usr/local/lsws"); err == nil && st.IsDir() {
		return "litespeed"
	}
	if _, err := os.Stat(sitePath + "/.htaccess"); err == nil {
		return "apache"
	}
	return ""
}

var (
	reHtaccessIndexesOn  = regexp.MustCompile(`(?mi)^\s*Options\s+[A-Za-z ,]*\+Indexes`)
	reHtaccessIndexesOff = regexp.MustCompile(`(?mi)^\s*Options\s+[A-Za-z ,]*-Indexes`)
	reNginxAutoIndex     = regexp.MustCompile(`(?m)^\s*autoindex\s+on\s*;`)
)

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "DIRECTORY_LISTING",
			Title:       "Directory indexes enabled",
			Category:    CatServer,
			Description: "Auto-index lists directory contents to visitors. Only determined from readable local configuration; without it the check skips rather than guesses.",
			References: []string{
				"https://nginx.org/en/docs/http/ngx_http_autoindex_module.html",
				"https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html",
			},
		},
		Run: runDirectoryListing,
	})
}

func runDirectoryListing(ctx *Context) []Finding {
	m := Meta{ID: "DIRECTORY_LISTING", Title: "Directory indexes enabled", Category: CatServer,
		References: []string{
			"https://nginx.org/en/docs/http/ngx_http_autoindex_module.html",
			"https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html",
		}}
	switch ctx.Server {
	case "nginx":
		for _, p := range nginxConfigPaths {
			data, err := os.ReadFile(p) //nolint:gosec // fixed path list above
			if err != nil {
				continue
			}
			if reNginxAutoIndex.Match(data) {
				return []Finding{Finding{
					ID: m.ID, Title: m.Title, Category: m.Category,
					Severity: SevLow, Status: StatusFailed, Confidence: ConfMedium,
					Description:    "nginx configuration enables autoindex; directory contents may be listed to visitors.",
					Evidence:       map[string]string{"config": p, "directive": "autoindex on"},
					Recommendation: "Remove autoindex on (or scope it to trusted locations).",
					References:     m.References,
				}}
			}
			return []Finding{Finding{ID: m.ID, Title: "Autoindex off", Category: m.Category,
				Severity: SevInfo, Status: StatusPassed, Confidence: ConfMedium,
				Description: "Readable nginx configuration does not enable autoindex.",
				Evidence:    map[string]string{"config": p}}}
		}
		return []Finding{m.skipf("nginx config not readable without elevated permissions")}
	case "apache", "litespeed":
		data, err := os.ReadFile(ctx.Site.Path + "/.htaccess") //nolint:gosec // site path under audit
		if err != nil {
			return []Finding{m.skipf(".htaccess not readable")}
		}
		switch {
		case reHtaccessIndexesOn.Match(data):
			return []Finding{Finding{
				ID: m.ID, Title: m.Title, Category: m.Category,
				Severity: SevLow, Status: StatusFailed, Confidence: ConfMedium,
				Description:    ".htaccess enables directory indexes (Options +Indexes).",
				Evidence:       map[string]string{"file": ".htaccess"},
				Recommendation: "Use 'Options -Indexes' to disable directory listings.",
				References:     m.References,
			}}
		case reHtaccessIndexesOff.Match(data):
			return []Finding{Finding{ID: m.ID, Title: "Indexes disabled", Category: m.Category,
				Severity: SevInfo, Status: StatusPassed, Confidence: ConfMedium,
				Description: ".htaccess disables directory indexes.",
				Evidence:    map[string]string{"file": ".htaccess"}}}
		default:
			return []Finding{Finding{ID: m.ID, Title: "Indexes setting not found", Category: m.Category,
				Severity: SevInfo, Status: StatusUnknown, Confidence: ConfLow,
				Description: "The readable .htaccess does not set Options ±Indexes; the host-wide Apache setting (httpd.conf) may still enable them and was not readable.",
				Evidence:    map[string]string{"file": ".htaccess"}}}
		}
	default:
		return []Finding{m.skipf("no readable web server configuration detected (server unknown)")}
	}
}

// keep the strings import meaningful if regexes move.
var _ = strings.TrimSpace
