package checks

import (
	"context"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/platform"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/releases"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/vulnerability"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wpcli"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// --- helpers ---

func testSite(t *testing.T, files map[string]string) *wordpress.Site {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	site, err := wordpress.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return site
}

func ctxFor(site *wordpress.Site) *Context {
	return &Context{
		Site:     site,
		Vulns:    vulnerability.Unavailable{},
		Ctx:      context.Background(),
		Offline:  true,
		Platform: platform.Current(),
	}
}

func runByID(t *testing.T, id string, ctx *Context) []Finding {
	t.Helper()
	c, ok := Get(id)
	if !ok {
		t.Fatalf("check %s not registered", id)
	}
	return c.Run(ctx)
}

func findingByID(t *testing.T, fs []Finding, id string) Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no finding with id %s in %+v", id, fs)
	return Finding{}
}

func statusOf(t *testing.T, fs []Finding, id string) Status {
	return findingByID(t, fs, id).Status
}

func perm(path string, mode os.FileMode) {
	_ = os.Chmod(path, mode)
}

// --- registry ---

func TestRegistryIDs(t *testing.T) {
	want := []string{
		"WP_CORE_OUTDATED", "WP_CORE_AUTO_UPDATES_DISABLED",
		"WP_DEBUG_ENABLED", "WP_DEBUG_DISPLAY_ENABLED",
		"FILE_EDITOR_ENABLED", "FILE_MODS_ALLOWED", "SECURITY_KEYS_MISSING",
		"FORCE_SSL_ADMIN_DISABLED", "DEFAULT_DATABASE_PREFIX",
		"WP_CONFIG_PERMISSIONS", "WEAK_FILE_PERMISSIONS",
		"EXPOSED_ENV_FILE", "EXPOSED_GIT_DIRECTORY", "EXPOSED_DEBUG_LOG",
		"EXPOSED_BACKUP_FILE", "EXPOSED_EDITOR_BACKUP", "PHP_EXECUTION_IN_UPLOADS",
		"PLUGIN_OUTDATED", "PLUGIN_VULNERABILITY", "INACTIVE_PLUGIN",
		"THEME_OUTDATED", "THEME_VULNERABILITY", "INACTIVE_THEME",
		"ADMIN_USERNAME", "PHP_OUTDATED", "PHP_DISPLAY_ERRORS",
		"DIRECTORY_LISTING", "HTTPS_DISABLED", "REST_USER_ENUMERATION",
		"XMLRPC_ENABLED",
	}
	seen := map[string]bool{}
	for _, c := range All() {
		if seen[c.ID] {
			t.Errorf("duplicate ID %s", c.ID)
		}
		seen[c.ID] = true
		if c.Category == "" || c.Title == "" || c.Description == "" {
			t.Errorf("check %s missing metadata", c.ID)
		}
	}
	for _, id := range want {
		if !seen[id] {
			t.Errorf("expected check %s registered", id)
		}
	}
}

// --- wp-config checks ---

const configWithDebug = `<?php
define( 'DB_PASSWORD', 'TopSecret99!' );
define( 'WP_DEBUG', true );
$table_prefix = 'wp_';
`

func TestWPDebugEnabledProduction(t *testing.T) {
	site := testSite(t, map[string]string{"wp-config.php": configWithDebug})
	fs := runByID(t, "WP_DEBUG_ENABLED", ctxFor(site))
	f := findingByID(t, fs, "WP_DEBUG_ENABLED")
	if f.Status != StatusFailed || f.Severity != SevMedium {
		t.Errorf("got %+v", f)
	}
	// Central secret test: DB password must never appear anywhere.
	for k, v := range f.Evidence {
		if v == "TopSecret99!" {
			t.Errorf("secret in evidence[%s]", k)
		}
	}
}

func TestWPDebugEnabledDevDowngrade(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-config.php": configWithDebug + "define( 'WP_ENVIRONMENT_TYPE', 'local' );\n",
	})
	f := findingByID(t, runByID(t, "WP_DEBUG_ENABLED", ctxFor(site)), "WP_DEBUG_ENABLED")
	if f.Severity != SevLow {
		t.Errorf("dev env should downgrade severity, got %s", f.Severity)
	}
}

func TestWPDebugDisplayDefaultFails(t *testing.T) {
	// WP_DEBUG on, WP_DEBUG_DISPLAY undefined → WordPress default = display on.
	site := testSite(t, map[string]string{"wp-config.php": configWithDebug})
	f := findingByID(t, runByID(t, "WP_DEBUG_DISPLAY_ENABLED", ctxFor(site)), "WP_DEBUG_DISPLAY_ENABLED")
	if f.Status != StatusFailed {
		t.Errorf("default display should fail, got %s", f.Status)
	}
}

func TestWPDebugDisplayExplicitOffPasses(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-config.php": configWithDebug + "define( 'WP_DEBUG_DISPLAY', false );\n",
	})
	if s := statusOf(t, runByID(t, "WP_DEBUG_DISPLAY_ENABLED", ctxFor(site)), "WP_DEBUG_DISPLAY_ENABLED"); s != StatusPassed {
		t.Errorf("explicit off should pass, got %s", s)
	}
}

func TestDebugChecksSkipWithoutConfig(t *testing.T) {
	site := testSite(t, map[string]string{"wp-settings.php": "<?php\n"})
	for _, id := range []string{"WP_DEBUG_ENABLED", "FILE_EDITOR_ENABLED", "SECURITY_KEYS_MISSING"} {
		if s := statusOf(t, runByID(t, id, ctxFor(site)), id); s != StatusSkipped {
			t.Errorf("%s should skip without wp-config, got %s", id, s)
		}
	}
}

func TestSecurityKeysMissing(t *testing.T) {
	site := testSite(t, map[string]string{"wp-config.php": configWithDebug})
	f := findingByID(t, runByID(t, "SECURITY_KEYS_MISSING", ctxFor(site)), "SECURITY_KEYS_MISSING")
	if f.Status != StatusFailed || f.Severity != SevHigh {
		t.Errorf("missing salts should fail high, got %+v", f)
	}

	fullKeys := "<?php\n"
	for _, k := range []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"} {
		fullKeys += "define( '" + k + "', 'value-" + k + "' );\n"
	}
	site2 := testSite(t, map[string]string{"wp-config.php": fullKeys})
	if s := statusOf(t, runByID(t, "SECURITY_KEYS_MISSING", ctxFor(site2)), "SECURITY_KEYS_MISSING"); s != StatusPassed {
		t.Errorf("all keys present should pass, got %s", s2Str(t, ctxFor(site2), "SECURITY_KEYS_MISSING"))
	}
}

func s2Str(t *testing.T, ctx *Context, id string) Status {
	t.Helper()
	return statusOf(t, runByID(t, id, ctx), id)
}

func TestFileEditorAndMods(t *testing.T) {
	site := testSite(t, map[string]string{"wp-config.php": "<?php\n"})
	if s := statusOf(t, runByID(t, "FILE_EDITOR_ENABLED", ctxFor(site)), "FILE_EDITOR_ENABLED"); s != StatusFailed {
		t.Errorf("editor should fail when DISALLOW_FILE_EDIT absent")
	}
	hardened := testSite(t, map[string]string{
		"wp-config.php": "<?php\ndefine( 'DISALLOW_FILE_EDIT', true );\ndefine( 'DISALLOW_FILE_MODS', true );\n",
	})
	if s := statusOf(t, runByID(t, "FILE_EDITOR_ENABLED", ctxFor(hardened)), "FILE_EDITOR_ENABLED"); s != StatusPassed {
		t.Errorf("editor should pass when disallowed")
	}
	if s := statusOf(t, runByID(t, "FILE_MODS_ALLOWED", ctxFor(hardened)), "FILE_MODS_ALLOWED"); s != StatusPassed {
		t.Errorf("mods should pass when disallowed")
	}
}

func TestDBPrefix(t *testing.T) {
	site := testSite(t, map[string]string{"wp-config.php": "<?php\n$table_prefix = 'wp_';\n"})
	f := findingByID(t, runByID(t, "DEFAULT_DATABASE_PREFIX", ctxFor(site)), "DEFAULT_DATABASE_PREFIX")
	if f.Status != StatusFailed || f.Severity != SevLow {
		t.Errorf("wp_ prefix should fail low, got %+v", f)
	}
	custom := testSite(t, map[string]string{"wp-config.php": "<?php\n$table_prefix = 'x9q_';\n"})
	if s := statusOf(t, runByID(t, "DEFAULT_DATABASE_PREFIX", ctxFor(custom)), "DEFAULT_DATABASE_PREFIX"); s != StatusPassed {
		t.Errorf("custom prefix should pass")
	}
}

// --- filesystem checks ---

func TestWPConfigPermissions(t *testing.T) {
	site := testSite(t, map[string]string{"wp-config.php": "<?php\n"})
	cfgPath := filepath.Join(site.Path, "wp-config.php")

	perm(cfgPath, 0o666) // world-writable
	site = testSiteReload(t, site.Path)
	if f := findingByID(t, runByID(t, "WP_CONFIG_PERMISSIONS", ctxFor(site)), "WP_CONFIG_PERMISSIONS"); f.Severity != SevHigh {
		t.Errorf("0666 should be high, got %s", f.Severity)
	}

	perm(cfgPath, 0o644) // world-readable
	site = testSiteReload(t, site.Path)
	if f := findingByID(t, runByID(t, "WP_CONFIG_PERMISSIONS", ctxFor(site)), "WP_CONFIG_PERMISSIONS"); f.Severity != SevLow {
		t.Errorf("0644 should be low, got %s", f.Severity)
	}

	perm(cfgPath, 0o600)
	site = testSiteReload(t, site.Path)
	if s := statusOf(t, runByID(t, "WP_CONFIG_PERMISSIONS", ctxFor(site)), "WP_CONFIG_PERMISSIONS"); s != StatusPassed {
		t.Errorf("0600 should pass")
	}
	perm(cfgPath, 0o600) // leave clean for temp cleanup
}

func testSiteReload(t *testing.T, dir string) *wordpress.Site {
	t.Helper()
	site, err := wordpress.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return site
}

func TestExposedEnvFile(t *testing.T) {
	site := testSite(t, map[string]string{".env": "DB_PASSWORD=x\n"})
	if f := findingByID(t, runByID(t, "EXPOSED_ENV_FILE", ctxFor(site)), "EXPOSED_ENV_FILE"); f.Status != StatusFailed || f.Severity != SevHigh {
		t.Errorf(".env should fail high, got %+v", f)
	}
	// Evidence must not contain the file contents.
	f := findingByID(t, runByID(t, "EXPOSED_ENV_FILE", ctxFor(site)), "EXPOSED_ENV_FILE")
	for _, v := range f.Evidence {
		if v == "DB_PASSWORD=x" {
			t.Error("evidence must not include .env contents")
		}
	}
	clean := testSite(t, map[string]string{"wp-settings.php": "<?php\n"})
	if s := statusOf(t, runByID(t, "EXPOSED_ENV_FILE", ctxFor(clean)), "EXPOSED_ENV_FILE"); s != StatusPassed {
		t.Errorf("clean site should pass env check")
	}
}

func TestExposedGitDirectory(t *testing.T) {
	site := testSite(t, map[string]string{".git/HEAD": "ref: refs/heads/main\n"})
	if s := statusOf(t, runByID(t, "EXPOSED_GIT_DIRECTORY", ctxFor(site)), "EXPOSED_GIT_DIRECTORY"); s != StatusFailed {
		t.Errorf(".git should fail")
	}
}

func TestExposedDebugLog(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-content/debug.log": "[10-Sep-2026 03:11:07 UTC] PHP Notice: x\n",
	})
	if s := statusOf(t, runByID(t, "EXPOSED_DEBUG_LOG", ctxFor(site)), "EXPOSED_DEBUG_LOG"); s != StatusFailed {
		t.Errorf("non-empty debug.log should fail")
	}
}

func TestExposedBackupsAndEditorFiles(t *testing.T) {
	site := testSite(t, map[string]string{
		"backup.sql":        "CREATE TABLE wp_options;",
		"wp-config.php~":    "<?php\n",
		"wp-includes/x.php": "<?php\n",
	})
	if s := statusOf(t, runByID(t, "EXPOSED_BACKUP_FILE", ctxFor(site)), "EXPOSED_BACKUP_FILE"); s != StatusFailed {
		t.Errorf("backup.sql should fail")
	}
	if s := statusOf(t, runByID(t, "EXPOSED_EDITOR_BACKUP", ctxFor(site)), "EXPOSED_EDITOR_BACKUP"); s != StatusFailed {
		t.Errorf("wp-config.php~ should fail")
	}
}

func TestPHPInUploads(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-content/uploads/2026/01/photo.php": "<?php echo 1;",
	})
	if s := statusOf(t, runByID(t, "PHP_EXECUTION_IN_UPLOADS", ctxFor(site)), "PHP_EXECUTION_IN_UPLOADS"); s != StatusFailed {
		t.Errorf("php in uploads should fail")
	}
	empty := testSite(t, map[string]string{
		"wp-content/uploads/2026/01/photo.jpg": "jpeg",
	})
	if s := statusOf(t, runByID(t, "PHP_EXECUTION_IN_UPLOADS", ctxFor(empty)), "PHP_EXECUTION_IN_UPLOADS"); s != StatusPassed {
		t.Errorf("jpg-only uploads should pass")
	}
	noUploads := testSite(t, map[string]string{"wp-settings.php": "<?php\n"})
	if s := statusOf(t, runByID(t, "PHP_EXECUTION_IN_UPLOADS", ctxFor(noUploads)), "PHP_EXECUTION_IN_UPLOADS"); s != StatusSkipped {
		t.Errorf("missing uploads dir should skip, got %s", s)
	}
}

// --- core + network checks ---

func TestCoreOutdated(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-includes/version.php": "<?php\n$wp_version = '6.4.1';\n",
	})
	ctx := ctxFor(site)
	ctx.Core = &releases.Core{
		Latest: "6.8.2",
		Status: map[string]string{"6.8.2": "latest", "6.4.1": "insecure", "6.7.1": "outdated"},
	}
	if f := findingByID(t, runByID(t, "WP_CORE_OUTDATED", ctx), "WP_CORE_OUTDATED"); f.Severity != SevHigh {
		t.Errorf("insecure version should be high, got %s", f.Severity)
	}

	ctx2 := ctxFor(site)
	ctx2.Core = &releases.Core{Latest: "6.8.2", Status: map[string]string{"6.8.2": "latest", "6.4.2": "outdated"}}
	_ = ctx2

	current := testSite(t, map[string]string{
		"wp-includes/version.php": "<?php\n$wp_version = '6.8.2';\n",
	})
	cctx := ctxFor(current)
	cctx.Core = &releases.Core{Latest: "6.8.2", Status: map[string]string{"6.8.2": "latest"}}
	if s := statusOf(t, runByID(t, "WP_CORE_OUTDATED", cctx), "WP_CORE_OUTDATED"); s != StatusPassed {
		t.Errorf("current version should pass, got %s", s)
	}

	// Offline: core nil → skipped.
	if s := statusOf(t, runByID(t, "WP_CORE_OUTDATED", ctxFor(site)), "WP_CORE_OUTDATED"); s != StatusSkipped {
		t.Errorf("offline core check should skip, got %s", s)
	}
}

func TestHTTPSDisabled(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-config.php": "<?php\nconst WP_HOME = 'http://example.com';\nconst WP_SITEURL = 'http://example.com/wp';\n",
	})
	f := findingByID(t, runByID(t, "HTTPS_DISABLED", ctxFor(site)), "HTTPS_DISABLED")
	if f.Status != StatusFailed || f.Severity != SevMedium {
		t.Errorf("http site should fail medium, got %+v", f)
	}

	loop := testSite(t, map[string]string{
		"wp-config.php": "<?php\nconst WP_HOME = 'http://localhost:8888';\n",
	})
	f2 := findingByID(t, runByID(t, "HTTPS_DISABLED", ctxFor(loop)), "HTTPS_DISABLED")
	if f2.Status != StatusFailed || f2.Severity != SevInfo {
		t.Errorf("loopback http should be info severity, got %+v", f2)
	}

	httpsSite := testSite(t, map[string]string{
		"wp-config.php": "<?php\nconst WP_HOME = 'https://example.com';\n",
	})
	if s := statusOf(t, runByID(t, "HTTPS_DISABLED", ctxFor(httpsSite)), "HTTPS_DISABLED"); s != StatusPassed {
		t.Errorf("https site should pass")
	}
}

func TestRESTUserEnumeration(t *testing.T) {
	var mode int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(mode)
		if mode == http.StatusOK {
			_, _ = w.Write([]byte(`[{"id":1,"slug":"john"},{"id":2,"slug":"admin"}]`))
		}
	}))
	defer srv.Close()

	site := testSite(t, map[string]string{
		"wp-config.php": "<?php\nconst WP_HOME = '" + srv.URL + "';\n",
	})

	// 200 with users → failed.
	mode = http.StatusOK
	ctx := ctxFor(site)
	ctx.Offline = false
	ctx.HTTP = srv.Client()
	if f := findingByID(t, runByID(t, "REST_USER_ENUMERATION", ctx), "REST_USER_ENUMERATION"); f.Status != StatusFailed || f.Severity != SevMedium {
		t.Errorf("open enumeration should fail medium, got %+v", f)
	}

	// 403 → passed.
	mode = http.StatusForbidden
	if s := statusOf(t, runByID(t, "REST_USER_ENUMERATION", ctx), "REST_USER_ENUMERATION"); s != StatusPassed {
		t.Errorf("blocked enumeration should pass, got %s", s)
	}

	// Offline → skipped.
	if s := statusOf(t, runByID(t, "REST_USER_ENUMERATION", ctxFor(site)), "REST_USER_ENUMERATION"); s != StatusSkipped {
		t.Errorf("offline should skip enumeration, got %s", s)
	}
}

// --- php + xmlrpc + users ---

func TestPHPOutdated(t *testing.T) {
	site := testSite(t, map[string]string{"wp-settings.php": "<?php\n"})
	ctx := ctxFor(site)
	ctx.WP = &wpcli.Siteenv{}
	ctx.WP.PHP = "7.4.33"
	if f := findingByID(t, runByID(t, "PHP_OUTDATED", ctx), "PHP_OUTDATED"); f.Severity != SevHigh {
		t.Errorf("PHP 7.4 should be high (EOL), got %s", f.Severity)
	}
	ctx.WP.PHP = "8.2.10"
	if f := findingByID(t, runByID(t, "PHP_OUTDATED", ctx), "PHP_OUTDATED"); f.Severity != SevLow {
		t.Errorf("PHP 8.2 should be low (security-only), got %s", f.Severity)
	}
}

func TestXMLRPC(t *testing.T) {
	site := testSite(t, map[string]string{"wp-settings.php": "<?php\n"})
	ctx := ctxFor(site)
	if s := statusOf(t, runByID(t, "XMLRPC_ENABLED", ctx), "XMLRPC_ENABLED"); s != StatusSkipped {
		t.Errorf("no wpcli should skip xmlrpc, got %s", s)
	}
	tr := true
	ctx.WP = &wpcli.Siteenv{XMLRPC: &tr}
	if s := statusOf(t, runByID(t, "XMLRPC_ENABLED", ctx), "XMLRPC_ENABLED"); s != StatusFailed {
		t.Errorf("xmlrpc true should fail (low)")
	}
	fal := false
	ctx.WP = &wpcli.Siteenv{XMLRPC: &fal}
	if s := statusOf(t, runByID(t, "XMLRPC_ENABLED", ctx), "XMLRPC_ENABLED"); s != StatusPassed {
		t.Errorf("xmlrpc false should pass")
	}
}

func TestAdminUsername(t *testing.T) {
	site := testSite(t, map[string]string{"wp-settings.php": "<?php\n"})
	ctx := ctxFor(site)
	ctx.WP = &wpcli.Siteenv{Admins: []wpcli.WPUser{{Login: "bobby"}, {Login: "admin"}}}
	if s := statusOf(t, runByID(t, "ADMIN_USERNAME", ctx), "ADMIN_USERNAME"); s != StatusFailed {
		t.Errorf("admin login should fail")
	}
	ctx.WP = &wpcli.Siteenv{Admins: []wpcli.WPUser{{Login: "bobby"}}}
	if s := statusOf(t, runByID(t, "ADMIN_USERNAME", ctx), "ADMIN_USERNAME"); s != StatusPassed {
		t.Errorf("no admin login should pass")
	}
	ctx.WP = nil
	if s := statusOf(t, runByID(t, "ADMIN_USERNAME", ctx), "ADMIN_USERNAME"); s != StatusSkipped {
		t.Errorf("no wpcli should skip")
	}
}

// --- plugins/themes + vulnerabilities ---

func TestPluginVulnerabilityWithStubProvider(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-content/plugins/broke/broke.php": "<?php\n/*\nPlugin Name: Broke\nVersion: 1.0.0\n*/\n",
	})
	ctx := ctxFor(site)
	ctx.Vulns = stubProvider{}

	fs := runByID(t, "PLUGIN_VULNERABILITY", ctx)
	f := findingByID(t, fs, "PLUGIN_VULNERABILITY")
	if f.Status != StatusFailed || f.Severity != SevCritical {
		t.Errorf("vulnerable plugin should fail critical, got %+v", f)
	}
	if !contains(f.Evidence["matches"], "CVE-0000-1234") {
		t.Errorf("evidence should name the CVE: %+v", f.Evidence)
	}

	safe := testSite(t, map[string]string{
		"wp-content/plugins/safe/safe.php": "<?php\n/*\nPlugin Name: Safe\nVersion: 9.9.9\n*/\n",
	})
	sctx := ctxFor(safe)
	sctx.Vulns = stubProvider{}
	if s := statusOf(t, runByID(t, "PLUGIN_VULNERABILITY", sctx), "PLUGIN_VULNERABILITY"); s != StatusPassed {
		t.Errorf("safe plugin should pass, got %s", s)
	}

	// Unavailable provider → skipped, never a fabricated failure.
	uctx := ctxFor(site)
	if s := statusOf(t, runByID(t, "PLUGIN_VULNERABILITY", uctx), "PLUGIN_VULNERABILITY"); s != StatusSkipped {
		t.Errorf("unavailable provider should skip, got %s", s)
	}
}

// stubProvider answers one specific slug/version combination.
type stubProvider struct{}

func (stubProvider) Name() string { return "stub" }

func (s stubProvider) lookup(slug, version string) ([]vulnerability.Vuln, error) {
	if slug == "broke" && version == "1.0.0" {
		return []vulnerability.Vuln{{
			ID: "v1", CVE: "CVE-0000-1234", Rating: vulnerability.SeverityCritical,
			Patched: "1.0.1", Source: "stub",
		}}, nil
	}
	return nil, nil
}

func (s stubProvider) LookupPlugin(slug, version string) ([]Vuln, error) {
	return s.lookup(slug, version)
}

func (s stubProvider) LookupTheme(slug, version string) ([]Vuln, error) {
	return nil, nil
}

func (s stubProvider) LookupCore(version string) ([]Vuln, error) {
	return nil, nil
}

type Vuln = vulnerability.Vuln

// --- options/filtering ---

func TestSeverityFiltering(t *testing.T) {
	opts := Options{MinSeverity: SevHigh}
	findings := []Finding{
		{ID: "A", Severity: SevCritical, Status: StatusFailed},
		{ID: "B", Severity: SevHigh, Status: StatusFailed},
		{ID: "C", Severity: SevMedium, Status: StatusFailed},
		{ID: "D", Severity: SevHigh, Status: StatusPassed}, // passed always dropped when filtering
	}
	got := opts.FilterFindings(findings)
	if len(got) != 2 || got[0].ID != "A" || got[1].ID != "B" {
		t.Errorf("severity filter wrong: %+v", got)
	}
	if len((Options{}).FilterFindings(findings)) != 4 {
		t.Errorf("no filter should keep everything")
	}
}

func contains(s, sub string) bool {
	return stringsContains(s, sub)
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
