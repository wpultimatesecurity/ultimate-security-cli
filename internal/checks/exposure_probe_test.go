package checks

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/probe"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wordpress"
)

// exposureFixture builds a site with the sensitive files the check probes.
func exposureFixture(t *testing.T) *wordpress.Site {
	t.Helper()
	return testSite(t, map[string]string{
		"wp-settings.php":                 "<?php\n",
		"wp-includes/version.php":         "<?php\n$wp_version = '6.4.1';\n",
		".env":                            "DB_PASSWORD=whatever",
		"wp-config.php~":                  "<?php\n",
		"wp-content/debug.log":            "[10-Sep-2026] notice\n",
		"backup-2026-09-10.sql":           "INSERT INTO users",
		"wp-content/plugins/x/readme.txt": "x",
	})
}

func proberFor(t *testing.T, serverURL string) *probe.Prober {
	t.Helper()
	return probe.New(probe.Policy{
		AllowedOrigins: []string{serverURL},
		AllowPrivate:   true, // the test server is on loopback
		MaxBodyBytes:   1 << 20,
	})
}

// TestPubliclyRetrievableConfirmsExposure is the property that makes the check
// worth having: a file that the server really serves is reported as confirmed,
// with the URL evidence, while one the server refuses is not.
func TestPubliclyRetrievableConfirmsExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("the exposure probe must use HEAD, got %s", r.Method)
		}
		switch r.URL.Path {
		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "19")
			w.WriteHeader(http.StatusOK)
		case "/wp-content/debug.log":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	site := exposureFixture(t)
	ctx := ctxFor(site)
	ctx.Offline = false
	ctx.BaseURL = srv.URL
	ctx.Probe = proberFor(t, srv.URL)

	f := findingByID(t, runByID(t, "SENSITIVE_FILE_PUBLICLY_RETRIEVABLE", ctx), "SENSITIVE_FILE_PUBLICLY_RETRIEVABLE")
	if f.Status != StatusFailed || f.Severity != SevHigh {
		t.Fatalf("confirmed exposure must fail high: %+v", f)
	}
	if len(f.Occurrences) != 1 || f.Occurrences[0].Location != ".env" {
		t.Fatalf("occurrences = %+v, want only the retrievable .env", f.Occurrences)
	}
	if !contains(f.Evidence["not_retrievable"], "debug.log") {
		t.Errorf("protected files belong in evidence: %+v", f.Evidence)
	}
	if !contains(f.Evidence["impact"], "not downloaded") {
		t.Errorf("evidence must state that contents were not downloaded: %+v", f.Evidence)
	}
}

func TestPubliclyRetrievablePassesWhenNothingIsServed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	site := exposureFixture(t)
	ctx := ctxFor(site)
	ctx.Offline = false
	ctx.BaseURL = srv.URL
	ctx.Probe = proberFor(t, srv.URL)

	f := findingByID(t, runByID(t, "SENSITIVE_FILE_PUBLICLY_RETRIEVABLE", ctx), "SENSITIVE_FILE_PUBLICLY_RETRIEVABLE")
	if f.Status != StatusPassed || f.Severity != SevInfo {
		t.Fatalf("a server that serves nothing must pass: %+v", f)
	}
}

// TestPubliclyRetrievableUnknownWhenInconclusive pins the skip discipline: a
// server that answers neither 200 nor a denial must not be reported as clean.
func TestPubliclyRetrievableUnknownWhenInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	site := exposureFixture(t)
	ctx := ctxFor(site)
	ctx.Offline = false
	ctx.BaseURL = srv.URL
	ctx.Probe = proberFor(t, srv.URL)

	f := findingByID(t, runByID(t, "SENSITIVE_FILE_PUBLICLY_RETRIEVABLE", ctx), "SENSITIVE_FILE_PUBLICLY_RETRIEVABLE")
	if f.Status != StatusUnknown {
		t.Fatalf("an inconclusive server must be unknown, not passed: %+v", f)
	}
}

func TestPubliclyRetrievableSkipsOffline(t *testing.T) {
	site := exposureFixture(t)
	ctx := ctxFor(site)
	if s := statusOf(t, runByID(t, "SENSITIVE_FILE_PUBLICLY_RETRIEVABLE", ctx), "SENSITIVE_FILE_PUBLICLY_RETRIEVABLE"); s != StatusSkipped {
		t.Fatalf("offline must skip, got %s", s)
	}
}

// TestExposureProbeSetIsBoundedAndInert pins two safety properties: the probe
// list is capped, and it never contains a PHP file (probing one would execute
// it).
func TestExposureProbeSetIsBoundedAndInert(t *testing.T) {
	site := testSite(t, map[string]string{
		"wp-settings.php":       "<?php\n",
		".env":                  "x",
		"dump.sql":              "x",
		"backup.zip":            "x",
		"another-backup.tar.gz": "x",
		"wp-content/debug.log":  "x",
		"shell.php":             "<?php\n",
		"wp-content/evil.php":   "<?php\n",
	})
	got := exposureProbeSet(site)
	if len(got) > maxExposureProbes {
		t.Fatalf("probe set has %d entries, cap is %d", len(got), maxExposureProbes)
	}
	if len(got) == 0 {
		t.Fatal("expected candidates")
	}
	for _, c := range got {
		if filepath.Ext(c.rel) == ".php" {
			t.Errorf("a PHP file must never be probed: %s", c.rel)
		}
	}
	found := map[string]bool{}
	for _, c := range got {
		found[c.rel] = true
	}
	for _, want := range []string{".env", "dump.sql", "backup.zip", "wp-content/debug.log"} {
		if !found[want] {
			t.Errorf("expected %s in the probe set: %+v", want, found)
		}
	}
	// Files that are not on disk are not probed: their absence is the
	// filesystem checks' business, and probing costs the site traffic.
	writeAbsent := map[string]bool{"shell.php": true, "wp-content/evil.php": true}
	for _, c := range got {
		if writeAbsent[c.rel] {
			t.Errorf("a PHP file must never be probed: %+v", c)
		}
	}
}

// TestExposureProbeSetContentURLMapping pins the URL derivation: a content
// directory below the WordPress root has a derivable public URL and is probed;
// one outside the root has no derivable URL and must not be requested at a
// guessed path.
func TestExposureProbeSetContentURLMapping(t *testing.T) {
	inside := testSite(t, map[string]string{
		"wp-settings.php":             "<?php\n",
		"wp-config.php":               "<?php\ndefine( 'WP_CONTENT_DIR', dirname( __FILE__ ) . '/elsewhere/content' );\n",
		"elsewhere/content/debug.log": "x",
	})
	probed := false
	for _, c := range exposureProbeSet(inside) {
		if c.rel == "elsewhere/content/debug.log" {
			probed = true
		}
	}
	if !probed {
		t.Errorf("a content directory below the web root is served at its relative path and must be probed: %+v", exposureProbeSet(inside))
	}

	// Content outside the WordPress root is served (if at all) from an unknown
	// location, so the check must stay silent about it.
	root := t.TempDir()
	shared := t.TempDir()
	if err := os.MkdirAll(filepath.Join(shared, "content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "content", "debug.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for rel, content := range map[string]string{
		"wp-settings.php":         "<?php\n",
		"wp-includes/version.php": "<?php\n$wp_version = '6.4.1';\n",
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := "<?php\ndefine( 'WP_CONTENT_DIR', '" + shared + "/content' );\n"
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	site, err := wordpress.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range exposureProbeSet(site) {
		if filepath.Base(c.rel) == "debug.log" {
			t.Fatalf("a content directory outside the web root must not be probed at a guessed URL: %+v", c)
		}
	}
}
