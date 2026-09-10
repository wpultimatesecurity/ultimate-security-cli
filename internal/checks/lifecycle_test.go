package checks

import (
	"testing"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/wpcli"
)

// TestPHPLifecycleTableIsCurrent is a maintenance guard: the lifecycle table
// decides whether a PHP version is reported as end-of-life, and a stale table
// reports real vulnerabilities as "supported". The test fails when the table
// has not been reviewed in a year or when its newest entry is close to
// expiring, which forces a review against php.net instead of silent rot.
func TestPHPLifecycleTableIsCurrent(t *testing.T) {
	reviewed, err := time.Parse("2006-01-02", phpLifecycleReviewed)
	if err != nil {
		t.Fatalf("phpLifecycleReviewed is not a date: %v", err)
	}
	if age := time.Since(reviewed); age > 365*24*time.Hour {
		t.Fatalf("the PHP lifecycle table was last reviewed %s (on %s); re-check php.net/supported-versions.php and update phpLifecycleReviewed",
			age.Round(24*time.Hour), phpLifecycleReviewed)
	}
	newest := ""
	var newestEOL time.Time
	for line, lc := range phpLifecycles {
		if line > newest {
			newest, newestEOL = line, lc.eol
		}
	}
	if newest == "" {
		t.Fatal("the lifecycle table is empty")
	}
	if newestEOL.Before(time.Now().AddDate(1, 0, 0)) {
		t.Fatalf("newest lifecycle entry (%s, EOL %s) expires within a year; add the newer PHP lines",
			newest, newestEOL.Format("2006-01-02"))
	}
}

// TestPHPUnknownLineIsNotAFalsePass pins the audit finding: a PHP version
// missing from the table must be reported as unknown, never as supported.
func TestPHPUnknownLineIsNotAFalsePass(t *testing.T) {
	site := testSite(t, map[string]string{"wp-settings.php": "<?php\n"})
	ctx := ctxFor(site)
	ctx.WP = &wpcli.Siteenv{PHP: "9.9.9"}
	f := findingByID(t, runByID(t, "PHP_OUTDATED", ctx), "PHP_OUTDATED")
	if f.Status != StatusUnknown {
		t.Fatalf("an unrecognised PHP line must be unknown, got %+v", f)
	}
	if f.Severity != SevInfo {
		t.Errorf("unknown PHP support must not deduct score: %s", f.Severity)
	}
}
