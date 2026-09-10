package wordpress

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.8.2", "6.8.2", 0},
		{"6.8.2", "6.8.1", 1},
		{"6.8.1", "6.8.2", -1},
		{"6.8", "6.8.0", -1}, // PHP: a missing segment is not zero
		{"10.0", "9.9", 1},
		{"6.9", "6.10", -1}, // numeric, not lexical
		{"8.2.1", "8.2", 1},
		{"v6.5", "6.5", -1}, // PHP: "v6.5" canonicalizes to "v.6.5", unknown name < digit
		{"6.8.2.1", "6.8.2", 1},

		// PHP version_compare() reference results (PHP 8.5.10), the semantics
		// affected-version range matching depends on.
		{"1.0", "1.0-beta", 1},
		{"1.0-beta", "1.0-alpha", 1},
		{"1.0-alpha", "1.0-dev", 1},
		{"1.0-dev", "1.0", -1},
		{"1.0", "1.0.0", -1},
		{"1.0rc1", "1.0", -1},
		{"1.0pl1", "1.0", 1},
		{"1.0-RC1", "1.0rc1", 0},
		{"1.0-p1", "1.0pl1", 0},
		{"1.0beta1", "1.0-alpha1", 1},
		{"20260911", "20260910", 1},
		{"20260911", "20260912", -1},
		{"4.0000002", "4.2", 0}, // leading zeros are decimal, verified against PHP
		{"2.0.2a", "2.0.2", -1},
		{"1.0-BETA", "1.0-beta", -1}, // canonicalization preserves case
		{"1.0+meta", "1.0meta", 0},
		{"1.0_1", "1.0.1", 0},
		{"3.0b2", "3.0b10", -1},
		{"2.1.0.a", "2.1.0", -1},
		{"1.0 1", "1.0.1", -1}, // spaces are separators, "1.0.1 " != "1.0.1"
		{"12", "12.0", -1},
		{"0", "0.0", -1},
		{"1.2.3.4", "1.2.3.4", 0},
		{"1.0.0.0.0", "1.0", 1},
		{"1.0", "1.0-0", -1},
		{"", "", 0},
		{"", "1.0", -1},
		{"1.0", "", 1},
		{"#1.0", "1.0", 0}, // '#' escape hatch: taken literally, not canonicalized
		{"#1.0", "1.0.0", -1},
	}
	for _, c := range cases {
		if got := VersionCompare(c.a, c.b); got != c.want {
			t.Errorf("VersionCompare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionBetween(t *testing.T) {
	cases := []struct {
		v, from       string
		fromInclusive bool
		to            string
		toInclusive   bool
		want          bool
	}{
		{"1.2.3", "1.0.0", true, "1.2.3", true, true},
		{"1.2.3", "1.0.0", true, "1.2.3", false, false},
		{"1.2.3", "1.2.3", false, "2.0", true, false},
		{"0.9", "1.0.0", true, "2.0", true, false},
		{"5.0", "", true, "", true, true}, // open range
		{"1.5", "1.0", true, "", true, true},
		{"9.9", "", true, "2.0", true, false},
		{"1.0", "*", true, "*", true, true},

		// Ranges that only contain the right members under PHP ordering.
		{"1.0", "1.0-beta", true, "1.0", true, true},
		{"1.0-alpha", "1.0-beta", true, "2.0", true, false},
		{"1.0-beta", "1.0-beta", true, "1.0", true, true},
		{"1.0.0", "1.0", true, "1.0", true, false}, // 1.0 < 1.0.0 in PHP
		{"1.0", "1.0", true, "1.0", true, true},
	}
	for _, c := range cases {
		got := VersionBetween(c.v, c.from, c.fromInclusive, c.to, c.toInclusive)
		if got != c.want {
			t.Errorf("VersionBetween(%q,%q,%v,%q,%v) = %v, want %v",
				c.v, c.from, c.fromInclusive, c.to, c.toInclusive, got, c.want)
		}
	}
}

func TestParseVersionFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTemp(t, dir, "version.php", `<?php
$wp_version = '6.8.2';
$wp_db_version = '58975';
$required_php_version = '7.2.24';
`)
	v, db := parseVersionFile(path)
	if v != "6.8.2" {
		t.Errorf("version = %q", v)
	}
	if db != "58975" {
		t.Errorf("db version = %q", db)
	}

	missing := dir + "/nope.php"
	if v, _ := parseVersionFile(missing); v != "" {
		t.Errorf("missing file should give empty version, got %q", v)
	}
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	// Nothing there.
	if err := Validate(dir); err == nil {
		t.Error("empty dir must not validate")
	}
	// Only wp-includes/version.php — not enough.
	writeTemp(t, dir, "wp-includes/version.php", "<?php $wp_version = '6.8';")
	if err := Validate(dir); err == nil {
		t.Error("version.php alone must not validate (needs 2+ indicators)")
	}
	// Add wp-config.php and wp-admin → valid.
	writeTemp(t, dir, "wp-config.php", "<?php\n")
	if err := os.MkdirAll(dir+"/wp-admin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Validate(dir); err != nil {
		t.Errorf("expected valid, got %v", err)
	}
}

func TestLoadPluginsAndThemes(t *testing.T) {
	root := t.TempDir()
	// Directory plugin.
	plugDir := root + "/wp-content/plugins/akismet"
	if err := os.MkdirAll(plugDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, plugDir, "akismet.php", `<?php
/*
Plugin Name: Akismet Anti-spam
Version: 5.3.1
*/
`)
	// Single-file plugin.
	writeTemp(t, root+"/wp-content/plugins", "hello.php", `<?php
/*
Plugin Name: Hello Dolly
Version: 1.6
*/
`)
	// Theme.
	themeDir := root + "/wp-content/themes/twentytwentyfour"
	if err := os.MkdirAll(themeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, themeDir, "style.css", `/*
Theme Name: Twenty Twenty-Four
Version: 1.1
*/
`)

	plugins := LoadPlugins(root + "/wp-content/plugins")
	if len(plugins) != 2 {
		t.Fatalf("plugins = %d, want 2", len(plugins))
	}
	bySlug := map[string]Plugin{}
	for _, p := range plugins {
		bySlug[p.Slug] = p
	}
	if p := bySlug["akismet"]; p.Name != "Akismet Anti-spam" || p.Version != "5.3.1" {
		t.Errorf("akismet = %+v", p)
	}
	if p := bySlug["hello"]; p.Name != "Hello Dolly" || p.Version != "1.6" {
		t.Errorf("hello = %+v", p)
	}

	themes := LoadThemes(root + "/wp-content/themes")
	if len(themes) != 1 || themes[0].Name != "Twenty Twenty-Four" || themes[0].Version != "1.1" {
		t.Errorf("themes = %+v", themes)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "wp-includes/version.php", "<?php\n$wp_version = '6.4.1';\n$wp_db_version = '56657';\n")
	writeTemp(t, dir, "wp-config.php", "<?php\n$table_prefix = 'wpx_';\ndefine('DB_PASSWORD', 'hunter2secret');\n")
	site, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if site.Version != "6.4.1" {
		t.Errorf("version = %q", site.Version)
	}
	if site.Prefix != "wpx_" {
		t.Errorf("prefix = %q", site.Prefix)
	}
	if site.Config == nil || len(site.Config.SecretLiterals) == 0 {
		t.Error("config secrets should be captured")
	}
	if site.PluginsPath == "" || site.UploadsPath == "" {
		t.Error("content paths should be populated")
	}
}

// versionFixtures seeds the differential corpus. It deliberately mixes ordinary
// WordPress/PHP releases with the prerelease, separator, whitespace and '#'
// escape forms whose ordering the old hand-rolled comparison got wrong.
var versionFixtures = []string{
	"1.0", "1.0.0", "1.0-beta", "1.0beta1", "1.0-BETA", "1.0-RC1", "1.0rc2",
	"1.0-dev", "1.0-alpha1", "1.0-p1", "1.0pl2", "2.0.2a", "20260911", "4.0000002",
	"1.2.3.4", "v1.2", "1.0+meta", "1.0_1", "6.8.2", "8.2.29", "1.0.0.0.0",
	"0", "0.0", "1", "1.0-rc", "1.0RC", "3.0b2", "2.1.0.a", "1.0 1", " 1.0",
	"1.0 ", "10.0", "9.9",
	// PHP edge cases: the '#' escape hatch, empty input, repeated dots, and a
	// numeric continuation after a separator.
	"#1.0", "#N#", "#1.", "", "1..2", "1.0-0", "0.0.0", "1.0.a", "2.0 beta",
}

// versionPairCorpus builds the pairs compared against PHP: every ordered pair of
// fixtures, plus every fixture paired with each fixture mutated by a leading and
// a trailing separator/tag, so both positions of the compared strings see the
// canonicalization and tail-rule paths.
func versionPairCorpus() [][2]string {
	mutations := []string{".1", "-beta", "rc1", "+meta", "_2", " "}
	pairs := make([][2]string, 0, len(versionFixtures)*len(versionFixtures)*(1+2*len(mutations)))
	for _, a := range versionFixtures {
		for _, b := range versionFixtures {
			pairs = append(pairs, [2]string{a, b})
		}
	}
	for _, f := range versionFixtures {
		for _, m := range mutations {
			for _, g := range versionFixtures {
				pairs = append(pairs, [2]string{f + m, g}, [2]string{m + f, g})
			}
		}
	}
	return pairs
}

// TestVersionCompareMatchesPHP is the differential test: the same corpus is fed
// to VersionCompare and to a real PHP binary, and any disagreement fails. The
// whole corpus is compared in ONE `php` process because spawning thousands of
// them would dominate the runtime without adding coverage. The test skips when
// PHP is absent, which is the case on the CI image.
func TestVersionCompareMatchesPHP(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("php not on PATH: skipping differential comparison with the reference implementation")
	}
	pairs := versionPairCorpus()
	want := phpVersionCompares(t, php, pairs)

	// Guard against a degenerate corpus: if generation ever regressed to only
	// equal or only ordered pairs, the differential comparison would still pass
	// while proving much less.
	outcomes := map[int]int{}
	for _, w := range want {
		outcomes[w]++
	}
	for _, c := range []int{-1, 0, 1} {
		if outcomes[c] < 100 {
			t.Errorf("corpus is degenerate: only %d pairs returned %d", outcomes[c], c)
		}
	}
	t.Logf("corpus outcomes: -1:%d 0:%d 1:%d", outcomes[-1], outcomes[0], outcomes[1])

	mismatches := 0
	for i, p := range pairs {
		if got := VersionCompare(p[0], p[1]); got != want[i] {
			mismatches++
			if mismatches <= 20 {
				t.Errorf("VersionCompare(%q, %q) = %d, php says %d", p[0], p[1], got, want[i])
			}
		}
	}
	if mismatches > 20 {
		t.Errorf("%d more mismatches suppressed", mismatches-20)
	}
	t.Logf("compared %d pairs against php %s (%s)", len(pairs), phpVersion(t, php), php)
}

// phpVersionCompares runs the pairs through one batched PHP process. Pairs are
// passed as "a<TAB>b" lines so version strings may contain spaces; tab is safe
// because no version fixture contains one.
func phpVersionCompares(t *testing.T, php string, pairs [][2]string) []int {
	t.Helper()

	var in strings.Builder
	for _, p := range pairs {
		in.WriteString(p[0])
		in.WriteByte('\t')
		in.WriteString(p[1])
		in.WriteByte('\n')
	}

	const src = `<?php
while (($line = fgets(STDIN)) !== false) {
    [$a, $b] = explode("\t", rtrim($line, "\r\n"), 2);
    echo version_compare($a, $b), "\n";
}
`
	script := filepath.Join(t.TempDir(), "version_compare.php")
	if err := os.WriteFile(script, []byte(src), 0o600); err != nil {
		t.Fatalf("write php script: %v", err)
	}

	// -n ignores php.ini so only core functions and the default locale affect
	// the comparison, keeping the reference run deterministic.
	cmd := exec.Command(php, "-n", script)
	cmd.Stdin = strings.NewReader(in.String())
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("php %s: %v: %s", script, err, stderr.String())
	}

	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != len(pairs) {
		t.Fatalf("php printed %d results for %d pairs: %s", len(lines), len(pairs), stderr.String())
	}
	out := make([]int, len(pairs))
	for i, line := range lines {
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			t.Fatalf("php result %d = %q: %v", i, line, err)
		}
		out[i] = n
	}
	return out
}

// phpVersion reports the PHP binary's own version for the test log.
func phpVersion(t *testing.T, php string) string {
	t.Helper()
	out, err := exec.Command(php, "-n", "-r", "echo PHP_VERSION;").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}
