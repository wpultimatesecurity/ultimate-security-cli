package wordpress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const sampleWpConfig = `<?php
/**
 * Sample config with comments that must not confuse the parser.
 */
// define( 'WP_DEBUG', true );  ← commented out, must be ignored
# define( 'DISALLOW_FILE_EDIT', true );

define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wpuser' );
define( 'DB_PASSWORD', 'S3cret!Password' );
define( 'DB_HOST', 'localhost:3306' );

define( 'AUTH_KEY',         'x1 real key value here' );
define( 'SECURE_AUTH_KEY',  'x2 real key value here' );
define( 'LOGGED_IN_KEY',    'x3 real key value here' );
define( 'NONCE_KEY',        'x4 real key value here' );
define( 'AUTH_SALT',        'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'x6 real salt value here' );
define( 'LOGGED_IN_SALT',   'x7 real salt value here' );
define( 'NONCE_SALT',       'x8 real salt value here' );

$table_prefix = 'wp_';

define( 'WP_DEBUG', true );
define( 'WP_DEBUG_DISPLAY', false );
define( 'WP_ENVIRONMENT_TYPE', 'production' );
define( 'WP_AUTO_UPDATE_CORE', 'minor' );
const WP_HOME = 'https://example.com';
const WP_SITEURL = 'https://example.com/wp';
`

func TestParseWpConfig(t *testing.T) {
	dir := t.TempDir()
	path := writeTemp(t, dir, "wp-config.php", sampleWpConfig)
	cfg := ParseWpConfig(path)
	if !cfg.Exists {
		t.Fatal("config should exist")
	}

	// Commented-out defines must be ignored.
	if v, ok := cfg.Bool("WP_DEBUG_DISPLAY"); !ok || v {
		t.Errorf("WP_DEBUG_DISPLAY = %v,%v; want false,true", v, ok)
	}
	if _, ok := cfg.Bool("DISALLOW_FILE_EDIT"); ok {
		t.Error("commented DISALLOW_FILE_EDIT must be ignored")
	}

	// Values.
	if v, _ := cfg.String("DB_NAME"); v != "wordpress" {
		t.Errorf("DB_NAME = %q", v)
	}
	if v, _ := cfg.String("WP_ENVIRONMENT_TYPE"); v != "production" {
		t.Errorf("WP_ENVIRONMENT_TYPE = %q", v)
	}
	if v, _ := cfg.String("WP_HOME"); v != "https://example.com" {
		t.Errorf("WP_HOME = %q", v)
	}
	if v, ok := cfg.Bool("WP_DEBUG"); !ok || !v {
		t.Errorf("WP_DEBUG = %v,%v; want true,true", v, ok)
	}
	if v, ok := cfg.Bool("WP_DEBUG_DISPLAY"); !ok || v {
		t.Errorf("WP_DEBUG_DISPLAY = %v,%v", v, ok)
	}
	if v, _ := cfg.String("WP_AUTO_UPDATE_CORE"); v != "minor" {
		t.Errorf("WP_AUTO_UPDATE_CORE = %q", v)
	}
	if cfg.Prefix != "wp_" {
		t.Errorf("prefix = %q", cfg.Prefix)
	}
}

func TestParseWpConfigSecretLiteralsCollected(t *testing.T) {
	dir := t.TempDir()
	path := writeTemp(t, dir, "wp-config.php", sampleWpConfig)
	cfg := ParseWpConfig(path)
	joined := ""
	for _, s := range cfg.SecretLiterals {
		joined += s + "|"
	}
	for _, want := range []string{"S3cret!Password", "wpuser", "x1 real key value here", "put your unique phrase here", "wp_"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SecretLiterals missing %q (got %q)", want, joined)
		}
	}
}

func TestKeyStates(t *testing.T) {
	dir := t.TempDir()
	path := writeTemp(t, dir, "wp-config.php", sampleWpConfig)
	cfg := ParseWpConfig(path)
	states := cfg.KeyStates()
	if states["AUTH_KEY"] != KeyPresent {
		t.Errorf("AUTH_KEY = %v, want KeyPresent", states["AUTH_KEY"])
	}
	if states["AUTH_SALT"] != KeyPlaceholder {
		t.Errorf("AUTH_SALT = %v, want KeyPlaceholder", states["AUTH_SALT"])
	}
	if states["NONCE_SALT"] != KeyPresent {
		t.Errorf("NONCE_SALT = %v, want KeyPresent", states["NONCE_SALT"])
	}

	// All-missing case.
	path2 := writeTemp(t, dir, "wp-config2.php", "<?php\ndefine( 'DB_NAME', 'x' );\n")
	cfg2 := ParseWpConfig(path2)
	if n := cfg2.DefinedSaltCount(); n != 0 {
		t.Errorf("DefinedSaltCount = %d, want 0", n)
	}
	states2 := cfg2.KeyStates()
	for k, st := range states2 {
		if st != KeyMissing {
			t.Errorf("%s = %v, want KeyMissing", k, st)
		}
	}
}

func TestParseWpConfigMissingFile(t *testing.T) {
	cfg := ParseWpConfig(filepath.Join(t.TempDir(), "nope.php"))
	if cfg.Exists {
		t.Error("missing file must report Exists=false")
	}

	if _, ok := cfg.Bool("WP_DEBUG"); ok {
		t.Error("missing file must not define constants")
	}
}

func TestPhpBool(t *testing.T) {
	cases := map[string]bool{
		"true": true, "TRUE": true, "1": true, "'1'": true, "\"1\"": true,
		"false": false, "0": false, "'0'": false, "": false, "whatever": false,
	}
	for in, want := range cases {
		if got := phpBool(in); got != want {
			t.Errorf("phpBool(%q) = %v, want %v", in, got, want)
		}
	}
}
