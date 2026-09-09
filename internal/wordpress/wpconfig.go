package wordpress

import (
	"os"
	"regexp"
	"strings"
)

// WpConfig is the result of statically parsing wp-config.php.
//
// Parsing is lexical only: comments are stripped and define()/const/
// $table_prefix statements are matched with regular expressions. The file is
// never executed or included, so hostile or malformed PHP cannot run.
//
// Values are kept as raw PHP literal text. Secret values (salts, DB password)
// are held here for internal comparisons only; they are exported to the
// redaction scrubber and never serialized.
type WpConfig struct {
	Path    string
	Exists  bool
	Mode    uint32
	Size    int64
	Defines map[string]string // constant name -> raw literal (e.g. `true`, `'6.8'`)
	Prefix  string            // $table_prefix without quotes

	// SecretLiterals collects values that must never appear in output.
	SecretLiterals []string
}

var (
	phpCommentLine  = regexp.MustCompile(`(?m)^\s*(//|#).*$`)
	phpCommentBlock = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reDefine        = regexp.MustCompile(`\bdefine\s*\(\s*['"]([A-Za-z0-9_]+)['"]\s*,\s*([^;]*?)\s*\)\s*;`)
	reConst         = regexp.MustCompile(`\bconst\s+([A-Z0-9_]+)\s*=\s*([^;]+);`)
	rePrefix        = regexp.MustCompile(`\$table_prefix\s*=\s*['"]([^'"]*)['"]`)
	// quotedString extracts a single- or double-quoted literal.
	quotedString = regexp.MustCompile(`^\s*('([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")`)
)

// secretNames are constants whose values must never leave the process.
var secretNames = map[string]bool{
	"DB_PASSWORD": true, "DB_USER": true, "DB_HOST": true, "DB_NAME": true,
	"AUTH_KEY": true, "SECURE_AUTH_KEY": true, "LOGGED_IN_KEY": true, "NONCE_KEY": true,
	"AUTH_SALT": true, "SECURE_AUTH_SALT": true, "LOGGED_IN_SALT": true, "NONCE_SALT": true,
}

// ParseWpConfig statically parses the file at path. A missing or unreadable
// file yields a WpConfig with Exists=false (checks report that state).
func ParseWpConfig(path string) *WpConfig {
	cfg := &WpConfig{Path: path, Defines: map[string]string{}}
	st, err := os.Stat(path)
	if err != nil {
		return cfg
	}
	cfg.Exists = true
	cfg.Size = st.Size()
	cfg.Mode = uint32(st.Mode().Perm())
	if st.Size() > 1<<20 { // wp-config files are small; refuse absurd inputs
		return cfg
	}
	data, err := os.ReadFile(path) //nolint:gosec // site under audit
	if err != nil {
		return cfg
	}
	return cfg.parse(string(data))
}

func (c *WpConfig) parse(src string) *WpConfig {
	src = phpCommentBlock.ReplaceAllString(src, " ")
	src = phpCommentLine.ReplaceAllString(src, " ")

	for _, m := range reDefine.FindAllStringSubmatch(src, -1) {
		c.set(m[1], m[2])
	}
	for _, m := range reConst.FindAllStringSubmatch(src, -1) {
		c.set(m[1], m[2])
	}
	if m := rePrefix.FindStringSubmatch(src); m != nil {
		c.Prefix = m[1]
		if c.Prefix != "" {
			c.SecretLiterals = append(c.SecretLiterals, c.Prefix) // low sensitivity, but not output material
		}
	}
	return c
}

func (c *WpConfig) set(name, raw string) {
	raw = strings.TrimSpace(raw)
	if !looksLikeConstantName(name) {
		return
	}
	if _, dup := c.Defines[name]; !dup {
		c.Defines[name] = raw
	}
	if secretNames[name] {
		if q := quotedString.FindStringSubmatch(raw); q != nil {
			if q[2] != "" {
				c.SecretLiterals = append(c.SecretLiterals, q[2])
			} else if q[3] != "" {
				c.SecretLiterals = append(c.SecretLiterals, q[3])
			}
		}
	}
}

// Has reports whether the constant is defined at all.
func (c *WpConfig) Has(name string) bool {
	_, ok := c.Defines[name]
	return ok
}

// Bool returns the boolean value of a constant and whether it was defined.
// PHP truthiness for the literals wp-config uses: true/1 → true, false/0 → false.
func (c *WpConfig) Bool(name string) (val, found bool) {
	raw, ok := c.Defines[name]
	if !ok {
		return false, false
	}
	return phpBool(raw), true
}

// String returns the unquoted string value of a constant.
func (c *WpConfig) String(name string) (string, bool) {
	raw, ok := c.Defines[name]
	if !ok {
		return "", false
	}
	if q := quotedString.FindStringSubmatch(raw); q != nil {
		if q[2] != "" {
			return q[2], true
		}
		return q[3], true
	}
	return strings.Trim(raw, `'"`), true
}

// KeyState describes one authentication key/salt constant.
type KeyState int

const (
	KeyMissing KeyState = iota
	KeyPlaceholder
	KeyPresent
)

// KeyStates classifies the 8 authentication key/salt constants.
func (c *WpConfig) KeyStates() map[string]KeyState {
	const placeholderText = "put your unique phrase here"
	out := map[string]KeyState{}
	for _, k := range []string{
		"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
		"AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT",
	} {
		raw, ok := c.Defines[k]
		switch {
		case !ok:
			out[k] = KeyMissing
		default:
			if v, isStr := c.String(k); isStr && strings.EqualFold(strings.TrimSpace(v), placeholderText) {
				out[k] = KeyPlaceholder
			} else if strings.TrimSpace(raw) == "" {
				out[k] = KeyMissing
			} else {
				out[k] = KeyPresent
			}
		}
	}
	return out
}

// DefinedSaltCount counts present (non-placeholder) salts.
func (c *WpConfig) DefinedSaltCount() int {
	n := 0
	for _, st := range c.KeyStates() {
		if st == KeyPresent {
			n++
		}
	}
	return n
}
