package wordpress

import (
	"os"
	"path/filepath"
	"strings"
)

// Layout is the resolved on-disk shape of an installation.
//
// WordPress lets a site move or rename wp-content, the plugin directory, the
// MU-plugin directory, and uploads; it also accepts wp-config.php one
// directory above the installation. Assuming the default layout therefore
// produces false "clean" results on a perfectly ordinary hardened site (and
// misses plugins entirely). Every path here is either resolved from the
// site's own configuration or reported as unresolved — never guessed.
type Layout struct {
	Root string
	// ConfigPath is where wp-config.php was found; ConfigParent is true when
	// it sits one directory above Root.
	ConfigPath   string
	ConfigParent bool

	ContentPath   string
	PluginsPath   string
	MuPluginsPath string
	UploadsPath   string
	ThemesPath    string

	// Sources name where each path came from: "default" or the constant that
	// overrode it. They are evidence in the report, not decoration.
	ContentSource   string
	PluginsSource   string
	MuPluginsSource string
	UploadsSource   string

	// Unresolved lists configured path constants that could not be evaluated
	// statically. A non-empty list is a coverage gap: the corresponding tree
	// was not examined.
	Unresolved []string
}

// Custom reports whether any path differs from the WordPress default layout.
func (l Layout) Custom() bool {
	return l.ContentSource != "default" || l.PluginsSource != "default" ||
		l.MuPluginsSource != "default" || l.UploadsSource != "default"
}

// resolveLayout derives the installation's directory layout from a statically
// parsed wp-config.php.
func resolveLayout(root string, cfg *WpConfig) Layout {
	l := Layout{
		Root:            root,
		ContentSource:   "default",
		PluginsSource:   "default",
		MuPluginsSource: "default",
		UploadsSource:   "default",
	}
	l.ConfigPath, l.ConfigParent = findConfig(root)

	env := pathEnv{dir: root}
	if l.ConfigPath != "" {
		env.file = l.ConfigPath
		env.dir = filepath.Dir(l.ConfigPath)
	}
	// ABSPATH is what relative path constants resolve against. WordPress
	// itself defines it as dirname(__FILE__) . '/', but a site may point it
	// elsewhere, so evaluate the site's own definition when it is resolvable.
	env.abspath = env.dir
	if raw, ok := cfg.Defines["ABSPATH"]; ok {
		if v, ok := evalPathExpr(raw, env); ok {
			v = strings.TrimSuffix(v, "/")
			if v != "" {
				env.abspath = v
			}
		}
	}

	l.ContentPath = resolveDir(cfg, "WP_CONTENT_DIR", filepath.Join(root, "wp-content"), &env, &l.ContentSource, &l.Unresolved)
	l.PluginsPath = resolveDir(cfg, "WP_PLUGIN_DIR", filepath.Join(l.ContentPath, "plugins"), &env, &l.PluginsSource, &l.Unresolved)
	l.MuPluginsPath = resolveDir(cfg, "WPMU_PLUGIN_DIR", filepath.Join(l.ContentPath, "mu-plugins"), &env, &l.MuPluginsSource, &l.Unresolved)
	l.UploadsPath = resolveUploads(cfg, &env, l, &l.UploadsSource, &l.Unresolved)
	l.ThemesPath = filepath.Join(l.ContentPath, "themes")
	return l
}

// findConfig locates wp-config.php: in the installation root, or — as
// WordPress itself allows — one directory above it.
func findConfig(root string) (path string, parent bool) {
	direct := filepath.Join(root, "wp-config.php")
	if _, err := statFile(direct); err == nil {
		return direct, false
	}
	up := filepath.Join(filepath.Dir(root), "wp-config.php")
	if _, err := statFile(up); err == nil {
		return up, true
	}
	return direct, false
}

// resolveDir evaluates one path constant, falling back to the default and
// recording the constant as unresolved when the expression cannot be
// statically evaluated.
func resolveDir(cfg *WpConfig, constant, def string, env *pathEnv, source *string, unresolved *[]string) string {
	raw, ok := cfg.Defines[constant]
	if !ok {
		*source = "default"
		return def
	}
	v, ok := evalPathExpr(raw, *env)
	if !ok || v == "" {
		*unresolved = append(*unresolved, constant)
		*source = constant + " (unresolved)"
		return def
	}
	*source = constant
	return absDir(v, env.abspath)
}

// resolveUploads handles the UPLOADS constant, which unlike the others is a
// path relative to ABSPATH and is ignored on multisite.
func resolveUploads(cfg *WpConfig, env *pathEnv, l Layout, source *string, unresolved *[]string) string {
	raw, ok := cfg.Defines["UPLOADS"]
	if !ok {
		*source = "default"
		return filepath.Join(l.ContentPath, "uploads")
	}
	v, ok := evalPathExpr(raw, *env)
	if !ok || v == "" {
		*unresolved = append(*unresolved, "UPLOADS")
		*source = "UPLOADS (unresolved)"
		return filepath.Join(l.ContentPath, "uploads")
	}
	*source = "UPLOADS"
	return absDir(v, env.abspath)
}

// absDir makes a resolved path absolute and cleans it. Relative results are
// relative to ABSPATH, matching how WordPress resolves these constants.
func absDir(p, abspath string) string {
	p = strings.TrimSuffix(strings.TrimSpace(p), "/")
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(abspath, p)
	}
	if abs, err := filepath.Abs(p); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(p)
}

// statFile is a tiny indirection that keeps the layout resolver testable.
func statFile(path string) (os.FileInfo, error) { return os.Stat(path) }

// pathEnv is the evaluation environment for path expressions.
type pathEnv struct {
	file    string // __FILE__
	dir     string // __DIR__
	abspath string // ABSPATH
}

// maxPathExpr bounds how much configuration text is evaluated.
const maxPathExpr = 4096

// evalPathExpr evaluates the restricted PHP subset that real wp-config.php
// files use for path constants:
//
//	string literals ('x' or "x")
//	__FILE__, __DIR__, ABSPATH
//	dirname( <expr> )
//	concatenation with "."
//
// Anything else — function calls, variables, ternaries, constants we do not
// model — makes the expression unresolvable, which the caller reports as a
// coverage gap instead of guessing a path. The file is never executed.
func evalPathExpr(expr string, env pathEnv) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || len(expr) > maxPathExpr {
		return "", false
	}
	p := &exprParser{src: expr, env: env}
	v, ok := p.parseConcat()
	if !ok {
		return "", false
	}
	p.skipSpace()
	if !p.done() {
		return "", false // trailing junk: not a plain path expression
	}
	return v, true
}

type exprParser struct {
	src string
	pos int
	env pathEnv
}

func (p *exprParser) done() bool { return p.pos >= len(p.src) }

func (p *exprParser) skipSpace() {
	for !p.done() && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t' || p.src[p.pos] == '\n' || p.src[p.pos] == '\r') {
		p.pos++
	}
}

// parseConcat parses  term { "." term } .
func (p *exprParser) parseConcat() (string, bool) {
	left, ok := p.parseTerm()
	if !ok {
		return "", false
	}
	for {
		p.skipSpace()
		if p.done() || p.src[p.pos] != '.' {
			return left, true
		}
		// A "." followed by another "." would be a concatenation of the next
		// term; PHP has no other use for "." here.
		p.pos++
		right, ok := p.parseTerm()
		if !ok {
			return "", false
		}
		left += right
	}
}

// parseTerm parses a string literal, a known constant, or dirname( expr ).
func (p *exprParser) parseTerm() (string, bool) {
	p.skipSpace()
	if p.done() {
		return "", false
	}
	switch c := p.src[p.pos]; {
	case c == '\'' || c == '"':
		return p.parseLiteral(c)
	case isIdentStart(c):
		ident := p.parseIdent()
		p.skipSpace()
		if !p.done() && p.src[p.pos] == '(' && ident == "DIRNAME" {
			p.pos++ // consume '('
			inner, ok := p.parseConcat()
			if !ok {
				return "", false
			}
			p.skipSpace()
			if p.done() || p.src[p.pos] != ')' {
				return "", false
			}
			p.pos++ // consume ')'
			return dirnameOf(inner), true
		}
		switch ident {
		case "__FILE__":
			return p.env.file, true
		case "__DIR__":
			return p.env.dir, true
		case "ABSPATH":
			return p.env.abspath, true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

// parseLiteral reads a single- or double-quoted PHP string. Escape sequences
// are honoured only for the quote character and the backslash itself, which
// is all a real path constant needs.
func (p *exprParser) parseLiteral(quote byte) (string, bool) {
	p.pos++ // opening quote
	var b strings.Builder
	for !p.done() {
		c := p.src[p.pos]
		switch c {
		case '\\':
			if p.pos+1 < len(p.src) {
				next := p.src[p.pos+1]
				if next == quote || next == '\\' {
					b.WriteByte(next)
					p.pos += 2
					continue
				}
			}
			b.WriteByte(c)
			p.pos++
		case quote:
			p.pos++ // closing quote
			return b.String(), true
		default:
			b.WriteByte(c)
			p.pos++
		}
	}
	return "", false // unterminated literal
}

func (p *exprParser) parseIdent() string {
	start := p.pos
	for !p.done() && isIdentChar(p.src[p.pos]) {
		p.pos++
	}
	return strings.ToUpper(p.src[start:p.pos])
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// dirnameOf mirrors PHP's dirname() for the paths used in wp-config.php.
func dirnameOf(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Dir(strings.TrimSuffix(p, "/"))
}
