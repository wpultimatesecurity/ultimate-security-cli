package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// assertNoControls fails when out still carries anything that could drive a
// terminal, a Markdown renderer, or a log reader. allowNewline/allowTab name
// the only C0 controls the caller permits.
func assertNoControls(t *testing.T, out string, allowNewline, allowTab bool) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Fatalf("output is not valid UTF-8: %q", out)
	}
	for _, r := range out {
		switch {
		case r == '\n':
			if !allowNewline {
				t.Errorf("newline survived: %q", out)
			}
		case r == '\t':
			if !allowTab {
				t.Errorf("tab survived: %q", out)
			}
		default:
			if needsStripping(r) {
				t.Errorf("control rune %U survived: %q", r, out)
			}
		}
	}
}

func TestTerminal(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "plain text", "plain text"},
		{"csi colour", "\x1b[31mred\x1b[0m", "red"},
		{"csi with params", "\x1b[1;38;5;196mx\x1b[m", "x"},
		{"osc hyperlink", "\x1b]8;;http://evil.example\x07text\x1b]8;;\x07", "text"},
		{"osc title st", "\x1b]0;title\x1b\\after", "after"},
		{"osc unterminated", "a\x1b]8;;no-terminator", "a"},
		{"8-bit csi", "\u009b31m", ""},
		{"8-bit osc", "\u009d0;title\x07after", "after"},
		{"8-bit dcs", "\u0090q\x1b\\after", "after"},
		{"dcs", "x\x1bPq#0;2;0\x1b\\y", "xy"},
		{"sos", "x\x1bXignored\x1b\\y", "xy"},
		{"pm", "x\x1b^ignored\x1b\\y", "xy"},
		{"apc", "x\x1b_ignored\x1b\\y", "xy"},
		{"single-char escape", "a\x1b7b", "ab"},
		{"dangling esc", "a\x1b", "a"},
		{"incomplete csi", "a\x1b[", "a"},
		{"newline kept", "a\nb", "a\nb"},
		{"tab kept", "a\tb", "a\tb"},
		{"carriage return dropped", "a\rb", "ab"},
		{"del", "a\x7fb", "ab"},
		{"nel", "a\u0085b", "ab"},
		{"bidi override", "a\u202Eb", "ab"},
		{"bidi mark", "a\u200Fb", "ab"},
		{"bidi isolate", "a\u2066b\u2069c", "abc"},
		{"bom", "a\uFEFFb", "ab"},
		{"invalid utf8", "a\xffb", "a\uFFFDb"},
		{"invalid utf8 run", "a\xff\xfeb", "a\uFFFDb"},
		{"non-ascii kept", "café ☕ 日本語", "café ☕ 日本語"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Terminal(tc.in)
			if got != tc.want {
				t.Errorf("Terminal(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertNoControls(t, got, true, true)
		})
	}
}

func TestTerminalPreservesEscapedTextAroundPayloads(t *testing.T) {
	// The visible text on both sides of a payload must survive intact.
	in := "prefix \x1b]8;;http://evil.example\x07click\x1b]8;;\x07 suffix\nsecond line"
	want := "prefix click suffix\nsecond line"
	if got := Terminal(in); got != want {
		t.Errorf("Terminal(%q) = %q, want %q", in, got, want)
	}
}

func TestLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "plain text", "plain text"},
		{"lf", "a\nb", "a b"},
		{"crlf", "a\r\nb", "a b"},
		{"lone cr", "a\rb", "a b"},
		{"tab", "a\tb", "a b"},
		{"tab run", "a\t\tb", "a b"},
		{"mixed run", "a  \t  b", "a b"},
		{"ordinary spaces preserved", "a  b", "a  b"},
		{"trailing spaces trimmed", "trailing  ", "trailing"},
		{"trailing newline", "line\n", "line"},
		{"blank lines", "a\n\n\nb", "a b"},
		{"multiline", "multi\nline\ntext", "multi line text"},
		{"escapes and newline", "\x1b[31mred\x1b[0m\ngreen", "red green"},
		{"bidi", "a\u202Eb", "ab"},
		{"8-bit csi", "a\u009b31mb", "ab"},
		{"osc", "\x1b]8;;http://evil.example\x07text\x1b]8;;\x07", "text"},
		{"invalid utf8", "a\xffb", "a\uFFFDb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Line(tc.in)
			if got != tc.want {
				t.Errorf("Line(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertNoControls(t, got, false, false)
		})
	}
}

func TestPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "/var/www/html/wp-config.php", "/var/www/html/wp-config.php"},
		{"spaces kept", "/var/www/my site/file.php", "/var/www/my site/file.php"},
		{"escape stripped", "/tmp/\x1b[31mevil\x1b[0m.php", "/tmp/evil.php"},
		{"newline flattened", "plugins/a\nb.php", "plugins/a b.php"},
		{"cr flattened", "plugins/a\rb.php", "plugins/a b.php"},
		{"bidi override stripped", "plugins/a\u202Eb.php", "plugins/ab.php"},
		{"backslashes kept", `C:\sites\wp`, `C:\sites\wp`},
		{"invalid utf8", "p\xffq", "p\uFFFDq"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Path(tc.in)
			if got != tc.want {
				t.Errorf("Path(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertNoControls(t, got, false, false)
		})
	}
}

func TestLog(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"wp-cli stderr", "Error: \x1b[31mCould not find\x1b[0m 'wp-config.php'\n", "Error: Could not find 'wp-config.php'"},
		{"multiline trace", "line one\r\nline two\nline three", "line one line two line three"},
		{"tab separated", "col1\tcol2", "col1 col2"},
		{"c1 controls", "a\u009bmb", "ab"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Log(tc.in)
			if got != tc.want {
				t.Errorf("Log(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertNoControls(t, got, false, false)
		})
	}
}

func TestMarkdownCode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "plain", "plain"},
		{"sql payload", "name`; DROP TABLE wp_users; --", "name'; DROP TABLE wp_users; --"},
		{"fence payload", "```", "'''"},
		{"apostrophes kept", "it's a 'test'", "it's a 'test'"},
		{"escape stripped", "a\x1b[31mb", "ab"},
		{"newline kept", "a\nb", "a\nb"},
		{"non-ascii kept", "café ☕", "café ☕"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MarkdownCode(tc.in)
			if got != tc.want {
				t.Errorf("MarkdownCode(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.ContainsRune(got, '`') {
				t.Errorf("backtick survived: %q", got)
			}
			assertNoControls(t, got, true, true)
		})
	}
}

func TestMarkdownTableCell(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "plain text", "plain text"},
		{"pipe", "a|b", `a\|b`},
		{"backslash", `a\b`, `a\\b`},
		{"backslash pipe", `a\|b`, `a\\\|b`},
		{"newline flattened", "a\nb", "a b"},
		{"crlf flattened", "a\r\nb", "a b"},
		{"tab flattened", "a\tb", "a b"},
		{"escape stripped", "a\x1b[31mb", "ab"},
		{"bidi stripped", "a\u202Eb", "ab"},
		{"invalid utf8", "a\xffb", "a\uFFFDb"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MarkdownTableCell(tc.in)
			if got != tc.want {
				t.Errorf("MarkdownTableCell(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertNoControls(t, got, false, false)
		})
	}
}

func TestMarkdownInline(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"ordinary prose", "plain prose, with punctuation!", "plain prose, with punctuation!"},
		{"non-ascii prose", "café ☕ 日本語", "café ☕ 日本語"},
		{"backtick", "a`b", "a\\`b"},
		{"backtick fence", "```", "\\`\\`\\`"},
		{"asterisk underscore", "a*b_c", `a\*b_c`},
		{"intraword underscore is left alone", "WP_DEBUG is enabled", "WP_DEBUG is enabled"},
		{"emphasis underscore is escaped", "_evil_", `\_evil\_`},
		{"underscore after space is escaped", "a _b", `a \_b`},
		{"brackets", "a[b]c", `a\[b\]c`},
		{"pipe", "a|b", `a\|b`},
		{"backslash", `C:\path`, `C:\\path`},
		{"html", "<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;/script&gt;"},
		{"ampersand", "a & b", "a &amp; b"},
		{"hash at start", "# heading", `\# heading`},
		{"hash after indent", "  # heading", `  \# heading`},
		{"hash after newline", "a\n# b", "a\n\\# b"},
		{"hash mid-line kept", "x # y", "x # y"},
		{"newline kept", "a\nb", "a\nb"},
		{"escape stripped", "a\x1b[31mb", "ab"},
		{"osc stripped", "\x1b]8;;http://evil.example\x07click\x1b]8;;\x07", "click"},
		{"bidi stripped", "a\u202Eb", "ab"},
		{"invalid utf8", "a\xffb", "a\uFFFDb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MarkdownInline(tc.in)
			if got != tc.want {
				t.Errorf("MarkdownInline(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertNoControls(t, got, true, true)
			if strings.Contains(got, "<") || strings.Contains(got, ">") {
				t.Errorf("raw angle bracket survived: %q", got)
			}
		})
	}
}

// TestCaps proves every function bounds its output on hostile input while
// never splitting a multi-byte rune.
func TestCaps(t *testing.T) {
	ascii := strings.Repeat("A", 100*1024)
	multi := strings.Repeat("é", 100*1024)
	// A payload whose escape sequence starts before the cut and would leak
	// visible text if truncation ran before stripping.
	payload := "\x1b[31m" + strings.Repeat("B", 100*1024) + "\x1b[0m"

	cases := []struct {
		name  string
		fn    func(string) string
		limit int
	}{
		{"Terminal", Terminal, terminalLimit},
		{"Line", Line, textLimit},
		{"Path", Path, textLimit},
		{"Log", Log, textLimit},
		{"MarkdownInline", MarkdownInline, markdownLimit},
		{"MarkdownCode", MarkdownCode, markdownLimit},
		{"MarkdownTableCell", MarkdownTableCell, textLimit},
	}
	for _, tc := range cases {
		for _, in := range []string{ascii, multi, payload} {
			got := tc.fn(in)
			if len(got) > tc.limit {
				t.Errorf("%s: output %d bytes exceeds cap %d", tc.name, len(got), tc.limit)
			}
			if n := utf8.RuneCountInString(got); n > tc.limit {
				t.Errorf("%s: output %d runes exceeds cap %d", tc.name, n, tc.limit)
			}
			if !strings.HasSuffix(got, truncationMarker) {
				t.Errorf("%s: truncated output %q lacks marker", tc.name, tail(got))
			}
			if !utf8.ValidString(got) {
				t.Errorf("%s: output is not valid UTF-8", tc.name)
			}
			if strings.ContainsRune(got, utf8.RuneError) {
				t.Errorf("%s: truncation split a rune", tc.name)
			}
		}
	}
}

// TestCapBoundary proves inputs at the cap are untouched and one rune over is
// cut to exactly the cap.
func TestCapBoundary(t *testing.T) {
	at := strings.Repeat("A", terminalLimit)
	if got := Terminal(at); got != at {
		t.Errorf("input at cap must be unchanged, got %d bytes", len(got))
	}
	over := strings.Repeat("A", terminalLimit+1)
	got := Terminal(over)
	if len(got) != terminalLimit {
		t.Errorf("over-cap output = %d bytes, want %d", len(got), terminalLimit)
	}
	if !strings.HasSuffix(got, truncationMarker) {
		t.Errorf("over-cap output lacks marker: %q", tail(got))
	}

	// Multi-byte input just over the cap must cut on a rune boundary.
	mb := strings.Repeat("é", textLimit)
	if got := Line(mb); len(got) > textLimit || utf8.RuneCountInString(got) > textLimit {
		t.Errorf("multi-byte cap violated: %d bytes / %d runes", len(got), utf8.RuneCountInString(got))
	}
}

// TestInvalidUTF8NeverPanics feeds every entry point malformed byte sequences;
// the result must be valid UTF-8 and must not panic.
func TestInvalidUTF8NeverPanics(t *testing.T) {
	inputs := []string{
		string([]byte{0xff, 0xfe, 'a'}),
		string([]byte{0xc3, 0x28}),
		string([]byte{0xed, 0xa0, 0x80}),
		string([]byte{0x80, 0x80, 0x80}),
		string([]byte{0xf0, 0x9f}),
		"\x1b[31m\xff\x1b]8;;\xff\x07",
	}
	fns := map[string]func(string) string{
		"Terminal":          Terminal,
		"Line":              Line,
		"Path":              Path,
		"Log":               Log,
		"MarkdownInline":    MarkdownInline,
		"MarkdownCode":      MarkdownCode,
		"MarkdownTableCell": MarkdownTableCell,
	}
	for name, fn := range fns {
		for _, in := range inputs {
			got := fn(in)
			if !utf8.ValidString(got) {
				t.Errorf("%s(%q) produced invalid UTF-8: %q", name, in, got)
			}
		}
	}
}

func tail(s string) string {
	const n = 12
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "…" + string(r[len(r)-n:])
}

// TestTextHonoursCallerCap pins the contract of the parameterized variant:
// the same single-line policy, with the caller's bound instead of the default.
func TestTextHonoursCallerCap(t *testing.T) {
	long := strings.Repeat("ab", 3000)
	got := Text(long, 4096)
	if len(got) > 4096 {
		t.Errorf("Text exceeded the caller cap: %d bytes", len(got))
	}
	if len(got) <= textLimit {
		t.Errorf("Text applied the default cap instead of the caller's: %d bytes", len(got))
	}
	if got := Text("a\nb\x1b[31m", 0); got != "a b" {
		t.Errorf("Text fallback to the default cap or single-line policy failed: %q", got)
	}
}
