package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzSanitizers pins the safety properties of every output channel: no
// terminal escape survives, no control character survives, Markdown cannot be
// restructured, output stays bounded, and nothing panics on malformed UTF-8.
func FuzzSanitizers(f *testing.F) {
	seeds := []string{
		"\x1b[31mred\x1b[0m",
		"\x1b]8;;http://evil.example\x07click\x1b]8;;\x07",
		"\u009b31m",
		"a\nb",
		"name`; DROP TABLE`",
		"a|b|c",
		"```",
		"a\u202Eb",
		"\xff\xfe invalid",
		"",
		"plain",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		term := Terminal(s)
		if strings.ContainsRune(term, esc) {
			t.Fatalf("Terminal left an ESC in %q", term)
		}
		if strings.ContainsAny(term, "\x00\x07\r") {
			t.Fatalf("Terminal left a control character in %q", term)
		}
		if len(term) > 8*1024+8 {
			t.Fatalf("Terminal output is unbounded: %d bytes", len(term))
		}

		line := Line(s)
		if strings.ContainsAny(line, "\n\r\t") {
			t.Fatalf("Line is not a single line: %q", line)
		}
		if !utf8.ValidString(line) {
			t.Fatalf("Line produced invalid UTF-8 from %q", s)
		}

		cell := MarkdownTableCell(s)
		if strings.ContainsAny(cell, "\n\r") {
			t.Fatalf("a table cell must not contain a line break: %q", cell)
		}
		if strings.Contains(unquotedPipes(cell), "|") {
			t.Fatalf("a table cell leaked an unescaped pipe: %q", cell)
		}

		inline := MarkdownInline(s)
		if strings.Contains(inline, "<") || strings.Contains(inline, ">") {
			t.Fatalf("MarkdownInline leaked raw angle brackets: %q", inline)
		}

		code := MarkdownCode(s)
		if strings.Contains(code, "`") {
			t.Fatalf("a code span can be terminated early: %q", code)
		}

		for _, in := range []string{term, line, cell, inline, code, Path(s), Log(s), Raw(s)} {
			if !utf8.ValidString(in) {
				t.Fatalf("output is not valid UTF-8 for input %q", s)
			}
			if strings.ContainsRune(in, esc) {
				t.Fatalf("an escape sequence survived in %q (input %q)", in, s)
			}
		}
	})
}

// unquotedPipes strips escaped pipes so the invariant check is about
// unescaped separators only.
func unquotedPipes(s string) string {
	return strings.ReplaceAll(s, `\|`, "")
}
