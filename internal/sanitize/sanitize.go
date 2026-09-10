// Package sanitize makes target-controlled text safe for a specific output
// channel.
//
// Nearly everything the scanner displays originates from the audited site:
// filesystem paths, plugin and theme names, URLs, WP-CLI stderr, and finding
// evidence. A hostile installation therefore controls bytes that are later
// rendered in the operator's terminal, in Markdown reports, and in log files.
// The redaction package removes secrets from that text but deliberately leaves
// it otherwise byte-identical, so ANSI/OSC escape sequences, newlines, bidi
// overrides, and Markdown metacharacters survive it and can restructure or
// disguise output: a plugin named "\x1b]8;;http://evil.example\x07click" is
// rendered as a trusted-looking hyperlink, and a path carrying U+202E hides
// its real extension.
//
// This package removes that capability. Each function applies the policy for
// exactly one output channel so that a call site documents where the text is
// going, and every function strips escape sequences, control characters, and
// bidi overrides before truncating so a cut can never leave a half-written
// escape sequence in the output. It complements redaction — scrub secrets
// first, then sanitize for the destination — and never replaces it.
package sanitize

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// terminalLimit bounds Terminal output at 8 KiB.
	terminalLimit = 8 * 1024
	// textLimit bounds single-line outputs (Line, Path, Log,
	// MarkdownTableCell) at 1 KiB.
	textLimit = 1024
	// markdownLimit bounds flowing Markdown text (MarkdownInline,
	// MarkdownCode) at 2 KiB.
	markdownLimit = 2 * 1024

	// truncationMarker replaces the tail of over-long input. It is a single
	// rune, so appending it can never split a multi-byte character.
	truncationMarker = "…"
)

// Escape and control code points handled by stripSequences.
const (
	esc   = '\x1b'   // ESC, introducer of every C0 escape sequence
	bel   = '\x07'   // short OSC terminator
	csiC1 = '\u009b' // 8-bit CSI
	oscC1 = '\u009d' // 8-bit OSC
	dcsC1 = '\u0090' // 8-bit DCS
	sosC1 = '\u0098' // 8-bit SOS
	pmC1  = '\u009e' // 8-bit PM
	apcC1 = '\u009f' // 8-bit APC
	stC1  = '\u009c' // 8-bit ST
)

// Terminal makes s safe for human terminal output: removes every C0/C1
// control character except \n and \t, strips ANSI/CSI/OSC/DCS/APC escape
// sequences, strips bidi override characters that can reorder displayed text,
// and caps the length. Multi-line text is preserved.
//
// Call it directly only where multi-line output is genuinely wanted; Line is
// the right choice for log lines, table cells, and other single-line slots.
func Terminal(s string) string {
	return truncate(stripSequences(s), terminalLimit)
}

// Line is Terminal plus newline/tab flattening — for single-line contexts
// (log lines, table cells, one-line evidence values). \r\n and lone \r are
// treated as line breaks, every line break or tab run collapses to one space,
// and trailing spaces are trimmed.
func Line(s string) string {
	return line(s, textLimit)
}

// Path makes a target-controlled filesystem path safe and bounded. It applies
// the single-line policy so a path containing a newline or escape sequence
// cannot forge an extra output line, and drops bidi overrides that could
// disguise the real file extension.
func Path(s string) string {
	return line(s, textLimit)
}

// Log makes subprocess/error text safe for a diagnostic log line. Untrusted
// WP-CLI stderr routinely carries ANSI colour and embedded newlines; Log
// flattens both so one tool invocation can never inject additional log lines.
func Log(s string) string {
	return line(s, textLimit)
}

// Raw strips escape sequences, control characters, and bidi overrides without
// applying a length cap. It exists for callers that have already bounded a
// value but must still never emit terminal control sequences — reporters, for
// example, which receive values sized by the scanner and must stay safe on
// their own rather than trusting the caller.
func Raw(s string) string { return stripSequences(s) }

// Text applies the single-line policy with a caller-chosen cap (in bytes).
// It exists for values that legitimately exceed the 1 KiB default — a list of
// fifty matching paths, for example — while still guaranteeing a single
// bounded, control-free line. A non-positive cap falls back to textLimit.
func Text(s string, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = textLimit
	}
	return line(s, maxBytes)
}

// MarkdownInline makes s safe inside a Markdown paragraph/heading: control
// characters removed and Markdown metacharacters that could restructure the
// document escaped (backtick, backslash, asterisk, underscore, brackets, angle
// brackets, pipe, hash at line start, and HTML-unsafe characters). Raw HTML is
// neutralised with entities (&lt;) so a crafted plugin name cannot inject
// markup, while ordinary prose, punctuation, and non-ASCII text are untouched.
func MarkdownInline(s string) string {
	s = stripSequences(s)
	var b strings.Builder
	b.Grow(len(s))
	// lineStart tracks whether only spaces/tabs have been seen since the last
	// newline, because "  # x" is still an ATX heading to CommonMark.
	lineStart := true
	var prev rune
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		next, _ := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\n':
			b.WriteRune(r)
			lineStart = true
			prev = 0 // a line break is never the left half of emphasis
			continue
		case ' ', '\t':
			// Leading whitespace does not end the line start.
			b.WriteRune(r)
			prev = r
			continue
		case '\\':
			b.WriteString(`\\`)
		case '`':
			b.WriteString("\\`")
		case '*':
			b.WriteString(`\*`)
		case '_':
			// Intraword underscores (WP_DEBUG) cannot open emphasis in
			// CommonMark, and escaping them turns every constant name in a
			// report into visual noise. Escape only where emphasis could
			// actually start or end.
			if isWordRune(prev) && isWordRune(next) {
				b.WriteRune(r)
			} else {
				b.WriteString(`\_`)
			}
		case '[':
			b.WriteString(`\[`)
		case ']':
			b.WriteString(`\]`)
		case '|':
			b.WriteString(`\|`)
		case '&':
			// Escaped before < and > so the entities emitted below are not
			// themselves double-escaped.
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '#':
			if lineStart {
				b.WriteString(`\#`)
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
		lineStart = false
		prev = r
	}
	return truncate(b.String(), markdownLimit)
}

// isWordRune reports whether r is the kind of character that makes an
// underscore intraword for CommonMark's emphasis rules.
func isWordRune(r rune) bool {
	if r == 0 {
		return false
	}
	if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
		return true
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// MarkdownCode makes s safe inside a `code span`. Backticks are replaced with
// an apostrophe so a crafted value cannot terminate the span early and inject
// Markdown after it, and angle brackets are neutralised as entities so a
// scanner report never contains an HTML-looking token an agent might act on —
// even where a renderer would treat it as literal text. Newlines and tabs are
// kept: CommonMark allows a code span to span lines, and preserving them keeps
// multi-line evidence readable.
func MarkdownCode(s string) string {
	s = stripSequences(s)
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return truncate(s, markdownLimit)
}

// MarkdownTableCell makes s safe inside a GFM table cell. Backslashes are
// escaped first, then pipes, so an injected pipe cannot open a new column, and
// newlines are flattened because a line break would split the table row.
func MarkdownTableCell(s string) string {
	s = flattenLine(normalizeNewlines(stripSequences(s)))
	// Entities first: a table cell may still contain inline HTML, and
	// "&" must not be double-escaped by the replacements below.
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	return truncate(s, textLimit)
}

// line is the single-line policy shared by Line, Path, and Log. The exported
// functions stay separate so call sites state their intent and the policies
// can diverge later without touching every caller.
func line(s string, limit int) string {
	s = normalizeNewlines(s)
	s = stripSequences(s)
	s = flattenLine(s)
	return truncate(s, limit)
}

// normalizeNewlines turns \r\n and lone \r into \n so a carriage return is
// treated as the line break it was meant to be rather than silently deleted.
func normalizeNewlines(s string) string {
	if !strings.ContainsRune(s, '\r') {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

var (
	// newlineRun matches a whitespace run containing a newline. Ordinary runs
	// of spaces are left alone so prose is not silently reflowed.
	newlineRun = regexp.MustCompile(`[ \t]*\n[ \t\n]*`)

	// tabRun matches a whitespace run containing a tab.
	tabRun = regexp.MustCompile(`[ \t]*\t[ \t]*`)
)

// flattenLine collapses every newline or tab run to a single space and trims
// trailing spaces, leaving runs of ordinary spaces untouched.
func flattenLine(s string) string {
	s = newlineRun.ReplaceAllString(s, " ")
	s = tabRun.ReplaceAllString(s, " ")
	return strings.TrimRight(s, " ")
}

// needsStripping reports whether r must not reach terminal output verbatim.
// \n and \t are the only C0 controls Terminal preserves.
func needsStripping(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case r < 0x20, r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == '\u200e', r == '\u200f', r == '\ufeff':
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// stripSequences removes escape sequences, C0/C1 controls (except \n and \t),
// bidi overrides, and the BOM. Invalid UTF-8 is replaced rather than dropped
// so the result is always valid UTF-8 and every later rune walk is safe.
//
// Sequence stripping must happen before generic control removal: deleting the
// introducer byte first would expose an OSC/DCS payload as ordinary text.
func stripSequences(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if !strings.ContainsFunc(s, needsStripping) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == esc:
			i = skipEscape(s, i+size)
		case r == csiC1:
			i = skipCSI(s, i+size)
		case r == oscC1, r == dcsC1, r == sosC1, r == pmC1, r == apcC1:
			i = skipString(s, i+size)
		case r == '\n' || r == '\t':
			b.WriteRune(r)
			i += size
		case needsStripping(r):
			i += size
		default:
			b.WriteRune(r)
			i += size
		}
	}
	return b.String()
}

// skipEscape consumes the escape sequence that begins at i, one rune past ESC,
// and returns the index of the first byte after it.
func skipEscape(s string, i int) int {
	if i >= len(s) {
		return i
	}
	r, size := utf8.DecodeRuneInString(s[i:])
	switch r {
	case '[':
		return skipCSI(s, i+size)
	case ']', 'P', 'X', '^', '_':
		return skipString(s, i+size)
	default:
		// Two-character escape such as ESC c, ESC 7, ESC =.
		return i + size
	}
}

// skipCSI consumes a CSI sequence body starting at i (just past "ESC [" or
// 8-bit CSI) and returns the index after its final byte. Parameter and
// intermediate bytes run 0x20–0x3F, the final byte 0x40–0x7E. A malformed
// sequence stops at the offending rune so the caller resumes normal scanning.
func skipCSI(s string, i int) int {
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r >= 0x40 && r <= 0x7e {
			return i + size
		}
		if r < 0x20 || r > 0x3f {
			return i
		}
		i += size
	}
	return i
}

// skipString consumes a string sequence body (OSC, DCS, SOS, PM, APC) starting
// at i just past the introducer, terminated by BEL, ST (ESC \), or 8-bit ST.
// An unterminated sequence swallows the rest of the input, which is the safe
// reading: the payload never becomes visible output.
func skipString(s string, i int) int {
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == bel, r == stC1:
			return i + size
		case r == esc:
			j := i + size
			if j < len(s) {
				if r2, size2 := utf8.DecodeRuneInString(s[j:]); r2 == '\\' {
					return j + size2
				}
			}
			return i
		default:
			i += size
		}
	}
	return i
}

// truncate bounds s to limit bytes without ever splitting a multi-byte rune.
// When it cuts, the marker replaces the tail so the result stays at or below
// the limit in both bytes and runes — a byte-bounded prefix can only ever hold
// fewer runes than its length, so one check covers both.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	budget := limit - len(truncationMarker)
	if budget < 0 {
		budget = 0
	}
	i := 0
	for i < len(s) {
		_, size := utf8.DecodeRuneInString(s[i:])
		if i+size > budget {
			break
		}
		i += size
	}
	return s[:i] + truncationMarker
}
