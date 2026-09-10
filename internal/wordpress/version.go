package wordpress

import (
	"fmt"
	"math"
	"strings"
)

// VersionCompare compares two version strings with the same algorithm as PHP's
// version_compare() (ext/standard/versioning.c: php_canonicalize_version() plus
// php_version_compare()). It returns -1 when a < b, 0 when a == b and 1 when
// a > b.
//
// WHY the PHP algorithm verbatim: WordPress core, plugins and themes version
// themselves the way PHP orders them, and the affected-version ranges this
// scanner matches against (Wordfence/WPScan advisories) were authored with the
// same ordering. An ad-hoc dotted-integer comparison mishandles prerelease
// syntax - it reports "1.0" < "1.0-beta" where PHP reports "1.0" > "1.0-beta" -
// and every such inversion silently drops a vulnerable version from the report.
//
// The rules callers must keep in mind:
//
//   - a missing trailing segment is NOT zero: "1.0" < "1.0.0";
//   - prerelease names rank dev < alpha=a < beta=b < RC=rc < # < pl=p, so
//     "1.0" > "1.0-beta" > "1.0-alpha" > "1.0-dev" and "1.0rc1" < "1.0";
//   - numeric segments compare numerically with decimal leading zeros ignored
//     ("10.0" > "9.9", "4.0000002" == "4.2"); a digit segment facing a name
//     segment compares that name against the "#N#" placeholder;
//   - canonicalization folds '-', '_' and '+' into '.', splits digit/letter
//     boundaries and turns any other non-alphanumeric byte into '.', but keeps
//     case ("1.0-BETA" < "1.0-beta");
//   - a leading '#' is PHP's escape hatch: that string is compared literally;
//   - the empty string sorts before any non-empty version.
func VersionCompare(a, b string) int { return phpVersionCompare(a, b) }

// phpVersionCompare is a direct port of php_version_compare(). It is kept
// separate from the exported wrapper so the recursive tail rule below can reuse
// it without re-documenting the public contract.
func phpVersionCompare(orig1, orig2 string) int {
	// PHP special-cases literal empty input before canonicalization, so
	// version_compare("", "0") is -1 while version_compare(".", "0") is also -1
	// but for an unrelated reason (canonicalization of "." yields "").
	if orig1 == "" || orig2 == "" {
		switch {
		case orig1 == "" && orig2 == "":
			return 0
		case orig1 != "":
			return 1
		default:
			return -1
		}
	}

	// A leading '#' escapes canonicalization: the string is used verbatim.
	ver1 := orig1
	if orig1[0] != '#' {
		ver1 = canonicalizeVersion(orig1)
	}
	ver2 := orig2
	if orig2[0] != '#' {
		ver2 = canonicalizeVersion(orig2)
	}

	// p1/p2 are the unconsumed suffixes, mirroring C's p1/p2 pointers; has1/has2
	// mirror whether the previous segment was dot-terminated (C's n1/n2 != NULL).
	// Unlike C, Go strings are immutable, so cutVersionSegment slices instead of
	// writing NUL over the dot.
	p1, p2 := ver1, ver2
	has1, has2 := true, true
	compare := 0
	for p1 != "" && p2 != "" && has1 && has2 {
		seg1, next1, more1 := cutVersionSegment(p1)
		seg2, next2, more2 := cutVersionSegment(p2)
		switch {
		case startsWithDigit(seg1) && startsWithDigit(seg2):
			// Numeric vs numeric: strtol semantics, so leading zeros drop out.
			compare = normalizeBool64(strtolVersion(seg1) - strtolVersion(seg2))
		case !startsWithDigit(seg1) && !startsWithDigit(seg2):
			compare = compareSpecialVersionForms(seg1, seg2)
		default:
			// Mixed names and digits: the numeric side stands in for "#N#",
			// which ranks between "rc" and "pl".
			if startsWithDigit(seg1) {
				compare = compareSpecialVersionForms("#N#", seg2)
			} else {
				compare = compareSpecialVersionForms(seg1, "#N#")
			}
		}
		if compare != 0 {
			break
		}
		if more1 {
			p1 = next1
		}
		if more2 {
			p2 = next2
		}
		has1, has2 = more1, more2
	}

	// Tail rule: one side ran out of segments. A digit continuation is newer
	// than a name continuation, and a name continuation is judged against the
	// "#N#" placeholder (hence "1.0" < "1.0.0" but "1.0" > "1.0-beta").
	if compare == 0 {
		switch {
		case has1:
			if startsWithDigit(p1) {
				compare = 1
			} else {
				compare = phpVersionCompare(p1, "#N#")
			}
		case has2:
			if startsWithDigit(p2) {
				compare = -1
			} else {
				compare = phpVersionCompare("#N#", p2)
			}
		}
	}
	return compare
}

// cutVersionSegment returns the segment of s up to the first '.', the suffix
// after that dot, and whether a dot was found. Without a dot the whole string
// is the segment and the suffix is s itself, mirroring php_version_compare()
// leaving p1 in place when strchr() returns NULL.
func cutVersionSegment(s string) (seg, rest string, hadDot bool) {
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, s, false
}

// canonicalizeVersion is a byte-for-byte port of php_canonicalize_version().
// It exists because the whole comparison rests on PHP's notion of a segment:
// the first byte is copied verbatim, then '-'/'_'/'+' become '.' (unless the
// previous output byte already is one), an alphanumeric/non-alphanumeric
// transition inserts '.', every other non-alphanumeric byte becomes '.', and a
// trailing dot is dropped. Case is preserved on purpose - PHP's table lookup is
// case-sensitive, so "1.0-BETA" and "1.0-beta" are different versions.
func canonicalizeVersion(v string) string {
	if v == "" {
		return ""
	}
	buf := make([]byte, 0, 2*len(v))
	buf = append(buf, v[0])
	prev := v[0] // C's lp: previous input byte
	for i := 1; i < len(v); i++ {
		c := v[i]
		last := buf[len(buf)-1] // C's lq: last emitted byte
		switch {
		case c == '-' || c == '_' || c == '+':
			if last != '.' {
				buf = append(buf, '.')
			}
		case (isVersionDigit(prev) != isVersionDigit(c)) && prev != '.' && c != '.':
			// digit <-> non-digit transition, e.g. "1beta" -> "1.beta"
			if last != '.' {
				buf = append(buf, '.')
			}
			buf = append(buf, c)
		case !isVersionAlnum(c):
			if last != '.' {
				buf = append(buf, '.')
			}
		default:
			buf = append(buf, c)
		}
		prev = c
	}
	// A trailing dot means PHP's "last component is empty", so drop it: "." and
	// "..." canonicalize to the empty string. buf always holds at least v[0].
	if len(buf) > 0 && buf[len(buf)-1] == '.' {
		buf = buf[:len(buf)-1]
	}
	return string(buf)
}

// specialVersionForm is one row of PHP's ordered table. Order matters: the
// first row whose name is a prefix of the segment wins, so "beta1" ranks as
// "beta" (before "b") and "alpha" before "a".
type specialVersionForm struct {
	name  string
	order int
}

var specialVersionForms = [...]specialVersionForm{
	{"dev", 0},
	{"alpha", 1},
	{"a", 1},
	{"beta", 2},
	{"b", 2},
	{"RC", 3},
	{"rc", 3},
	{"#", 4},
	{"pl", 5},
	{"p", 5},
}

// compareSpecialVersionForms ports compare_special_version_forms(): unknown
// names rank -1 so any recognised form outranks them, and the result is
// normalized to -1/0/1 because callers only ever branch on its sign.
func compareSpecialVersionForms(form1, form2 string) int {
	return normalizeBool(specialVersionOrder(form1) - specialVersionOrder(form2))
}

// specialVersionOrder returns the table order of form, or -1 when no row is a
// prefix of it. Prefix matching (strncmp) is deliberate: "beta1", "rc2" and
// "p1" all rank as their base form.
func specialVersionOrder(form string) int {
	for _, f := range specialVersionForms {
		if strings.HasPrefix(form, f.name) {
			return f.order
		}
	}
	return -1
}

// strtolVersion mirrors strtol(s, NULL, 10) for the digit-led segments the
// comparison loop feeds it: leading ASCII digits are consumed and an
// overflowing value saturates at MaxInt64, exactly as libc reports LONG_MAX.
// PHP compares such saturated values, so a segment wider than 64 bits must not
// wrap around here.
func strtolVersion(s string) int64 {
	var n int64
	for i := 0; i < len(s) && isVersionDigit(s[i]); i++ {
		d := int64(s[i] - '0')
		if n > (math.MaxInt64-d)/10 {
			return math.MaxInt64
		}
		n = n*10 + d
	}
	return n
}

// normalizeBool ports ZEND_NORMALIZE_BOOL for the int64 difference of two
// strtol results: only the sign survives.
func normalizeBool64(n int64) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	default:
		return 0
	}
}

// normalizeBool is normalizeBool64 for the small int differences used by the
// special-form table, keeping those call sites free of casts.
func normalizeBool(n int) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	default:
		return 0
	}
}

// startsWithDigit reports whether s begins with an ASCII digit, C's
// isdigit((unsigned char)*p). It guards the index so canonicalization's empty
// output ("." and "..." collapse to "") cannot panic.
func startsWithDigit(s string) bool { return s != "" && isVersionDigit(s[0]) }

// isVersionDigit mirrors C's isdig(): ASCII digits only, so the comparison is
// independent of locale.
func isVersionDigit(c byte) bool { return c >= '0' && c <= '9' }

// isVersionAlnum mirrors C's isalnum() in the C locale. Bytes >= 0x80 are not
// letters here, matching PHP treating them as separators.
func isVersionAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// VersionBetween reports whether v is within [from, to] respecting
// inclusivity flags. Empty bounds are open.
func VersionBetween(v string, from string, fromInclusive bool, to string, toInclusive bool) bool {
	if from != "" && from != "*" {
		c := VersionCompare(v, from)
		if c < 0 || (c == 0 && !fromInclusive) {
			return false
		}
	}
	if to != "" && to != "*" {
		c := VersionCompare(v, to)
		if c > 0 || (c == 0 && !toInclusive) {
			return false
		}
	}
	return true
}

func FormatVersion(major, minor int) string {
	return fmt.Sprintf("%d.%d", major, minor)
}
