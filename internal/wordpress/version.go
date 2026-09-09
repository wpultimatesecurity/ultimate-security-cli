package wordpress

import (
	"fmt"
	"strconv"
	"strings"
)

// VersionCompare compares dotted version strings (WordPress/PHP/plugin style,
// e.g. "6.8.2", "8.2", "1.2.10"). It returns -1 when a < b, 0 when a == b and
// 1 when a > b. Non-numeric segments compare lexically; a missing segment is 0.
//
// This intentionally avoids a semver dependency: WordPress and PHP versions
// are simple dotted integers, and plugins occasionally use suffixes that
// semver libraries reject.
func VersionCompare(a, b string) int {
	as := splitVersion(a)
	bs := splitVersion(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := range n {
		var x, y segment
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if c := x.compare(y); c != 0 {
			return c
		}
	}
	return 0
}

type segment struct {
	num  int
	text string
}

func splitVersion(v string) []segment {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == '_' })
	out := make([]segment, 0, len(parts))
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, segment{num: n})
		} else {
			out = append(out, segment{text: strings.ToLower(p)})
		}
	}
	return out
}

func (s segment) compare(o segment) int {
	switch {
	case s.num != 0 || o.num != 0:
		if s.num != o.num {
			if s.num < o.num {
				return -1
			}
			return 1
		}
		// equal numbers; numeric beats textual ("0" vs "beta")
		if s.text == "" && o.text != "" {
			return 1
		}
		if s.text != "" && o.text == "" {
			return -1
		}
	}
	return strings.Compare(s.text, o.text)
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
