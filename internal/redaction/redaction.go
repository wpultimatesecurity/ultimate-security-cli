// Package redaction is the central, mandatory sanitizer for everything that
// leaves the process. Checks should never put secrets in evidence in the first
// place, but no finding reaches a reporter without passing through Redact —
// so a careless check cannot leak credentials, salts, or tokens.
package redaction

import (
	"regexp"
	"sort"
	"strings"
)

// secretValues holds exact secret strings observed while parsing a site
// (wp-config defines, environment secrets). They are replaced wherever they
// appear in output.
type Scrubber struct {
	// literals are exact strings to replace (sorted longest-first).
	literals []string
	// placeholder is the replacement token.
	placeholder string
}

const placeholder = "[REDACTED]"

// NewScrubber returns a scrubber that removes the given exact secret values
// from any text it processes. Empty values are ignored. Values shorter than
// 4 characters are ignored to avoid mangling ordinary text.
func NewScrubber(secrets ...string) *Scrubber {
	s := &Scrubber{}
	seen := make(map[string]bool, len(secrets))
	for _, v := range secrets {
		if len(v) < 4 || seen[v] {
			continue
		}
		seen[v] = true
		s.literals = append(s.literals, v)
	}
	// Longest first so overlapping secrets are fully removed.
	sort.Slice(s.literals, func(i, j int) bool { return len(s.literals[i]) > len(s.literals[j]) })
	return s
}

var (
	// bearerToken matches Authorization: Bearer/Basic header values.
	bearerToken = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[a-z0-9\-._~+/=]{8,}`)

	// secretAssignment matches key=value / key: value shapes whose key
	// contains a sensitive word (password, secret, token, api_key, ...).
	secretAssignment = regexp.MustCompile(
		`(?i)\b[\w.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|credential|private[_-]?key)[\w.-]*["']?\s*[:=]\s*["']?[^\s"',;&}]{4,}`)

	// privateKeyBlock matches PEM key material.
	privateKeyBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)

	// longHex matches long hexadecimal blobs (session tokens, hashes of secrets).
	longHex = regexp.MustCompile(`\b[a-f0-9]{40,}\b`)

	// applicationPassword matches WP app passwords with their spaced format.
	applicationPassword = regexp.MustCompile(`\b[a-zA-Z]{4}(?: [a-zA-Z]{4}){4,7}\b`)
)

// Scrub applies every redaction rule to s and returns safe text.
func (sc *Scrubber) Scrub(s string) string {
	if s == "" {
		return s
	}
	for _, lit := range sc.literals {
		s = strings.ReplaceAll(s, lit, placeholder)
	}
	s = privateKeyBlock.ReplaceAllString(s, placeholder)
	s = bearerToken.ReplaceAllString(s, "$1 "+placeholder)
	s = applicationPassword.ReplaceAllStringFunc(s, func(m string) string {
		// Only redact if some secret literal has the same spaced layout;
		// otherwise leave ordinary text ("New Site Login") alone.
		flat := strings.ReplaceAll(m, " ", "")
		for _, lit := range sc.literals {
			if strings.ReplaceAll(lit, " ", "") == flat {
				return placeholder
			}
		}
		return m
	})
	s = secretAssignment.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.IndexAny(m, "=:")
		return m[:i+1] + " " + placeholder
	})
	s = longHex.ReplaceAllString(s, placeholder)
	return s
}

// Map scrubs every value of a string map, returning a new map.
func (sc *Scrubber) Map(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[sc.Scrub(k)] = sc.Scrub(v)
	}
	return out
}

// Slice scrubs every element of a string slice.
func (sc *Scrubber) Slice(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = sc.Scrub(v)
	}
	return out
}
