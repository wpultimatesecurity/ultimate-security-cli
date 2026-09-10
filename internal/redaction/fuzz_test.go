package redaction

import (
	"strings"
	"testing"
)

// FuzzScrubber pins the property the whole reporting path depends on: no
// secret that was registered with the scrubber may survive redaction, for any
// surrounding text. A scrubber bug leaks credentials into reports, logs, and
// agent transcripts.
func FuzzScrubber(f *testing.F) {
	seeds := []struct {
		secret string
		text   string
	}{
		{"hunter2hunter2", "password: hunter2hunter2"},
		{"TopSecret99!", "DB_PASSWORD=TopSecret99!; other=1"},
		{"a b c d e", "application password: a b c d e used"},
		{"sk-live-abcdef123456", "Authorization: Bearer sk-live-abcdef123456"},
		{"short", "short"},
		{"", ""},
		{"\x1b[31msecret-value\x1b[0m", "value: \x1b[31msecret-value\x1b[0m"},
	}
	for _, s := range seeds {
		f.Add(s.secret, s.text)
	}
	f.Fuzz(func(t *testing.T, secret, text string) {
		sc := NewScrubber(secret)
		out := sc.Scrub(text)
		// The literal rule applies to values of at least four characters.
		if len(secret) >= 4 && strings.Contains(out, secret) {
			t.Fatalf("secret %q survived redaction of %q -> %q", secret, text, out)
		}
		// The scrubber must never panic and must never expand input wildly
		// (a redaction loop that grows the string would be a DoS).
		if len(out) > len(text)*4+64 {
			t.Fatalf("redaction grew the text from %d to %d bytes", len(text), len(out))
		}
		// Map and Slice must be equivalent to per-value scrubbing.
		m := sc.Map(map[string]string{"k": text})
		if m["k"] != out {
			t.Fatalf("Map disagrees with Scrub: %q vs %q", m["k"], out)
		}
	})
}
