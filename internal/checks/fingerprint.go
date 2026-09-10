package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// fingerprintBytes is the number of digest bytes kept for a fingerprint.
// Eight bytes make collisions negligible for a report-sized finding set while
// keeping identifiers readable in CI annotations and diffs.
const fingerprintBytes = 8

// HashFingerprint derives a stable short identifier from identity parts.
//
// Inputs are sorted and NUL-joined before hashing, so a finding's fingerprint
// depends on what it is about — not on the order the occurrences were
// discovered in, the wording of a description, or the line a check sits on.
func HashFingerprint(parts []string) string {
	sorted := make([]string, 0, len(parts))
	for _, p := range parts {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\x00")))
	return hex.EncodeToString(sum[:fingerprintBytes])
}
