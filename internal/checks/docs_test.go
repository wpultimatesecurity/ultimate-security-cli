package checks

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Documentation drift is a correctness problem for a security tool: a check
// whose documented category, importance, or existence differs from the code
// misleads whoever is reading the report or deciding what to enable. These
// tests read the published documentation and compare it with the live
// registry, so adding or re-classifying a check fails until the docs follow.

// docsRow matches one row of the registry table in docs/checks.md:
// | `ID` | category | importance | default |
var docsRow = regexp.MustCompile(`(?m)^\| ` + "`" + `([A-Z0-9_]+)` + "`" + ` \| ([a-z-]+) \| ([a-z]+) \|`)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join("..", "..", rel)
	data, err := os.ReadFile(path) //nolint:gosec // fixed repository paths
	if err != nil {
		t.Skipf("%s not readable from the test working directory: %v", rel, err)
	}
	return string(data)
}

// TestDocsRegistryMatchesCode pins docs/checks.md against the registry.
func TestDocsRegistryMatchesCode(t *testing.T) {
	doc := repoFile(t, filepath.Join("docs", "checks.md"))
	rows := map[string][2]string{}
	for _, m := range docsRow.FindAllStringSubmatch(doc, -1) {
		rows[m[1]] = [2]string{m[2], m[3]}
	}
	if len(rows) == 0 {
		t.Fatal("no registry rows parsed from docs/checks.md; the table format changed")
	}
	for _, c := range All() {
		row, ok := rows[c.ID]
		if !ok {
			t.Errorf("check %s is registered but missing from docs/checks.md", c.ID)
			continue
		}
		if row[0] != string(c.Category) {
			t.Errorf("%s: docs say category %q, code says %q", c.ID, row[0], c.Category)
		}
		if row[1] != c.Importance.String() {
			t.Errorf("%s: docs say importance %q, code says %q", c.ID, row[1], c.Importance)
		}
		delete(rows, c.ID)
	}
	for id := range rows {
		t.Errorf("docs/checks.md lists %s, which is not registered", id)
	}
}

// TestDocsStateTheRealCheckCount pins the count the docs advertise, so
// adding a check forces a documentation update instead of silently shipping a
// stale number.
func TestDocsStateTheRealCheckCount(t *testing.T) {
	want := itoa(len(All()))
	readme := repoFile(t, "README.md")
	if !strings.Contains(readme, want+" checks across") {
		t.Errorf("README.md does not state %q; update its check count", want+" checks across")
	}
}

// TestDocsRegistryListsEveryCheckInReadme pins the check list in README.md
// against the registry, so a new check cannot ship undocumented.
func TestDocsRegistryListsEveryCheckInReadme(t *testing.T) {
	readme := repoFile(t, "README.md")
	start := strings.Index(readme, "## Security checks")
	end := strings.Index(readme, "## Scoring")
	if start < 0 || end < 0 || end < start {
		t.Fatal("could not locate the check list section in README.md")
	}
	section := readme[start:end]
	var missing []string
	for _, c := range All() {
		if !strings.Contains(section, "`"+c.ID+"`") {
			missing = append(missing, c.ID)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("checks missing from the README check list: %s", strings.Join(missing, ", "))
	}
}
