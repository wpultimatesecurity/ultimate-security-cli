// Package scoring computes the deterministic security score.
//
// # Algorithm (documented, reproducible)
//
// Each failed finding contributes a weight by severity:
//
//	critical 40, high 20, medium 10, low 4, info 0.
//
// Findings are grouped by severity (rank descending, then check ID ascending
// for stability). Within one severity group the first three findings count
// at full weight; every additional finding counts at half weight. This keeps
// a dozen low-severity rows from zeroing the score while still registering
// volume.
//
//   - Category score = clamp(0, 100, 100 − Σ contributions of that category).
//   - Overall score  = clamp(0, 100, 100 − Σ contributions of all findings).
//   - Passed, skipped and unknown findings contribute nothing.
package scoring

import (
	"sort"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
)

// Result is the score for one site.
type Result struct {
	Overall    int
	Categories map[checks.Category]int
}

// Compute derives the score from findings.
func Compute(findings []checks.Finding) Result {
	var failed []checks.Finding
	for _, f := range findings {
		if f.Status == checks.StatusFailed {
			failed = append(failed, f)
		}
	}
	// Stable order: severity rank desc, then ID.
	sort.SliceStable(failed, func(i, j int) bool {
		ri, rj := failed[i].Severity.Rank(), failed[j].Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		return failed[i].ID < failed[j].ID
	})

	res := Result{Categories: map[checks.Category]int{}}
	overall := 100
	seenPerSeverity := map[checks.Severity]int{}
	for _, f := range failed {
		n := seenPerSeverity[f.Severity]
		seenPerSeverity[f.Severity] = n + 1
		w := f.Severity.Weight()
		if n >= 3 {
			w = (w + 1) / 2 // half weight, rounded up to stay integral
		}
		overall -= w
		res.Categories[f.Category] -= w
	}
	res.Overall = clamp100(overall)
	for cat, deduction := range res.Categories {
		res.Categories[cat] = clamp100(100 + deduction)
	}
	return res
}

func clamp100(v int) int {
	switch {
	case v < 0:
		return 0
	case v > 100:
		return 100
	default:
		return v
	}
}
