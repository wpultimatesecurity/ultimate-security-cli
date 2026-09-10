// Package scoring computes the deterministic security score and the scan
// coverage score.
//
// # Risk score (documented, reproducible)
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
//   - Risk score     = clamp(0, 100, 100 − Σ contributions of all findings).
//   - Passed, skipped, unknown and suppressed findings contribute nothing.
//
// # Coverage score
//
// Risk alone is misleading: "100/100" can mean "everything checked and
// clean" or "most checks never ran". Coverage answers the second question as
// the share of check weight that reached a conclusion (passed or failed),
// weighted by each check's importance. A site is never presented as secure
// without also stating how much of the audit actually ran.
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

// Compute derives the risk score from findings.
func Compute(findings []checks.Finding) Result {
	var failed []checks.Finding
	for _, f := range findings {
		if f.Status == checks.StatusFailed && !f.Suppressed {
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

// Gap is one check that could not reach a conclusion, with the reason it
// reported.
type Gap struct {
	CheckID string `json:"check_id"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	// Importance is the coverage weight the check carried.
	Importance int `json:"importance"`
}

// Coverage reports how much of the audit actually ran.
type Coverage struct {
	// Score is the weighted share of check weight that reached a conclusion.
	Score int `json:"score"`
	// Determined and Total count checks, not weight (for display).
	Determined int `json:"checks_determined"`
	Total      int `json:"checks_total"`
	// Confidence summarizes the score: high, medium, or low.
	Confidence string `json:"confidence"`
	// Gaps lists every check that did not reach a conclusion, most important
	// first, so the reason for a low score is visible.
	Gaps []Gap `json:"gaps,omitempty"`

	// Filesystem examination accounting. A walk that stopped early means even
	// a "no matches" result is a lower bound.
	FilesWalked          int    `json:"files_walked,omitempty"`
	WalkTruncated        bool   `json:"walk_truncated,omitempty"`
	WalkTruncationReason string `json:"walk_truncation_reason,omitempty"`
	UnreadableEntries    int    `json:"unreadable_entries,omitempty"`
	SymlinksSkipped      int    `json:"symlinks_skipped,omitempty"`
}

// ComputeCoverage derives the coverage score from the findings of one site.
func ComputeCoverage(findings []checks.Finding) Coverage {
	cov := Coverage{}
	weightTotal := 0
	weightDetermined := 0
	for _, f := range findings {
		w := checks.ImportanceOf(f.ID).Weight()
		weightTotal += w
		cov.Total++
		if f.Status.Determined() {
			weightDetermined += w
			cov.Determined++
			continue
		}
		cov.Gaps = append(cov.Gaps, Gap{
			CheckID:    f.ID,
			Status:     string(f.Status),
			Reason:     gapReason(f),
			Importance: w,
		})
	}
	if weightTotal == 0 {
		cov.Score = 100
		cov.Confidence = string(checks.ConfHigh)
		return cov
	}
	cov.Score = int(float64(weightDetermined)/float64(weightTotal)*100 + 0.5)
	// Sort gaps by importance desc, then ID, for a stable and useful report.
	sort.SliceStable(cov.Gaps, func(i, j int) bool {
		if cov.Gaps[i].Importance != cov.Gaps[j].Importance {
			return cov.Gaps[i].Importance > cov.Gaps[j].Importance
		}
		return cov.Gaps[i].CheckID < cov.Gaps[j].CheckID
	})
	cov.Confidence = string(coverageConfidence(cov.Score))
	return cov
}

func gapReason(f checks.Finding) string {
	if f.Evidence == nil {
		return ""
	}
	return f.Evidence["reason"]
}

func coverageConfidence(score int) checks.Confidence {
	switch {
	case score >= 90:
		return checks.ConfHigh
	case score >= 70:
		return checks.ConfMedium
	default:
		return checks.ConfLow
	}
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
