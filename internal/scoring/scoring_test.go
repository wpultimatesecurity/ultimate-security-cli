package scoring

import (
	"testing"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
)

func failed(sev checks.Severity, id string, cat checks.Category) checks.Finding {
	return checks.Finding{ID: id, Severity: sev, Status: checks.StatusFailed, Category: cat}
}

func TestEmptyScanScores100(t *testing.T) {
	if got := Compute(nil).Overall; got != 100 {
		t.Errorf("empty score = %d, want 100", got)
	}
}

func TestSingleFindingWeights(t *testing.T) {
	cases := map[checks.Severity]int{
		checks.SevCritical: 60,
		checks.SevHigh:     80,
		checks.SevMedium:   90,
		checks.SevLow:      96,
		checks.SevInfo:     100, // info findings never reduce the score
	}
	for sev, want := range cases {
		got := Compute([]checks.Finding{failed(sev, "X", checks.CatConfig)}).Overall
		if got != want {
			t.Errorf("score with one %s = %d, want %d", sev, got, want)
		}
	}
}

func TestDecayBeyondThreeFindings(t *testing.T) {
	// 3 mediums: 100 - 30 = 70. 4 mediums: 100 - 30 - 5 = 65.
	three := Compute([]checks.Finding{
		failed(checks.SevMedium, "A", checks.CatConfig),
		failed(checks.SevMedium, "B", checks.CatConfig),
		failed(checks.SevMedium, "C", checks.CatConfig),
	}).Overall
	four := Compute([]checks.Finding{
		failed(checks.SevMedium, "A", checks.CatConfig),
		failed(checks.SevMedium, "B", checks.CatConfig),
		failed(checks.SevMedium, "C", checks.CatConfig),
		failed(checks.SevMedium, "D", checks.CatConfig),
	}).Overall
	if three != 70 {
		t.Errorf("three mediums = %d, want 70", three)
	}
	if four != 65 {
		t.Errorf("four mediums = %d, want 65 (decay)", four)
	}
}

func TestVolumeOfLowFindingsDoesNotZeroScore(t *testing.T) {
	var fs []checks.Finding
	for i := range 50 {
		fs = append(fs, failed(checks.SevLow, checks.Finding{ID: ""}.ID+string(rune('A'+i%26)), checks.CatConfig))
	}
	// 26 unique IDs max; duplicates collapse via sort but scoring counts
	// each finding. Even so the floor is clamped and info never hurts.
	got := Compute(fs).Overall
	if got < 0 {
		t.Errorf("score must not go negative: %d", got)
	}
}

func TestPassedAndSkippedDoNotAffect(t *testing.T) {
	fs := []checks.Finding{
		{ID: "A", Severity: checks.SevHigh, Status: checks.StatusPassed},
		{ID: "B", Severity: checks.SevCritical, Status: checks.StatusSkipped},
	}
	if got := Compute(fs).Overall; got != 100 {
		t.Errorf("non-failed findings must not affect score, got %d", got)
	}
}

func TestCategoryScores(t *testing.T) {
	fs := []checks.Finding{
		failed(checks.SevHigh, "PLUGIN_VULN", checks.CatPlugins),
		failed(checks.SevLow, "DEBUG", checks.CatConfig),
	}
	res := Compute(fs)
	if res.Categories[checks.CatPlugins] != 80 {
		t.Errorf("plugins = %d, want 80", res.Categories[checks.CatPlugins])
	}
	if res.Categories[checks.CatConfig] != 96 {
		t.Errorf("config = %d, want 96", res.Categories[checks.CatConfig])
	}
	if res.Overall != 76 {
		t.Errorf("overall = %d, want 76", res.Overall)
	}
}

func TestDeterminism(t *testing.T) {
	fs := []checks.Finding{
		failed(checks.SevCritical, "B", checks.CatPlugins),
		failed(checks.SevMedium, "A", checks.CatConfig),
		failed(checks.SevHigh, "C", checks.CatFS),
		failed(checks.SevLow, "D", checks.CatServer),
	}
	first := Compute(fs)
	for range 20 {
		// Shuffle input order; result must be identical.
		rotated := append(append([]checks.Finding{}, fs[1:]...), fs[0])
		next := Compute(rotated)
		if next.Overall != first.Overall {
			t.Fatalf("score not deterministic: %d vs %d", next.Overall, first.Overall)
		}
		for c, v := range first.Categories {
			if next.Categories[c] != v {
				t.Fatalf("category %s not deterministic: %d vs %d", c, next.Categories[c], v)
			}
		}
	}
}

func TestClampAtZero(t *testing.T) {
	var fs []checks.Finding
	for i := range 10 {
		fs = append(fs, failed(checks.SevCritical, checks.Finding{ID: ""}.ID+string(rune('A'+i)), checks.CatConfig))
	}
	if got := Compute(fs).Overall; got != 0 {
		t.Errorf("many criticals must clamp to 0, got %d", got)
	}
}

// TestCoverageWeightsImportance pins the property that keeps a high score
// honest: a skipped high-importance check costs more coverage than a skipped
// context check, and a suppressed finding still counts as determined.
func TestCoverageWeightsImportance(t *testing.T) {
	// WP_CORE_INTEGRITY_MODIFIED is ImpCore (3), DIRECTORY_LISTING is
	// ImpContext (1). Skipping only the core check must cost 3/4 of a
	// two-check audit, not half of it.
	findings := []checks.Finding{
		{ID: "CORE_INTEGRITY_MODIFIED", Status: checks.StatusSkipped, Severity: checks.SevInfo},
		{ID: "DIRECTORY_LISTING", Status: checks.StatusPassed, Severity: checks.SevInfo},
	}
	cov := ComputeCoverage(findings)
	if cov.Score != 25 {
		t.Errorf("coverage = %d, want 25 (weight 1 of 4 determined)", cov.Score)
	}
	if len(cov.Gaps) != 1 || cov.Gaps[0].Importance != 3 {
		t.Fatalf("gaps = %+v, want the core check with importance 3", cov.Gaps)
	}

	// The mirror image: skipping the context check costs little.
	findings[0].Status, findings[1].Status = checks.StatusPassed, checks.StatusSkipped
	if got := ComputeCoverage(findings).Score; got != 75 {
		t.Errorf("coverage = %d, want 75 (weight 3 of 4 determined)", got)
	}
}

func TestCoverageConfidenceBoundaries(t *testing.T) {
	make100 := func(determined int) []checks.Finding {
		var out []checks.Finding
		for i := 0; i < 100; i++ {
			st := checks.StatusSkipped
			if i < determined {
				st = checks.StatusPassed
			}
			out = append(out, checks.Finding{ID: "WP_DEBUG_ENABLED", Status: st, Severity: checks.SevInfo})
		}
		return out
	}
	cases := []struct {
		determined int
		wantScore  int
		wantConf   checks.Confidence
	}{
		{100, 100, checks.ConfHigh},
		{90, 90, checks.ConfHigh},
		{89, 89, checks.ConfMedium},
		{70, 70, checks.ConfMedium},
		{69, 69, checks.ConfLow},
		{0, 0, checks.ConfLow},
	}
	for _, tc := range cases {
		cov := ComputeCoverage(make100(tc.determined))
		if cov.Score != tc.wantScore || cov.Confidence != string(tc.wantConf) {
			t.Errorf("%d determined: score %d (%s), want %d (%s)",
				tc.determined, cov.Score, cov.Confidence, tc.wantScore, tc.wantConf)
		}
		if cov.Total != 100 || cov.Determined != tc.determined {
			t.Errorf("%d determined: counted %d/%d", tc.determined, cov.Determined, cov.Total)
		}
	}
}

// TestSuppressedFindingsDoNotScore pins that accepting a risk removes its
// weight without removing the finding.
func TestSuppressedFindingsDoNotScore(t *testing.T) {
	f := failed(checks.SevCritical, "X", checks.CatConfig)
	if got := Compute([]checks.Finding{f}).Overall; got != 60 {
		t.Fatalf("critical finding score = %d, want 60", got)
	}
	f.Suppressed = true
	if got := Compute([]checks.Finding{f}).Overall; got != 100 {
		t.Errorf("suppressed finding still scored: %d, want 100", got)
	}
}
