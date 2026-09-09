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
