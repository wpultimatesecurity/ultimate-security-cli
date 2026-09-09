package releases

import "testing"

func TestBuildCoreFromStableCheck(t *testing.T) {
	c := buildCore(map[string]string{
		"7.1":   "latest",
		"7.0.4": "stable",
		"6.9.7": "stable",
		"6.8.8": "stable",
	})
	if c.Latest != "7.1" {
		t.Errorf("latest = %q", c.Latest)
	}
	if got := c.Classify("7.1"); got != "latest" {
		t.Errorf("7.1 = %q, want latest", got)
	}
	if got := c.Classify("6.8.8"); got != "stable" {
		t.Errorf("6.8.8 = %q, want stable", got)
	}
	// On a maintained branch but behind its tip → insecure (missed fixes).
	if got := c.Classify("6.8.2"); got != "insecure" {
		t.Errorf("6.8.2 = %q, want insecure", got)
	}
	// Branch entirely absent → insecure.
	if got := c.Classify("5.2.26"); got != "insecure" {
		t.Errorf("5.2.26 = %q, want insecure", got)
	}
	// Unknown dev version not matching any branch → insecure is claimed
	// only for known branches; "" only when dataset empty.
	if got := (&Core{}).Classify("7.1"); got != "" {
		t.Errorf("empty core should classify unknown, got %q", got)
	}
}

func TestBuildCoreFromOffers(t *testing.T) {
	status := map[string]string{
		"7.1":   "latest",
		"7.0.4": "stable",
		"6.9.7": "stable",
	}
	c := &Core{Latest: "7.1", Status: status}
	if got := c.Classify("7.0.4"); got != "stable" {
		t.Errorf("branch tip 7.0.4 = %q, want stable", got)
	}
	if got := c.Classify("6.4.1"); got != "insecure" {
		t.Errorf("6.4.1 = %q, want insecure (branch tip 6.4.x newer)", got)
	}
}

func TestClassifyNil(t *testing.T) {
	var c *Core
	if got := c.Classify("6.8"); got != "" {
		t.Errorf("nil core = %q, want empty", got)
	}
}

func TestBranchOf(t *testing.T) {
	cases := map[string]string{
		"6.8.2":  "6.8",
		"7.1":    "7.1",
		"6.4.1":  "6.4",
		"6":      "",
		"":       "",
		"6.8-RC": "6.8",
	}
	for in, want := range cases {
		if got := branchOf(in); got != want {
			t.Errorf("branchOf(%q) = %q, want %q", in, got, want)
		}
	}
}
