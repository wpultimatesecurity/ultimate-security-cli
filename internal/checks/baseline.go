package checks

import (
	"fmt"
	"sort"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/baseline"
)

// Baseline drift compares a site's current inventory and open findings with a
// baseline recorded by `wpus baseline create`, so operators can answer the
// operational question — "what became less secure since the last known-good
// state?" — instead of re-reading an old report.
//
// The check is deliberately relative: it never fails a site on its own
// merits, only on what differs from the state the operator recorded. Every
// drift finding therefore carries the caveat that an intended deployment
// looks identical to an undocumented change; the value is in the diff, not
// in the severity.

// BaselineCheckID is the drift check's stable identifier. The scan refers to
// it by name because it must run after every other check for the site.
const BaselineCheckID = "BASELINE_DRIFT"

// maxBaselineOccurrences caps the per-group occurrence list. The full count
// is always reported in evidence, so a truncated list is never mistaken for
// the whole change set.
const maxBaselineOccurrences = 25

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          BaselineCheckID,
			Title:       "Installation differs from the recorded baseline",
			Category:    CatFS,
			Description: "Compares the installation with a baseline recorded by `wpus baseline create`: plugins, themes, MU plugins, drop-ins, administrators, and open findings. Reported changes are operational signals, not verdicts — a legitimate deployment looks the same as an undocumented change, so investigate anything that cannot be attributed.",
			Importance:  ImpStandard,
		},
		Run: runBaselineDrift,
	})
}

// BaselineSnapshot returns the inventory a baseline records for this context.
// `wpus baseline create` uses it so what gets written is derived exactly the
// way the drift check derives the current state; the two can never disagree
// about what the installation consists of.
func BaselineSnapshot(ctx *Context) baseline.Snapshot {
	snap, _ := baselineSnapshot(ctx)
	return snap
}

// baselineSnapshot builds the inventory the baseline package diffs and
// reports whether administrator logins were available. Absent admin data is
// "not determined", never "no admins": a static scan cannot read the user
// table, so the caller must record it as a coverage gap.
func baselineSnapshot(ctx *Context) (baseline.Snapshot, bool) {
	site := ctx.Site
	if site == nil {
		return baseline.Snapshot{}, false
	}
	snap := baseline.Snapshot{WordPress: site.Version}
	for _, p := range site.Plugins {
		snap.Plugins = append(snap.Plugins, baseline.Component{Slug: p.Slug, Version: p.Version})
	}
	for _, t := range site.Themes {
		snap.Themes = append(snap.Themes, baseline.Component{Slug: t.Slug, Version: t.Version})
	}
	for _, p := range site.MuPlugins {
		snap.MuPlugins = append(snap.MuPlugins, baseline.Component{Slug: p.Slug, Version: p.Version})
	}
	for _, d := range site.Dropins {
		snap.Dropins = append(snap.Dropins, d.File)
	}
	sort.Slice(snap.Plugins, func(i, j int) bool { return snap.Plugins[i].Slug < snap.Plugins[j].Slug })
	sort.Slice(snap.Themes, func(i, j int) bool { return snap.Themes[i].Slug < snap.Themes[j].Slug })
	sort.Slice(snap.MuPlugins, func(i, j int) bool { return snap.MuPlugins[i].Slug < snap.MuPlugins[j].Slug })
	sort.Strings(snap.Dropins)

	if ctx.WP != nil {
		for _, u := range ctx.WP.Admins {
			if u.Login != "" {
				snap.Admins = append(snap.Admins, u.Login)
			}
		}
	}
	sort.Strings(snap.Admins)

	for _, f := range ctx.Findings {
		if f.Status != StatusFailed {
			continue // passed/skipped/unknown rows are not findings to track.
		}
		snap.Findings = append(snap.Findings, baseline.FindingRef{
			Fingerprint: findingFingerprint(f), ID: f.ID, Severity: string(f.Severity),
		})
	}
	sort.Slice(snap.Findings, func(i, j int) bool {
		return snap.Findings[i].Fingerprint < snap.Findings[j].Fingerprint
	})
	return snap, len(snap.Admins) > 0
}

// findingFingerprint prefers the fingerprint the policy stage already computed
// and derives it only for findings the scan has not annotated yet — the drift
// check runs before policy is applied.
func findingFingerprint(f Finding) string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	return f.ComputeFingerprint()
}

func runBaselineDrift(ctx *Context) []Finding {
	m := Meta{ID: BaselineCheckID, Title: "Installation differs from the recorded baseline", Category: CatFS}
	if ctx.Baseline == nil {
		return []Finding{m.skipf("no --baseline supplied")}
	}
	b := ctx.Baseline
	evidence := map[string]string{
		"baseline_schema_version": b.SchemaVersion,
		"baseline_created_at":     b.CreatedAt.UTC().Format(time.RFC3339),
	}
	if ctx.Site == nil {
		f := m.skipf("no site loaded")
		for k, v := range evidence {
			f.Evidence[k] = v
		}
		return []Finding{f}
	}

	snap, adminsKnown := baselineSnapshot(ctx)
	// Compare against a baseline whose admin list is dropped when no live
	// user data is available: a static scan cannot read the user table, so
	// reporting every recorded administrator as "removed" would be a lie.
	ref := b
	if !adminsKnown {
		stripped := *b
		stripped.Admins = nil
		ref = &stripped
		evidence["admins"] = "not collected: requires --live WP-CLI data, so user changes are not compared"
		ctx.AddGap("baseline drift: administrator accounts were not collected (requires --live), so user changes are not compared")
	}

	changes := baseline.Compare(ref, &snap)
	if len(changes) == 0 {
		return []Finding{{
			ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
			Description: "The installation matches the recorded baseline: no component, drop-in, administrator, version, or open finding changed.",
			Evidence:    evidence,
		}}
	}

	// One finding per change kind, so a report reader sees "what kind of
	// thing moved" first and the individual items as occurrences. Ordered by
	// severity so the actionable groups come first.
	groups := map[baseline.ChangeKind][]baseline.Change{}
	for _, c := range changes {
		groups[c.Kind] = append(groups[c.Kind], c)
	}
	kinds := make([]baseline.ChangeKind, 0, len(groups))
	for k := range groups {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool {
		ri, rj := driftSeverity(kinds[i]).Rank(), driftSeverity(kinds[j]).Rank()
		if ri != rj {
			return ri > rj
		}
		return kinds[i] < kinds[j]
	})

	out := make([]Finding, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, driftFinding(m, kind, groups[kind], evidence))
	}
	return out
}

// driftFinding renders one change kind as a single finding with one
// occurrence per changed item.
func driftFinding(m Meta, kind baseline.ChangeKind, changes []baseline.Change, baseEvidence map[string]string) Finding {
	evidence := make(map[string]string, len(baseEvidence)+3)
	for k, v := range baseEvidence {
		evidence[k] = v
	}
	evidence["change"] = string(kind)
	evidence["changes"] = itoa(len(changes))

	shown := changes
	if len(shown) > maxBaselineOccurrences {
		shown = shown[:maxBaselineOccurrences]
		evidence["occurrences_omitted"] = itoa(len(changes) - maxBaselineOccurrences)
	}
	occ := make([]Occurrence, 0, len(shown))
	for _, c := range shown {
		occ = append(occ, Occurrence{ResourceType: c.Resource, Slug: c.Slug, Detail: changeDetail(c)})
	}

	return Finding{
		ID: m.ID, Title: m.Title, Category: m.Category,
		Severity: driftSeverity(kind), Status: StatusFailed, Confidence: ConfHigh,
		Description:    driftDescription(kind, len(changes)),
		Evidence:       evidence,
		Occurrences:    occ,
		Recommendation: "Confirm each change belongs to an intended deployment; investigate anything you cannot attribute to a known plugin, host, or team action.",
	}
}

// driftSeverity maps a change kind to how much attention it deserves. Additions
// are medium because an attacker's persistence and a legitimate release look
// the same; version moves are low; removals and resolved findings inform.
func driftSeverity(kind baseline.ChangeKind) Severity {
	switch kind {
	case baseline.ChangeComponentAdded, baseline.ChangeDropinAdded,
		baseline.ChangeAdminAdded, baseline.ChangeFindingAdded:
		return SevMedium
	case baseline.ChangeVersionChanged:
		return SevLow
	default:
		return SevInfo
	}
}

func driftDescription(kind baseline.ChangeKind, n int) string {
	switch kind {
	case baseline.ChangeComponentAdded:
		return fmt.Sprintf("%d plugin/theme/MU-plugin component(s) appeared since the baseline. A legitimate deployment looks the same; the signal is in whether the change is documented.", n)
	case baseline.ChangeComponentRemoved:
		return fmt.Sprintf("%d component(s) recorded in the baseline are gone.", n)
	case baseline.ChangeVersionChanged:
		return fmt.Sprintf("%d component(s) changed version since the baseline — updates and downgrades both look like this.", n)
	case baseline.ChangeDropinAdded:
		return fmt.Sprintf("%d drop-in file(s) appeared since the baseline. Drop-ins execute at privileged bootstrap points and are a persistence location, but cache and security plugins install them legitimately.", n)
	case baseline.ChangeDropinRemoved:
		return fmt.Sprintf("%d drop-in file(s) recorded in the baseline are gone.", n)
	case baseline.ChangeAdminAdded:
		return fmt.Sprintf("%d administrator account(s) appeared since the baseline. A new admin is the highest-signal drift there is, but a handover or a new team member looks identical.", n)
	case baseline.ChangeAdminRemoved:
		return fmt.Sprintf("%d administrator account(s) recorded in the baseline are gone.", n)
	case baseline.ChangeFindingAdded:
		return fmt.Sprintf("%d finding(s) are new since the baseline — either the installation changed or the vulnerability data was updated.", n)
	case baseline.ChangeFindingResolved:
		return fmt.Sprintf("%d finding(s) recorded in the baseline are no longer reported.", n)
	default:
		return fmt.Sprintf("%d change(s) since the baseline.", n)
	}
}

// changeDetail renders the from→to note an occurrence carries, because the
// occurrence's slug alone does not say what moved.
func changeDetail(c baseline.Change) string {
	switch c.Kind {
	case baseline.ChangeVersionChanged:
		return c.From + " → " + c.To
	case baseline.ChangeFindingAdded:
		return fmt.Sprintf("finding %s (%s) is new", c.CheckID, c.To)
	case baseline.ChangeFindingResolved:
		return fmt.Sprintf("finding %s (%s) was resolved", c.CheckID, c.From)
	case baseline.ChangeComponentAdded, baseline.ChangeDropinAdded, baseline.ChangeAdminAdded:
		if c.To != "" {
			return "added, version " + c.To
		}
		return "added"
	default:
		if c.From != "" {
			return "removed, was version " + c.From
		}
		return "removed"
	}
}
