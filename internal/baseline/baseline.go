// Package baseline records a point-in-time inventory of a WordPress
// installation and diffs later scans against it.
//
// A point-in-time audit answers "is this site secure right now?". Operators
// usually need the operational question instead: "what changed since the last
// known-good state?". A baseline is a small JSON document capturing the
// inventory (components, drop-ins, administrators) and the fingerprints of the
// findings that were open, so a later scan can report additions, removals,
// and version moves without re-reading an old report.
//
// The file is schema-versioned and written atomically: a baseline from an
// older or newer wpus is refused rather than silently misread, and an
// interrupted write never leaves a partial file behind.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// SchemaVersion is the format version written into every baseline file. Load
// refuses anything else, because a mismatch means the fields are not the ones
// this code will read.
const SchemaVersion = "1.0"

// Baseline is the recorded state of one installation.
type Baseline struct {
	SchemaVersion string       `json:"schema_version"`
	CreatedAt     time.Time    `json:"created_at"`
	Tool          string       `json:"tool"`
	WordPress     string       `json:"wordpress"`
	Plugins       []Component  `json:"plugins"`
	Themes        []Component  `json:"themes"`
	MuPlugins     []Component  `json:"mu_plugins,omitempty"`
	Dropins       []string     `json:"dropins,omitempty"`
	Admins        []string     `json:"admins,omitempty"` // logins; only populated with --live
	Findings      []FindingRef `json:"findings"`
}

// Component is one installed plugin, theme, or must-use plugin.
type Component struct {
	Slug    string `json:"slug"`
	Version string `json:"version"`
}

// FindingRef is the stable identity of one open finding. The fingerprint is
// the identity; the ID and severity are carried so a report can name what
// appeared or was resolved without consulting the recorded report.
type FindingRef struct {
	Fingerprint string `json:"fingerprint"`
	ID          string `json:"id"`
	Severity    string `json:"severity"`
}

// Resource names a Change applies to. They are stable API for consumers.
const (
	ResourcePlugin   = "plugin"
	ResourceTheme    = "theme"
	ResourceMuPlugin = "mu-plugin"
	ResourceDropin   = "dropin"
	ResourceUser     = "user"
	ResourceFinding  = "finding"
)

// ChangeKind classifies one difference between a baseline and a snapshot.
type ChangeKind string

const (
	// ChangeComponentAdded covers plugins, themes, and MU plugins appearing.
	ChangeComponentAdded ChangeKind = "added"
	// ChangeComponentRemoved covers plugins, themes, and MU plugins gone.
	ChangeComponentRemoved ChangeKind = "removed"
	// ChangeVersionChanged is reported instead of an add/remove pair when a
	// component exists on both sides at different versions.
	ChangeVersionChanged ChangeKind = "version_changed"

	ChangeDropinAdded   ChangeKind = "dropin_added"
	ChangeDropinRemoved ChangeKind = "dropin_removed"

	ChangeAdminAdded   ChangeKind = "admin_added"
	ChangeAdminRemoved ChangeKind = "admin_removed"

	ChangeFindingAdded    ChangeKind = "finding_added"
	ChangeFindingResolved ChangeKind = "finding_resolved"
)

// Change is one difference between a baseline and a later snapshot.
type Change struct {
	Kind     ChangeKind
	Resource string // ResourcePlugin, ResourceTheme, ResourceMuPlugin, ResourceDropin, ResourceUser, ResourceFinding
	Slug     string
	From     string // previous version/severity; "" when not applicable
	To       string
	CheckID  string // set for finding changes
}

// Snapshot is the current state in the same shape as a Baseline, minus the
// metadata, so Compare only diffs two inventories.
type Snapshot struct {
	WordPress string
	Plugins   []Component
	Themes    []Component
	MuPlugins []Component
	Dropins   []string
	Admins    []string
	Findings  []FindingRef
}

// Save writes the baseline atomically: a temporary file in the destination
// directory, flushed and closed, then renamed into place. A crash or a failed
// write therefore leaves either the old file or the new one — never a
// half-written baseline that a later scan would misread.
func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("baseline: encoding %s: %w", path, err)
	}
	data = append(data, '\n')

	f, err := os.CreateTemp(filepath.Dir(path), ".wpus-baseline-*")
	if err != nil {
		return fmt.Errorf("baseline: %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			os.Remove(tmp) //nolint:errcheck // best-effort cleanup on the error path
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close() //nolint:errcheck
		return fmt.Errorf("baseline: %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("baseline: %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("baseline: %s: %w", path, err)
	}
	tmp = ""
	return nil
}

// Load reads a baseline file, rejecting a document this build does not
// understand. A missing file is an error: silently scanning without the
// requested reference state would defeat the point of asking for it.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("baseline %s: invalid JSON: %w", path, err)
	}
	if b.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("baseline %s: unsupported schema_version %q (this build writes %q)", path, b.SchemaVersion, SchemaVersion)
	}
	return &b, nil
}

// Compare diffs a baseline against a current snapshot.
//
// Ordering is deterministic (resource, then slug, then kind) so two runs over
// the same state produce byte-identical change lists. Findings are compared by
// fingerprint only, and a version change is a single ChangeVersionChanged
// rather than an add plus a remove. The result is empty, never nil, when
// nothing changed.
func Compare(old *Baseline, current *Snapshot) []Change {
	changes := []Change{}
	if old == nil || current == nil {
		return changes
	}
	changes = append(changes, compareComponents(old.Plugins, current.Plugins, ResourcePlugin)...)
	changes = append(changes, compareComponents(old.Themes, current.Themes, ResourceTheme)...)
	changes = append(changes, compareComponents(old.MuPlugins, current.MuPlugins, ResourceMuPlugin)...)
	changes = append(changes, compareSets(old.Dropins, current.Dropins, ResourceDropin, ChangeDropinAdded, ChangeDropinRemoved)...)
	changes = append(changes, compareSets(old.Admins, current.Admins, ResourceUser, ChangeAdminAdded, ChangeAdminRemoved)...)
	changes = append(changes, compareFindings(old.Findings, current.Findings)...)
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Resource != changes[j].Resource {
			return changes[i].Resource < changes[j].Resource
		}
		if changes[i].Slug != changes[j].Slug {
			return changes[i].Slug < changes[j].Slug
		}
		return changes[i].Kind < changes[j].Kind
	})
	return changes
}

// compareComponents diffs two component lists keyed by slug. A version change
// is one ChangeVersionChanged so a consumer never has to reconcile an
// add/remove pair for what is a single upgrade.
func compareComponents(old, current []Component, resource string) []Change {
	oldBySlug := make(map[string]string, len(old))
	for _, c := range old {
		oldBySlug[c.Slug] = c.Version
	}
	curBySlug := make(map[string]string, len(current))
	for _, c := range current {
		curBySlug[c.Slug] = c.Version
	}
	var changes []Change
	for slug, curVersion := range curBySlug {
		oldVersion, existed := oldBySlug[slug]
		switch {
		case !existed:
			changes = append(changes, Change{Kind: ChangeComponentAdded, Resource: resource, Slug: slug, To: curVersion})
		case oldVersion != curVersion:
			changes = append(changes, Change{Kind: ChangeVersionChanged, Resource: resource, Slug: slug, From: oldVersion, To: curVersion})
		}
	}
	for slug, oldVersion := range oldBySlug {
		if _, ok := curBySlug[slug]; !ok {
			changes = append(changes, Change{Kind: ChangeComponentRemoved, Resource: resource, Slug: slug, From: oldVersion})
		}
	}
	return changes
}

// compareSets diffs two string sets (drop-in filenames, administrator logins)
// using the caller's added/removed kinds.
func compareSets(old, current []string, resource string, added, removed ChangeKind) []Change {
	oldSet := make(map[string]bool, len(old))
	for _, s := range old {
		oldSet[s] = true
	}
	curSet := make(map[string]bool, len(current))
	for _, s := range current {
		curSet[s] = true
	}
	var changes []Change
	for s := range curSet {
		if !oldSet[s] {
			changes = append(changes, Change{Kind: added, Resource: resource, Slug: s})
		}
	}
	for s := range oldSet {
		if !curSet[s] {
			changes = append(changes, Change{Kind: removed, Resource: resource, Slug: s})
		}
	}
	return changes
}

// compareFindings diffs the open-finding sets by fingerprint. The fingerprint
// is the identity, so a rewording or a re-ordered occurrence list cannot show
// up as drift.
func compareFindings(old, current []FindingRef) []Change {
	oldByFP := make(map[string]FindingRef, len(old))
	for _, f := range old {
		oldByFP[f.Fingerprint] = f
	}
	curByFP := make(map[string]FindingRef, len(current))
	for _, f := range current {
		curByFP[f.Fingerprint] = f
	}
	var changes []Change
	for fp, f := range curByFP {
		if _, ok := oldByFP[fp]; !ok {
			changes = append(changes, Change{
				Kind: ChangeFindingAdded, Resource: ResourceFinding, Slug: fp, To: f.Severity, CheckID: f.ID,
			})
		}
	}
	for fp, f := range oldByFP {
		if _, ok := curByFP[fp]; !ok {
			changes = append(changes, Change{
				Kind: ChangeFindingResolved, Resource: ResourceFinding, Slug: fp, From: f.Severity, CheckID: f.ID,
			})
		}
	}
	return changes
}
