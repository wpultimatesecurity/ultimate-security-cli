package reporting

import (
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/checks"
)

// SARIF 2.1.0 output for code-scanning integrations (GitHub code scanning,
// Azure DevOps, and anything else that consumes SARIF).
//
// One run per site: a SARIF run has a single originalUriBaseIds map, and
// findings are located relative to the site root, so a fleet scan stays
// unambiguous. Only failed findings are reported; a suppressed finding is
// emitted with a SARIF suppression so the accepted risk remains visible
// instead of silently disappearing.

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool              `json:"tool"`
	Invocations       []sarifInvocation      `json:"invocations,omitempty"`
	OriginalURIBaseID map[string]sarifBaseID `json:"originalUriBaseIds,omitempty"`
	Results           []sarifResult          `json:"results"`
	Properties        map[string]any         `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name,omitempty"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      *sarifText      `json:"fullDescription,omitempty"`
	HelpURI              string          `json:"helpUri,omitempty"`
	Help                 *sarifText      `json:"help,omitempty"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           map[string]any  `json:"properties,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc,omitempty"`
}

type sarifBaseID struct {
	URI string `json:"uri"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppress   `json:"suppressions,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifSuppress struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// WriteSARIF renders the report as SARIF 2.1.0.
func WriteSARIF(w io.Writer, r *Report) error {
	log := sarifLog{Schema: sarifSchema, Version: "2.1.0", Runs: make([]sarifRun, 0, len(r.Sites))}
	for _, site := range r.Sites {
		log.Runs = append(log.Runs, sarifRunFor(r, site))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifRunFor(r *Report, site SiteReport) sarifRun {
	failed := failedFindings(site.Findings)

	// Rules are the distinct check IDs that produced a result, ordered by ID
	// so repeated scans of the same site stay byte-comparable.
	index := map[string]int{}
	var ruleIDs []string
	for _, f := range failed {
		if _, ok := index[f.ID]; ok {
			continue
		}
		index[f.ID] = len(ruleIDs)
		ruleIDs = append(ruleIDs, f.ID)
	}
	sort.Strings(ruleIDs)
	for i, id := range ruleIDs {
		index[id] = i
	}

	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		f := firstFinding(failed, id)
		rule := sarifRule{
			ID:                   id,
			Name:                 id,
			ShortDescription:     sarifText{Text: f.Title},
			DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(f.Severity)},
			Properties: map[string]any{
				"category": string(f.Category),
			},
		}
		if f.Description != "" {
			rule.FullDescription = &sarifText{Text: f.Description}
		}
		if len(f.References) > 0 {
			rule.HelpURI = f.References[0]
		}
		if f.Recommendation != "" {
			rule.Help = &sarifText{Text: f.Recommendation}
		}
		rules = append(rules, rule)
	}

	results := make([]sarifResult, 0, len(failed))
	for _, f := range failed {
		res := sarifResult{
			RuleID:    f.ID,
			RuleIndex: index[f.ID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: sarifMessage(f)},
			Properties: map[string]any{
				"category":   string(f.Category),
				"severity":   string(f.Severity),
				"confidence": string(f.Confidence),
			},
		}
		if f.Fingerprint != "" {
			res.PartialFingerprints = map[string]string{"wpus/v1": f.Fingerprint}
		}
		if f.Suppressed {
			res.Suppressions = []sarifSuppress{{Kind: "external", Justification: f.SuppressionReason}}
		}
		if loc, ok := sarifLocationFor(f); ok {
			res.Locations = []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: loc}}}
		}
		results = append(results, res)
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           r.Tool.Name,
			Version:        r.Tool.Version,
			InformationURI: "https://github.com/wpultimatesecurity/ultimate-security-cli",
			Rules:          rules,
		}},
		Invocations: []sarifInvocation{{
			ExecutionSuccessful: true,
			StartTimeUTC:        r.Scan.StartedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}},
		Results: results,
		Properties: map[string]any{
			"risk_score":     site.RiskScore,
			"coverage_score": site.CoverageScore,
			"confidence":     site.Confidence,
			"wordpress":      site.WordPress,
		},
	}
	if u := fileURI(site.Path); u != "" {
		run.OriginalURIBaseID = map[string]sarifBaseID{"SITE": {URI: u}}
	}
	return run
}

// sarifMessage combines the description with the evidence an operator needs
// to act, in one bounded line.
func sarifMessage(f checks.Finding) string {
	parts := []string{f.Title}
	if f.Description != "" {
		parts = append(parts, f.Description)
	}
	if f.Recommendation != "" {
		parts = append(parts, "Recommendation: "+f.Recommendation)
	}
	return strings.Join(parts, " ")
}

// sarifLocationFor extracts a site-relative file location when the finding
// names one. Paths are evidence values, so they are only ever used as
// relative artifact URIs.
func sarifLocationFor(f checks.Finding) (sarifArtifact, bool) {
	for _, key := range []string{"file", "path"} {
		v := strings.TrimSpace(f.Evidence[key])
		if v == "" || strings.ContainsAny(v, "\x00") {
			continue
		}
		// Absolute paths would leak the operator's layout into a report that
		// is uploaded to a code-scanning service; keep the basename-relative
		// form only when the value already looks relative.
		if strings.HasPrefix(v, "/") || strings.Contains(v, ":\\") {
			continue
		}
		return sarifArtifact{URI: url.PathEscape(strings.TrimPrefix(v, "./")), URIBaseID: "SITE"}, true
	}
	return sarifArtifact{}, false
}

func firstFinding(fs []checks.Finding, id string) checks.Finding {
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	return checks.Finding{ID: id}
}

func sarifLevel(s checks.Severity) string {
	switch s {
	case checks.SevCritical, checks.SevHigh:
		return "error"
	case checks.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

// fileURI renders a directory as a file:// URI for originalUriBaseIds.
func fileURI(dir string) string {
	if dir == "" || !strings.HasPrefix(dir, "/") {
		return ""
	}
	u := url.URL{Scheme: "file", Path: strings.TrimSuffix(dir, "/") + "/"}
	return u.String()
}
