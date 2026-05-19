package pages

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/api"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/messages"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type settingsTab int

const (
	tabExport settingsTab = iota
	tabImport
	tabTree
	tabActions
)

type SettingsPage struct {
	deps         messages.PageDeps
	options      api.OptionsResult
	tab          settingsTab
	loading      bool
	exported     *api.SettingsExport
	importResult *api.SettingsImportResult
	treeKeys     []string
	treeCursor   int
	search       string
	width        int
	height       int
}

func NewSettingsPage() *SettingsPage {
	return &SettingsPage{}
}

func (p *SettingsPage) SetDeps(deps messages.PageDeps) {
	p.deps = deps
}

func (p *SettingsPage) Init() tea.Cmd {
	return p.loadOptions()
}

func (p *SettingsPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		p.width = msg.Width
		p.height = msg.Height
	case tea.KeyPressMsg:
		switch msg.String() {
		case "1":
			p.tab = tabExport
		case "2":
			p.tab = tabImport
		case "3":
			p.tab = tabTree
		case "4":
			p.tab = tabActions
		case "e":
			return p, p.exportSettings()
		case "up", "k":
			if p.treeCursor > 0 {
				p.treeCursor--
			}
		case "down", "j":
			if p.treeCursor < len(p.treeKeys)-1 {
				p.treeCursor++
			}
		}
	case messages.OptionsLoadedMsg:
		if msg.Err == nil {
			p.options = msg.Options
			p.buildTreeKeys()
		}
		p.loading = false
	case messages.SettingsExportedMsg:
		if msg.Err == nil {
			p.exported = msg.Export
		}
	case messages.SettingsImportedMsg:
		if msg.Err == nil {
			p.importResult = msg.Result
		}
	}
	return p, nil
}

func (p SettingsPage) View() tea.View {
	var b strings.Builder

	tabs := []string{"[1] Export", "[2] Import", "[3] Raw Settings", "[4] Actions"}
	for i, t := range tabs {
		if settingsTab(i) == p.tab {
			b.WriteString(theme.ActiveTabStyle.Render(t))
		} else {
			b.WriteString(theme.InactiveTabStyle.Render(t))
		}
		b.WriteString("  ")
	}
	b.WriteString("\n\n")

	switch p.tab {
	case tabExport:
		b.WriteString(p.renderExport())
	case tabImport:
		b.WriteString(p.renderImport())
	case tabTree:
		b.WriteString(p.renderTree())
	case tabActions:
		b.WriteString(p.renderActions())
	}

	return tea.NewView(b.String())
}

func (p SettingsPage) renderExport() string {
	var b strings.Builder
	b.WriteString(theme.TitleStyle.Render("Export Settings"))
	b.WriteString("\n\n")
	if p.exported != nil {
		b.WriteString(fmt.Sprintf("Plugin: %s\n", p.exported.PluginVersion))
		b.WriteString(fmt.Sprintf("Exported: %s\n", p.exported.ExportedAt))
		b.WriteString(fmt.Sprintf("Version: %s\n", p.exported.Version))
		b.WriteString("\n")
		data, _ := json.MarshalIndent(p.exported.Settings, "", "  ")
		b.WriteString(theme.StatusMutedStyle.Render(string(data)))
	} else {
		b.WriteString(theme.LabelStyle.Render("Press <e> to export settings"))
	}
	return b.String()
}

func (p SettingsPage) renderImport() string {
	var b strings.Builder
	b.WriteString(theme.TitleStyle.Render("Import Settings"))
	b.WriteString("\n\n")
	if p.importResult != nil {
		if p.importResult.DryRun {
			b.WriteString(theme.StatusWarnStyle.Render("DRY RUN PREVIEW"))
			b.WriteString("\n\n")
			for path, change := range p.importResult.Changes {
				b.WriteString(fmt.Sprintf("  %s: %s\n", path, change.Action))
			}
			if len(p.importResult.Warnings) > 0 {
				b.WriteString("\nWarnings:\n")
				for _, w := range p.importResult.Warnings {
					b.WriteString(theme.StatusWarnStyle.Render("  - " + w + "\n"))
				}
			}
			if len(p.importResult.Errors) > 0 {
				b.WriteString("\nErrors:\n")
				for _, e := range p.importResult.Errors {
					b.WriteString(theme.StatusErrStyle.Render("  - " + e + "\n"))
				}
			}
		}
	} else {
		b.WriteString(theme.StatusMutedStyle.Render("Import not yet implemented in this view"))
	}
	return b.String()
}

func (p SettingsPage) renderTree() string {
	var b strings.Builder
	b.WriteString(theme.TitleStyle.Render("Raw Settings"))
	b.WriteString("\n\n")
	if p.loading {
		b.WriteString(theme.StatusMutedStyle.Render("Loading..."))
		return b.String()
	}
	if len(p.treeKeys) == 0 {
		b.WriteString(theme.StatusMutedStyle.Render("No settings loaded"))
		return b.String()
	}

	visible := p.treeKeys
	end := p.treeCursor + 20
	if end > len(visible) {
		end = len(visible)
	}
	start := p.treeCursor
	if start > end {
		start = end
	}

	for i := start; i < end; i++ {
		prefix := "  "
		if i == p.treeCursor {
			prefix = theme.ActiveTabStyle.Render("► ")
		}
		b.WriteString(fmt.Sprintf("%s%s\n", prefix, p.treeKeys[i]))
	}

	if len(p.treeKeys) > 20 {
		b.WriteString(fmt.Sprintf("\n%d of %d keys\n", p.treeCursor+1, len(p.treeKeys)))
	}
	return b.String()
}

func (p SettingsPage) renderActions() string {
	var b strings.Builder
	b.WriteString(theme.TitleStyle.Render("Actions"))
	b.WriteString("\n\n")
	b.WriteString("  • Reset all settings (destructive)\n")
	b.WriteString("  • Purge cache\n")
	b.WriteString("  • Clear cache\n")
	b.WriteString("\n")
	b.WriteString(theme.StatusErrStyle.Render("These actions affect the remote WordPress site."))
	return b.String()
}

func (p *SettingsPage) buildTreeKeys() {
	p.treeKeys = nil
	if p.options == nil {
		return
	}
	p.treeKeys = flattenMap("", p.options)
	sort.Strings(p.treeKeys)
}

func flattenMap(prefix string, m map[string]interface{}) []string {
	var keys []string
	for k, v := range m {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		if isRedacted(k) {
			keys = append(keys, fullKey+": ****")
		} else {
			switch val := v.(type) {
			case map[string]interface{}:
				keys = append(keys, flattenMap(fullKey, val)...)
			default:
				keys = append(keys, fmt.Sprintf("%s: %v", fullKey, val))
			}
		}
	}
	return keys
}

func isRedacted(key string) bool {
	lower := strings.ToLower(key)
	for _, pattern := range []string{"password", "secret", "token", "api_key", "webhook"} {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (p SettingsPage) loadOptions() tea.Cmd {
	return func() tea.Msg {
		p.loading = true
		if p.deps.API == nil {
			return messages.OptionsLoadedMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewOptionsService(p.deps.API)
		opts, err := svc.GetOptions(p.deps.Ctx, "")
		return messages.OptionsLoadedMsg{Options: opts, Err: err}
	}
}

func (p SettingsPage) exportSettings() tea.Cmd {
	return func() tea.Msg {
		if p.deps.API == nil {
			return messages.SettingsExportedMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewSettingsService(p.deps.API)
		exp, err := svc.Export(p.deps.Ctx, false)
		return messages.SettingsExportedMsg{Export: exp, Err: err}
	}
}
