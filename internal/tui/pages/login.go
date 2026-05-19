package pages

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/api"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/messages"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/components"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type LoginPage struct {
	deps     messages.PageDeps
	options  api.OptionsResult
	dirty    map[string]interface{}
	loading  bool
	saving   bool
	cursor   int
	sections []loginSection
	width    int
	height   int
	unsaved  *components.UnsavedIndicator
}

type loginSection struct {
	key   string
	title string
}

func NewLoginPage() *LoginPage {
	return &LoginPage{
		unsaved: components.NewUnsavedIndicator(),
	}
}

func (p *LoginPage) SetDeps(deps messages.PageDeps) {
	p.deps = deps
}

func (p *LoginPage) Init() tea.Cmd {
	return p.loadOptions()
}

func (p *LoginPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		p.width = msg.Width
		p.height = msg.Height
	case tea.KeyPressMsg:
		switch msg.String() {
		case "r":
			return p, p.loadOptions()
		case "ctrl+s":
			if len(p.dirty) > 0 {
				return p, p.saveOptions()
			}
		}
	case messages.OptionsLoadedMsg:
		if msg.Err == nil {
			p.options = msg.Options
			p.dirty = make(map[string]interface{})
			p.parseSections()
		}
		p.loading = false
	case messages.OptionsSavedMsg:
		p.saving = false
		if msg.Err == nil {
			p.dirty = make(map[string]interface{})
			return p, p.loadOptions()
		}
	}
	return p, nil
}

func (p LoginPage) View() tea.View {
	var b strings.Builder

	b.WriteString(theme.TitleStyle.Render("Login Protection"))
	if p.unsaved != nil {
		p.unsaved.SetDirty(len(p.dirty) > 0)
		b.WriteString(" ")
		b.WriteString(p.unsaved.View())
	}
	b.WriteString("\n\n")

	if p.loading {
		b.WriteString(theme.StatusMutedStyle.Render("Loading settings..."))
		return tea.NewView(b.String())
	}

	if p.options == nil {
		b.WriteString(theme.StatusMutedStyle.Render("No settings loaded"))
		return tea.NewView(b.String())
	}

	b.WriteString(p.renderSections())
	b.WriteString("\n")
	b.WriteString(theme.LabelStyle.Render("<ctrl+s> save  <r> refresh  <esc> discard"))

	return tea.NewView(b.String())
}

func (p LoginPage) renderSections() string {
	var b strings.Builder

	for i, sec := range p.sections {
		if i == p.cursor {
			b.WriteString(theme.ActiveTabStyle.Render("► " + sec.title))
		} else {
			b.WriteString("  " + theme.StatusMutedStyle.Render(sec.title))
		}
		b.WriteString("\n")

		data := p.getSectionData(sec.key)
		if data != nil {
			b.WriteString(p.renderSettings(data, "    "))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func (p LoginPage) getSectionData(key string) map[string]interface{} {
	if p.options == nil {
		return nil
	}
	security, ok := p.options["security"].(map[string]interface{})
	if !ok {
		return nil
	}
	section, ok := security[key].(map[string]interface{})
	if !ok {
		return nil
	}
	return section
}

func (p LoginPage) renderSettings(data map[string]interface{}, indent string) string {
	var b strings.Builder
	for k, v := range data {
		b.WriteString(indent)
		b.WriteString(theme.LabelStyle.Render(k))
		b.WriteString(": ")
		switch val := v.(type) {
		case bool:
			if val {
				b.WriteString(theme.StatusOKStyle.Render("enabled"))
			} else {
				b.WriteString(theme.StatusMutedStyle.Render("disabled"))
			}
		case map[string]interface{}:
			b.WriteString("\n")
			b.WriteString(p.renderSettings(val, indent+"  "))
		default:
			b.WriteString(theme.ValueStyle.Render(fmt.Sprintf("%v", val)))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (p *LoginPage) parseSections() {
	p.sections = nil
	if p.options == nil {
		return
	}
	security, ok := p.options["security"].(map[string]interface{})
	if !ok {
		return
	}
	known := []struct{ key, title string }{
		{"login_security", "Custom Login URL"},
		{"login_limit", "Login Attempts"},
		{"password_policies", "Password Policy"},
		{"ip_blocking", "IP Blocking"},
	}
	for _, s := range known {
		if _, exists := security[s.key]; exists {
			p.sections = append(p.sections, loginSection{key: s.key, title: s.title})
		}
	}
}

func (p LoginPage) loadOptions() tea.Cmd {
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

func (p LoginPage) saveOptions() tea.Cmd {
	return func() tea.Msg {
		p.saving = true
		if p.deps.API == nil {
			return messages.OptionsSavedMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewOptionsService(p.deps.API)
		result, err := svc.SaveOptions(p.deps.Ctx, map[string]interface{}{
			"security": p.dirty,
		})
		return messages.OptionsSavedMsg{Result: result, Err: err}
	}
}
