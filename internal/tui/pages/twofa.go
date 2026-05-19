package pages

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/api"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/messages"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type providerCard struct {
	name     string
	enabled  bool
	expanded bool
	secret   string
	qrURI    string
	status   string
}

type TFAPage struct {
	deps      messages.PageDeps
	status    *api.TFAStatus
	provider  *api.TFAProviderStatus
	cards     map[string]*providerCard
	cursor    int
	cardOrder []string
	loading   bool
	width     int
	height    int
}

func NewTFAPage() *TFAPage {
	return &TFAPage{}
}

func (p *TFAPage) SetDeps(deps messages.PageDeps) {
	p.deps = deps
}

func (p *TFAPage) Init() tea.Cmd {
	return tea.Batch(
		p.loadStatus(),
		p.loadProvider(),
	)
}

func (p *TFAPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		p.width = msg.Width
		p.height = msg.Height
	case tea.KeyPressMsg:
		switch msg.String() {
		case "up", "k":
			if p.cursor > 0 {
				p.cursor--
			}
		case "down", "j":
			if p.cursor < len(p.cardOrder)-1 {
				p.cursor++
			}
		case "enter":
			if len(p.cardOrder) > 0 && p.cursor < len(p.cardOrder) {
				name := p.cardOrder[p.cursor]
				if card, ok := p.cards[name]; ok {
					card.expanded = !card.expanded
				}
			}
		case "r":
			return p, tea.Batch(p.loadStatus(), p.loadProvider())
		}
	case messages.TFAStatusMsg:
		if msg.Err == nil {
			p.status = msg.Status
		}
	case messages.TFAProviderMsg:
		if msg.Err == nil {
			p.provider = msg.Status
		}
		p.loading = false
	case messages.TFAEmailStatusMsg:
		if msg.Err == nil && msg.Status != nil {
			if p.cards == nil {
				p.cards = make(map[string]*providerCard)
			}
			p.cards["email"] = &providerCard{
				name:    "Email",
				enabled: msg.Status.Enabled,
				status:  msg.Status.Email,
			}
			p.updateCardOrder()
		}
	case messages.TFAGenericStatusMsg:
	case messages.TFASecretMsg:
		if msg.Err == nil && msg.Result != nil {
			// Don't store secret in logs
		}
	}
	return p, nil
}

func (p TFAPage) View() tea.View {
	var b strings.Builder

	b.WriteString(theme.TitleStyle.Render("2FA Management"))
	b.WriteString("\n\n")

	if p.status != nil {
		status := "disabled"
		style := theme.StatusMutedStyle
		if p.status.Enabled {
			status = "enabled"
			style = theme.StatusOKStyle
		}
		b.WriteString("2FA: ")
		b.WriteString(style.Render(status))
		if p.status.Provider != "" {
			b.WriteString(" (")
			b.WriteString(theme.ValueStyle.Render(p.status.Provider))
			b.WriteString(")")
		}
		b.WriteString("\n\n")
	}

	if p.loading {
		b.WriteString(theme.StatusMutedStyle.Render("Loading 2FA status..."))
		return tea.NewView(b.String())
	}

	if len(p.cardOrder) == 0 {
		p.initDefaultCards()
	}

	for i, name := range p.cardOrder {
		card, ok := p.cards[name]
		if !ok {
			card = &providerCard{name: name}
		}

		prefix := "  "
		if i == p.cursor {
			prefix = theme.ActiveTabStyle.Render("► ")
		}

		statusIcon := theme.StatusMutedStyle.Render("○")
		if card.enabled {
			statusIcon = theme.StatusOKStyle.Render("●")
		}

		b.WriteString(fmt.Sprintf("%s%s %s", prefix, statusIcon, strings.Title(card.name)))
		b.WriteString("\n")

		if card.expanded {
			if card.status != "" {
				b.WriteString(fmt.Sprintf("    Status: %s\n", card.status))
			}
			b.WriteString("    Use setup/disable actions from the API\n")
		}
		b.WriteString("\n")
	}

	b.WriteString(theme.LabelStyle.Render("<r> refresh  <enter> expand/collapse"))

	return tea.NewView(b.String())
}

func (p *TFAPage) initDefaultCards() {
	p.cardOrder = []string{"email", "totp", "hotp"}
	p.cards = map[string]*providerCard{
		"email": {name: "email"},
		"totp":  {name: "totp"},
		"hotp":  {name: "hotp"},
	}
}

func (p *TFAPage) updateCardOrder() {
	if len(p.cardOrder) == 0 {
		p.cardOrder = []string{"email", "totp", "hotp"}
	}
}

func (p TFAPage) loadStatus() tea.Cmd {
	return func() tea.Msg {
		if p.deps.API == nil {
			return messages.TFAStatusMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewTFAService(p.deps.API)
		status, err := svc.GetStatus(p.deps.Ctx)
		return messages.TFAStatusMsg{Status: status, Err: err}
	}
}

func (p TFAPage) loadProvider() tea.Cmd {
	return func() tea.Msg {
		p.loading = true
		if p.deps.API == nil {
			return messages.TFAProviderMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewTFAService(p.deps.API)
		status, err := svc.GetProvider(p.deps.Ctx)
		return messages.TFAProviderMsg{Status: status, Err: err}
	}
}
