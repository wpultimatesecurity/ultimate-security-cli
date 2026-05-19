package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/api"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/cache"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/config"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/messages"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/components"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/keys"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/pages"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type Page interface {
	tea.Model
	SetDeps(deps PageDeps)
}

type PageDeps = messages.PageDeps

type AppModel struct {
	config     config.Config
	cfgPath    string
	deps       PageDeps
	pages      map[PageID]Page
	active     PageID
	tabBar     *components.TabBar
	statusBar  *components.StatusBar
	keyBar     *components.KeyBar
	errBanner  *components.ErrorBanner
	confirm    *components.ConfirmDialog
	width      int
	height     int
	helpOpen   bool
	quitting   bool
	clock      time.Time
	connStatus components.ConnectionStatus
	pluginVer  string
}

func NewApp(cfg config.Config, cfgPath string) AppModel {
	tabBar := components.NewTabBar()
	statusBar := components.NewStatusBar()
	keyBar := components.NewKeyBar(keys.GlobalHelpEntries()...)
	errBanner := components.NewErrorBanner()
	confirm := components.NewConfirmDialog()

	_, siteErr := cfg.ActiveSite()
	activePage := PageSetup
	if siteErr == nil {
		activePage = PageDashboard
	}

	m := AppModel{
		config:    cfg,
		cfgPath:   cfgPath,
		active:    activePage,
		tabBar:    tabBar,
		statusBar: statusBar,
		keyBar:    keyBar,
		errBanner: errBanner,
		confirm:   confirm,
		clock:     time.Now(),
	}

	m.pages = map[PageID]Page{
		PageSetup:     pages.NewSetupPage(),
		PageDashboard: pages.NewDashboardPage(),
		PageScore:     pages.NewScorePage(),
		PageLogin:     pages.NewLoginPage(),
		PageTFA:       pages.NewTFAPage(),
		PageSettings:  pages.NewSettingsPage(),
		PageLogs:      pages.NewLogsPage(),
	}

	if siteErr == nil {
		site, _ := cfg.ActiveSite()
		m.setupDeps(site)
		statusBar.SetSite(site.Name)
		statusBar.SetStatus(components.StatusConnected)
	}

	tabBar.SetActive(activePage)

	return m
}

func (m AppModel) Init() tea.Cmd {
	var cmds []tea.Cmd

	if m.active == PageSetup {
		if p, ok := m.pages[PageSetup]; ok {
			cmds = append(cmds, p.Init())
		}
	} else {
		cmds = append(cmds, m.tickClock())
		if p, ok := m.pages[m.active]; ok {
			cmds = append(cmds, p.Init())
		}
	}

	return tea.Batch(cmds...)
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.layoutChrome()
		var cmds []tea.Cmd
		for id, p := range m.pages {
			updated, cmd := p.Update(msg)
			m.pages[id] = updated.(Page)
			cmds = append(cmds, cmd)
		}
		return m, tea.Batch(cmds...)

	case tea.KeyPressMsg:
		if m.confirm.Visible() {
			return m.handleConfirm(msg)
		}

		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "?":
			m.helpOpen = !m.helpOpen
			return m, nil
		case "ctrl+l":
			return m, nil
		case "1":
			return m, m.navigateTo(PageDashboard)
		case "2":
			return m, m.navigateTo(PageScore)
		case "3":
			return m, m.navigateTo(PageLogin)
		case "4":
			return m, m.navigateTo(PageTFA)
		case "5":
			return m, m.navigateTo(PageSettings)
		case "6":
			return m, m.navigateTo(PageLogs)
		}

	case messages.ConnectionChangedMsg:
		if msg.Connected {
			m.connStatus = components.StatusConnected
			m.pluginVer = msg.Version
			m.statusBar.SetStatus(components.StatusConnected)
			m.statusBar.SetPluginVersion(msg.Version)
			if msg.Site != nil {
				m.statusBar.SetSite(msg.Site.Name)
				m.setupDeps(msg.Site)
			}
			return m, m.navigateTo(PageDashboard)
		}
		m.connStatus = components.StatusAuthFailed
		m.statusBar.SetStatus(components.StatusAuthFailed)
		m.errBanner.Show(
			fmt.Sprintf("Connection failed: %v", msg.Err),
			"Press Enter to edit connection",
		)
		return m, nil

	case messages.ClockTickMsg:
		m.clock = msg.Time
		m.statusBar.SetClock(msg.Time)
		return m, m.tickClock()
	}

	if p, ok := m.pages[m.active]; ok {
		updated, cmd := p.Update(msg)
		m.pages[m.active] = updated.(Page)
		return m, cmd
	}

	return m, nil
}

func (m AppModel) View() tea.View {
	if m.quitting {
		return tea.NewView("")
	}

	if m.width == 0 {
		return tea.NewView("Loading...")
	}

	var b strings.Builder

	b.WriteString(m.statusBar.View())
	b.WriteString("\n")

	sep := strings.Repeat("─", m.width)
	b.WriteString(theme.SeparatorStyle.Render(sep))
	b.WriteString("\n")

	b.WriteString(m.tabBar.View())
	b.WriteString("\n")

	b.WriteString(theme.SeparatorStyle.Render(sep))
	b.WriteString("\n")

	if m.errBanner.Visible() {
		b.WriteString(m.errBanner.View())
		b.WriteString("\n")
	}

	if m.helpOpen {
		b.WriteString(m.renderHelp())
	} else if p, ok := m.pages[m.active]; ok {
		b.WriteString(p.View().Content)
	}

	b.WriteString("\n")
	b.WriteString(theme.SeparatorStyle.Render(sep))
	b.WriteString("\n")
	b.WriteString(m.keyBar.View())

	if m.confirm.Visible() {
		return tea.NewView(lipgloss.Place(m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			m.confirm.View(),
		))
	}

	v := tea.NewView(b.String())
	v.AltScreen = true
	return v
}

func (m *AppModel) navigateTo(target PageID) tea.Cmd {
	if target == m.active {
		return nil
	}
	m.active = target
	m.tabBar.SetActive(target)
	m.errBanner.Hide()

	if p, ok := m.pages[target]; ok {
		p.SetDeps(m.deps)
		return p.Init()
	}
	return nil
}

func (m *AppModel) setupDeps(site *config.SiteConfig) {
	client := api.NewClient(site, m.config.API)
	c := cache.New[cache.SiteKey, interface{}]()
	m.deps = PageDeps{
		Site:  site,
		API:   client,
		Cache: c,
		Ctx:   context.Background(),
	}
	for _, p := range m.pages {
		p.SetDeps(m.deps)
	}
}

func (m *AppModel) layoutChrome() {
	m.tabBar.SetWidth(m.width)
	m.statusBar.SetWidth(m.width)
	m.keyBar.SetWidth(m.width)
	m.errBanner.SetWidth(m.width)
	m.confirm.SetSize(m.width, m.height)
}

func (m *AppModel) handleConfirm(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "right", "tab":
		f := m.confirm.Focused()
		if f == 0 {
			m.confirm.SetFocused(1)
		} else {
			m.confirm.SetFocused(0)
		}
		return m, nil
	case "enter":
		if m.confirm.Focused() == 0 {
			m.confirm.Hide()
		}
		m.confirm.Hide()
		return m, nil
	case "esc", "n":
		m.confirm.Hide()
		return m, nil
	}
	return m, nil
}

func (m AppModel) renderHelp() string {
	var b strings.Builder
	b.WriteString(theme.TitleStyle.Render("Keybindings"))
	b.WriteString("\n\n")
	for _, k := range keys.GlobalHelpEntries() {
		help := k.Help()
		b.WriteString(fmt.Sprintf("  %-12s %s\n",
			theme.KeyStyle.Render(help.Key),
			help.Desc,
		))
	}
	return b.String()
}

func (m AppModel) tickClock() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return messages.ClockTickMsg{Time: t}
	})
}
