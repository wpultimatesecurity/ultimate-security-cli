package pages

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/api"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/cache"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/messages"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/components"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type DashboardPage struct {
	deps         messages.PageDeps
	pluginInfo   *api.PluginInfo
	score        *api.SecurityScore
	failedLogins *api.FailedLoginResult
	onlineUsers  *api.WhosOnlineResult
	systemInfo   api.SystemInfo
	loading      bool
	lastRefresh  time.Time
	width        int
	height       int
	scoreMeter   *components.ScoreMeter
}

func NewDashboardPage() *DashboardPage {
	return &DashboardPage{
		scoreMeter: components.NewScoreMeter(),
	}
}

func (p *DashboardPage) SetDeps(deps messages.PageDeps) {
	p.deps = deps
}

func (p *DashboardPage) Init() tea.Cmd {
	return tea.Batch(
		p.loadPluginInfo(),
		p.loadSecurityScore(),
		p.loadFailedLogins(),
		p.loadWhosOnline(),
	)
}

func (p *DashboardPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		p.width = msg.Width
		p.height = msg.Height
		p.scoreMeter.SetWidth(msg.Width)
	case tea.KeyPressMsg:
		switch msg.String() {
		case "r":
			return p, tea.Batch(
				p.loadPluginInfo(),
				p.loadSecurityScore(),
				p.loadFailedLogins(),
				p.loadWhosOnline(),
			)
		}
	case messages.PluginInfoLoadedMsg:
		if msg.Err == nil {
			p.pluginInfo = msg.Info
		}
	case messages.SecurityScoreLoadedMsg:
		if msg.Err == nil {
			p.score = msg.Score
			p.scoreMeter.SetScore(msg.Score)
		}
	case messages.FailedLoginsLoadedMsg:
		if msg.Err == nil {
			p.failedLogins = msg.Result
		}
	case messages.WhosOnlineLoadedMsg:
		if msg.Err == nil {
			p.onlineUsers = msg.Result
		}
	}
	return p, nil
}

func (p DashboardPage) View() tea.View {
	var b strings.Builder

	b.WriteString(p.renderScore())
	b.WriteString("\n")
	b.WriteString(p.renderFailedLogins())
	b.WriteString("\n")
	b.WriteString(p.renderOnlineUsers())

	return tea.NewView(b.String())
}

func (p DashboardPage) renderScore() string {
	var b strings.Builder
	b.WriteString(theme.TitleStyle.Render("Score"))
	b.WriteString("\n")
	if p.score != nil {
		p.scoreMeter.SetWidth(p.width)
		b.WriteString(p.scoreMeter.View())
	} else {
		b.WriteString(theme.StatusMutedStyle.Render("Loading score..."))
	}
	return b.String()
}

func (p DashboardPage) renderFailedLogins() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(theme.TitleStyle.Render("Failed Logins"))
	b.WriteString("\n")
	if p.failedLogins != nil {
		b.WriteString(fmt.Sprintf("Total: %d", p.failedLogins.TotalFailed))
		if len(p.failedLogins.Logs) > 0 {
			b.WriteString("\n")
			b.WriteString(theme.TableHeaderStyle.Render(
				fmt.Sprintf("%-20s %-15s %-18s %s",
					"TIME", "USER", "IP", "MESSAGE",
				),
			))
			b.WriteString("\n")
			limit := len(p.failedLogins.Logs)
			if limit > 10 {
				limit = 10
			}
			for _, log := range p.failedLogins.Logs[:limit] {
				b.WriteString(fmt.Sprintf("%-20s %-15s %-18s %s\n",
					log.CreatedAt,
					log.Username,
					log.IPAddress,
					log.Message,
				))
			}
		}
	} else {
		b.WriteString(theme.StatusMutedStyle.Render("Loading..."))
	}
	return b.String()
}

func (p DashboardPage) renderOnlineUsers() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString(theme.TitleStyle.Render("Online Users"))
	b.WriteString("\n")
	if p.onlineUsers != nil {
		if p.onlineUsers.Count > 0 {
			b.WriteString(fmt.Sprintf("%d user(s) online", p.onlineUsers.Count))
			if len(p.onlineUsers.Users) > 0 {
				b.WriteString("\n")
				for _, u := range p.onlineUsers.Users {
					b.WriteString(fmt.Sprintf("  %s (%s) - %s\n",
						theme.ValueStyle.Render(u.Username),
						theme.StatusMutedStyle.Render(u.IPAddress),
						theme.StatusMutedStyle.Render(u.Status),
					))
				}
			}
		} else {
			b.WriteString(theme.StatusMutedStyle.Render("No users online"))
		}
	} else {
		b.WriteString(theme.StatusMutedStyle.Render("Loading..."))
	}
	return b.String()
}

func (p DashboardPage) loadPluginInfo() tea.Cmd {
	return func() tea.Msg {
		if p.deps.API == nil {
			return messages.PluginInfoLoadedMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewConnectionService(p.deps.API)
		info, err := svc.TestConnection(p.deps.Ctx)
		return messages.PluginInfoLoadedMsg{Info: info, Err: err}
	}
}

func (p DashboardPage) loadSecurityScore() tea.Cmd {
	return func() tea.Msg {
		if p.deps.API == nil {
			return messages.SecurityScoreLoadedMsg{Err: fmt.Errorf("not connected")}
		}
		if p.deps.Cache != nil {
			key := cache.SecurityScoreKey(p.deps.Site.Name)
			if cached, ok := p.deps.Cache.Get(key); ok {
				if s, ok := cached.(*api.SecurityScore); ok {
					return messages.SecurityScoreLoadedMsg{Score: s}
				}
			}
		}
		svc := api.NewScoreService(p.deps.API)
		score, err := svc.GetScore(p.deps.Ctx)
		if err == nil && p.deps.Cache != nil {
			p.deps.Cache.Set(cache.SecurityScoreKey(p.deps.Site.Name), score, cache.TTL(cache.KeySecurityScore))
		}
		return messages.SecurityScoreLoadedMsg{Score: score, Err: err}
	}
}

func (p DashboardPage) loadFailedLogins() tea.Cmd {
	return func() tea.Msg {
		if p.deps.API == nil {
			return messages.FailedLoginsLoadedMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewLogsService(p.deps.API)
		result, err := svc.GetFailedLoginLogs(p.deps.Ctx)
		return messages.FailedLoginsLoadedMsg{Result: result, Err: err}
	}
}

func (p DashboardPage) loadWhosOnline() tea.Cmd {
	return func() tea.Msg {
		if p.deps.API == nil {
			return messages.WhosOnlineLoadedMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewLogsService(p.deps.API)
		result, err := svc.GetWhosOnline(p.deps.Ctx, 10, false, "all")
		return messages.WhosOnlineLoadedMsg{Result: result, Err: err}
	}
}
