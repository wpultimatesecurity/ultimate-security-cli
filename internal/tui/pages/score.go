package pages

import (
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/api"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/cache"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/messages"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/components"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type ScorePage struct {
	deps       messages.PageDeps
	checks     *api.ScoreChecks
	score      *api.SecurityScore
	loading    bool
	search     string
	filterCat  string
	cursor     int
	expanded   map[string]bool
	scoreMeter *components.ScoreMeter
	width      int
	height     int
}

func NewScorePage() *ScorePage {
	return &ScorePage{
		expanded:   make(map[string]bool),
		scoreMeter: components.NewScoreMeter(),
	}
}

func (p *ScorePage) SetDeps(deps messages.PageDeps) {
	p.deps = deps
}

func (p *ScorePage) Init() tea.Cmd {
	return p.loadChecks()
}

func (p *ScorePage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		p.width = msg.Width
		p.height = msg.Height
		p.scoreMeter.SetWidth(msg.Width)
	case tea.KeyPressMsg:
		switch msg.String() {
		case "r", "ctrl+r":
			return p, p.refreshScore()
		case "up", "k":
			if p.cursor > 0 {
				p.cursor--
			}
		case "down", "j":
			if p.checks != nil && p.cursor < len(p.checks.Checks)-1 {
				p.cursor++
			}
		case "enter":
			if p.checks != nil {
				keys := p.sortedCheckKeys()
				if p.cursor < len(keys) {
					p.expanded[keys[p.cursor]] = !p.expanded[keys[p.cursor]]
				}
			}
		}
	case messages.ScoreChecksLoadedMsg:
		if msg.Err == nil {
			p.checks = msg.Checks
			if p.checks != nil {
				p.score = &p.checks.Score
				p.scoreMeter.SetScore(p.score)
			}
		}
		p.loading = false
	case messages.SecurityScoreLoadedMsg:
		if msg.Err == nil {
			p.score = msg.Score
			p.scoreMeter.SetScore(msg.Score)
		}
	}
	return p, nil
}

func (p ScorePage) View() tea.View {
	var b strings.Builder

	b.WriteString(theme.TitleStyle.Render("Security Score"))
	b.WriteString("\n\n")

	if p.scoreMeter != nil && p.score != nil {
		b.WriteString(p.scoreMeter.View())
		b.WriteString("\n")
	}

	if p.score != nil && p.score.NextTier != nil && len(p.score.NextTier.BlockedBy) > 0 {
		b.WriteString(theme.StatusWarnStyle.Render("Blocked by: "))
		b.WriteString(strings.Join(p.score.NextTier.BlockedBy, ", "))
		b.WriteString("\n")
	}

	b.WriteString("\n")

	if p.loading {
		b.WriteString(theme.StatusMutedStyle.Render("Loading checks..."))
		return tea.NewView(b.String())
	}

	if p.checks == nil || len(p.checks.Checks) == 0 {
		b.WriteString(theme.StatusMutedStyle.Render("No check data available"))
		return tea.NewView(b.String())
	}

	b.WriteString(theme.TableHeaderStyle.Render(
		fmt.Sprintf("  %-5s %-30s %-8s %-8s %-10s %s",
			"CAT", "CHECK", "POINTS", "EARNED", "PASSED", "PRO",
		),
	))
	b.WriteString("\n")

	keys := p.sortedCheckKeys()
	for i, key := range keys {
		check := p.checks.Checks[key]
		row := fmt.Sprintf("  %-5s %-30s %3d/%-4d %-8s %-10s %s",
			check.Category,
			truncate(check.Name, 30),
			check.Points,
			check.Points,
			" ",
			" ",
			boolStr(check.ProOnly),
		)
		if i == p.cursor {
			b.WriteString(theme.SelectedRowStyle.Render(row))
		} else {
			b.WriteString(row)
		}
		if p.expanded[key] {
			b.WriteString("\n    ")
			b.WriteString(theme.StatusMutedStyle.Render(check.Description))
		}
		b.WriteString("\n")
	}

	return tea.NewView(b.String())
}

func (p ScorePage) sortedCheckKeys() []string {
	if p.checks == nil {
		return nil
	}
	keys := make([]string, 0, len(p.checks.Checks))
	for k := range p.checks.Checks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (p ScorePage) loadChecks() tea.Cmd {
	return func() tea.Msg {
		p.loading = true
		if p.deps.API == nil {
			return messages.ScoreChecksLoadedMsg{Err: fmt.Errorf("not connected")}
		}
		if p.deps.Cache != nil {
			key := cache.SecurityScoreChecksKey(p.deps.Site.Name)
			if cached, ok := p.deps.Cache.Get(key); ok {
				if c, ok := cached.(*api.ScoreChecks); ok {
					return messages.ScoreChecksLoadedMsg{Checks: c}
				}
			}
		}
		svc := api.NewScoreService(p.deps.API)
		checks, err := svc.GetChecks(p.deps.Ctx)
		if err == nil && p.deps.Cache != nil {
			p.deps.Cache.Set(cache.SecurityScoreChecksKey(p.deps.Site.Name), checks, cache.TTL(cache.KeySecurityScoreChecks))
		}
		return messages.ScoreChecksLoadedMsg{Checks: checks, Err: err}
	}
}

func (p ScorePage) refreshScore() tea.Cmd {
	return func() tea.Msg {
		if p.deps.API == nil {
			return messages.SecurityScoreLoadedMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewScoreService(p.deps.API)
		score, err := svc.Refresh(p.deps.Ctx)
		if err == nil && p.deps.Cache != nil {
			p.deps.Cache.Set(cache.SecurityScoreKey(p.deps.Site.Name), score, cache.TTL(cache.KeySecurityScore))
		}
		return messages.SecurityScoreLoadedMsg{Score: score, Err: err}
	}
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
