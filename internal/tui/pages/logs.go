package pages

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/api"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/messages"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type LogsPage struct {
	deps       messages.PageDeps
	logs       []api.AuditLog
	eventTypes api.EventTypesResult
	total      int
	page       int
	perPage    int
	totalPages int
	cursor     int
	loading    bool
	filterOpen bool
	filter     api.AuditLogParams
	detailOpen bool
	detailLog  *api.AuditLog
	width      int
	height     int
}

func NewLogsPage() *LogsPage {
	return &LogsPage{
		perPage: 50,
		filter:  api.AuditLogParams{Page: 1, PerPage: 50},
	}
}

func (p *LogsPage) SetDeps(deps messages.PageDeps) {
	p.deps = deps
}

func (p *LogsPage) Init() tea.Cmd {
	return tea.Batch(
		p.loadLogs(),
		p.loadEventTypes(),
	)
}

func (p *LogsPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			if p.cursor < len(p.logs)-1 {
				p.cursor++
			}
		case "n", "right":
			if p.page < p.totalPages {
				p.page++
				p.filter.Page = p.page
				return p, p.loadLogs()
			}
		case "p", "left":
			if p.page > 1 {
				p.page--
				p.filter.Page = p.page
				return p, p.loadLogs()
			}
		case "enter":
			if p.cursor < len(p.logs) {
				p.detailLog = &p.logs[p.cursor]
				p.detailOpen = !p.detailOpen
			}
		case "r":
			return p, p.loadLogs()
		case "f":
			p.filterOpen = !p.filterOpen
		case "esc":
			if p.detailOpen {
				p.detailOpen = false
			} else if p.filterOpen {
				p.filterOpen = false
			}
		}
	case messages.AuditLogsLoadedMsg:
		if msg.Err == nil && msg.Result != nil {
			p.logs = msg.Result.Logs
			p.total = msg.Result.Total
			p.page = msg.Result.Page
			p.perPage = msg.Result.PerPage
			p.totalPages = msg.Result.TotalPages
			p.cursor = 0
		}
		p.loading = false
	case messages.EventTypesLoadedMsg:
		if msg.Err == nil {
			p.eventTypes = msg.Types
		}
	}
	return p, nil
}

func (p LogsPage) View() tea.View {
	var b strings.Builder

	b.WriteString(theme.TitleStyle.Render("Activity Logs"))

	if p.total > 0 {
		b.WriteString(fmt.Sprintf(" - page %d/%d (%d total)", p.page, p.totalPages, p.total))
	}

	if p.filter.EventType != "" {
		b.WriteString(fmt.Sprintf(" filter: %s", p.filter.EventType))
	}
	if p.filter.Severity != "" {
		b.WriteString(fmt.Sprintf(" severity: %s", p.filter.Severity))
	}
	if p.filter.Search != "" {
		b.WriteString(fmt.Sprintf(" search: %s", p.filter.Search))
	}

	b.WriteString("\n\n")

	if p.detailOpen && p.detailLog != nil {
		b.WriteString(p.renderDetail())
		return tea.NewView(b.String())
	}

	if p.loading {
		b.WriteString(theme.StatusMutedStyle.Render("Loading logs..."))
		return tea.NewView(b.String())
	}

	if len(p.logs) == 0 {
		b.WriteString(theme.StatusMutedStyle.Render("No logs found"))
		return tea.NewView(b.String())
	}

	b.WriteString(theme.TableHeaderStyle.Render(
		fmt.Sprintf("%-20s %-6s %-18s %-12s %-15s %s",
			"TIME", "SEV", "EVENT", "USER", "IP", "MESSAGE",
		),
	))
	b.WriteString("\n")

	maxRows := 20
	if p.height > 0 {
		maxRows = p.height - 10
	}
	if maxRows < 5 {
		maxRows = 5
	}

	end := p.cursor + maxRows
	if end > len(p.logs) {
		end = len(p.logs)
	}
	start := p.cursor - maxRows/2
	if start < 0 {
		start = 0
	}
	if end-start > maxRows {
		end = start + maxRows
	}

	for i := start; i < end; i++ {
		log := p.logs[i]

		row := fmt.Sprintf("%-20s %-6s %-18s %-12s %-15s %s",
			truncate(log.CreatedAt, 20),
			p.severityStyle(log.Severity, truncate(strings.ToUpper(log.Severity), 6)),
			truncate(log.EventType, 18),
			truncate(log.Username, 12),
			truncate(log.IPAddress, 15),
			truncate(log.Message, 40),
		)
		if i == p.cursor {
			b.WriteString(theme.SelectedRowStyle.Render(row))
		} else {
			b.WriteString(row)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(theme.LabelStyle.Render("<n/→> next page  <p/←> prev page  <enter> detail  <f> filters  <r> refresh"))

	return tea.NewView(b.String())
}

func (p LogsPage) renderDetail() string {
	log := p.detailLog
	var b strings.Builder
	b.WriteString(theme.TitleStyle.Render("Log Detail"))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("Event:    %s\n", theme.ValueStyle.Render(log.EventType)))
	b.WriteString(fmt.Sprintf("Time:     %s\n", log.CreatedAt))
	b.WriteString(fmt.Sprintf("User:     %s (ID: %d)\n", log.Username, log.UserID))
	b.WriteString(fmt.Sprintf("IP:       %s\n", log.IPAddress))
	b.WriteString(fmt.Sprintf("Severity: %s\n", p.severityStyle(log.Severity, log.Severity)))
	b.WriteString(fmt.Sprintf("Message:  %s\n", log.Message))
	if log.UserAgent != "" {
		b.WriteString(fmt.Sprintf("Agent:    %s\n", theme.StatusMutedStyle.Render(log.UserAgent)))
	}
	b.WriteString("\n")
	b.WriteString(theme.LabelStyle.Render("<esc> close"))
	return b.String()
}

func (p LogsPage) severityStyle(sev, text string) string {
	switch strings.ToLower(sev) {
	case "high", "critical", "error":
		return theme.StatusErrStyle.Render(text)
	case "medium", "warning", "warn":
		return theme.StatusWarnStyle.Render(text)
	case "low", "info", "ok":
		return theme.StatusOKStyle.Render(text)
	default:
		return theme.StatusMutedStyle.Render(text)
	}
}

func (p LogsPage) loadLogs() tea.Cmd {
	return func() tea.Msg {
		p.loading = true
		if p.deps.API == nil {
			return messages.AuditLogsLoadedMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewLogsService(p.deps.API)
		result, err := svc.GetLogs(p.deps.Ctx, p.filter)
		return messages.AuditLogsLoadedMsg{Result: result, Err: err}
	}
}

func (p LogsPage) loadEventTypes() tea.Cmd {
	return func() tea.Msg {
		if p.deps.API == nil {
			return messages.EventTypesLoadedMsg{Err: fmt.Errorf("not connected")}
		}
		svc := api.NewLogsService(p.deps.API)
		types, err := svc.GetEventTypes(p.deps.Ctx)
		return messages.EventTypesLoadedMsg{Types: types, Err: err}
	}
}
