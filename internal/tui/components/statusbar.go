package components

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type ConnectionStatus int

const (
	StatusUnknown ConnectionStatus = iota
	StatusConnected
	StatusAuthFailed
	StatusPluginMissing
	StatusSSLWarning
	StatusOffline
)

type StatusBar struct {
	siteName   string
	status     ConnectionStatus
	pluginVer  string
	scoreStale time.Duration
	clock      time.Time
	width      int
}

func NewStatusBar() *StatusBar {
	return &StatusBar{
		status: StatusUnknown,
		clock:  time.Now(),
	}
}

func (s *StatusBar) SetSite(name string) {
	s.siteName = name
}

func (s *StatusBar) SetStatus(st ConnectionStatus) {
	s.status = st
}

func (s *StatusBar) SetPluginVersion(v string) {
	s.pluginVer = v
}

func (s *StatusBar) SetScoreStale(d time.Duration) {
	s.scoreStale = d
}

func (s *StatusBar) SetClock(t time.Time) {
	s.clock = t
}

func (s *StatusBar) SetWidth(w int) {
	s.width = w
}

func (s *StatusBar) View() string {
	var parts []string

	parts = append(parts, theme.BrandStyle.Render("uscli"))

	if s.siteName != "" {
		parts = append(parts, theme.ValueStyle.Render(s.siteName))
	}

	parts = append(parts, s.statusText())

	if s.pluginVer != "" {
		parts = append(parts, theme.StatusMutedStyle.Render("v"+s.pluginVer))
	}

	if s.scoreStale > 0 {
		stale := fmt.Sprintf("score stale %s", formatDuration(s.scoreStale))
		parts = append(parts, theme.StatusWarnStyle.Render(stale))
	}

	parts = append(parts, theme.StatusMutedStyle.Render(s.clock.Format("15:04")))

	line := strings.Join(parts, theme.SeparatorStyle.Render("  "))
	if s.width > 0 {
		line = lipgloss.NewStyle().Width(s.width).Render(line)
	}
	return line
}

func (s *StatusBar) statusText() string {
	switch s.status {
	case StatusConnected:
		return theme.StatusOKStyle.Render("REST OK ●")
	case StatusAuthFailed:
		return theme.StatusErrStyle.Render("AUTH FAILED ●")
	case StatusPluginMissing:
		return theme.StatusMutedStyle.Render("PLUGIN MISSING ○")
	case StatusSSLWarning:
		return theme.StatusWarnStyle.Render("SSL WARNING ●")
	case StatusOffline:
		return theme.StatusErrStyle.Render("OFFLINE ●")
	default:
		return theme.StatusMutedStyle.Render("CONNECTING...")
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
