package components

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/pageid"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type TabBar struct {
	pages  []pageid.ID
	active pageid.ID
	width  int
}

func NewTabBar() *TabBar {
	return &TabBar{
		pages:  pageid.Order,
		active: pageid.Dashboard,
	}
}

func (t *TabBar) SetActive(p pageid.ID) {
	t.active = p
}

func (t *TabBar) Active() pageid.ID {
	return t.active
}

func (t *TabBar) SetWidth(w int) {
	t.width = w
}

func (t *TabBar) View() string {
	var tabs []string
	for i, p := range t.pages {
		label := fmt.Sprintf("[%d] %s", i+1, p.Title())
		if p == t.active {
			tabs = append(tabs, theme.ActiveTabStyle.Render(label))
		} else {
			tabs = append(tabs, theme.InactiveTabStyle.Render(label))
		}
	}
	line := strings.Join(tabs, " ")
	if t.width > 0 {
		line = lipgloss.NewStyle().Width(t.width).Render(line)
	}
	return line
}
