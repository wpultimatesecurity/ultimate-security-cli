package components

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type ErrorBanner struct {
	message string
	action  string
	width   int
	visible bool
}

func NewErrorBanner() *ErrorBanner {
	return &ErrorBanner{}
}

func (e *ErrorBanner) Show(msg, action string) {
	e.message = msg
	e.action = action
	e.visible = true
}

func (e *ErrorBanner) Hide() {
	e.visible = false
	e.message = ""
	e.action = ""
}

func (e *ErrorBanner) Visible() bool {
	return e.visible
}

func (e *ErrorBanner) SetWidth(w int) {
	e.width = w
}

func (e *ErrorBanner) View() string {
	if !e.visible {
		return ""
	}
	var b strings.Builder
	b.WriteString(theme.StatusErrStyle.Render("● ERR: "))
	b.WriteString(theme.ErrorBannerStyle.Render(e.message))
	if e.action != "" {
		b.WriteString(" ")
		b.WriteString(theme.LabelStyle.Render(e.action))
	}
	line := b.String()
	if e.width > 0 {
		line = lipgloss.NewStyle().Width(e.width).Render(line)
	}
	return line
}

type ConfirmDialog struct {
	title    string
	message  string
	siteName string
	focused  int
	visible  bool
	width    int
	height   int
}

func NewConfirmDialog() *ConfirmDialog {
	return &ConfirmDialog{}
}

func (c *ConfirmDialog) Show(title, message, siteName string) {
	c.title = title
	c.message = message
	c.siteName = siteName
	c.focused = 1
	c.visible = true
}

func (c *ConfirmDialog) Hide() {
	c.visible = false
}

func (c *ConfirmDialog) Visible() bool {
	return c.visible
}

func (c *ConfirmDialog) Focused() int {
	return c.focused
}

func (c *ConfirmDialog) SetFocused(i int) {
	c.focused = i
}

func (c *ConfirmDialog) SetSize(w, h int) {
	c.width = w
	c.height = h
}

func (c *ConfirmDialog) View() string {
	if !c.visible {
		return ""
	}

	var b strings.Builder
	b.WriteString(theme.DialogConfirmStyle.Render(c.title))
	b.WriteString("\n\n")
	b.WriteString(c.message)
	if c.siteName != "" {
		b.WriteString(fmt.Sprintf("\n\nSite: %s", theme.ValueStyle.Render(c.siteName)))
	}
	b.WriteString("\n\n")

	yes := "  Yes  "
	no := "  No  "
	if c.focused == 0 {
		yes = theme.ActiveTabStyle.Render("[ Yes ]")
		no = "  No  "
	} else {
		yes = "  Yes  "
		no = theme.ActiveTabStyle.Render("[ No ]")
	}
	b.WriteString(yes)
	b.WriteString("  ")
	b.WriteString(no)

	content := b.String()
	dialogWidth := 50
	if c.width > 0 && dialogWidth > c.width-4 {
		dialogWidth = c.width - 4
	}

	return theme.DialogStyle.
		Width(dialogWidth).
		Render(content)
}
