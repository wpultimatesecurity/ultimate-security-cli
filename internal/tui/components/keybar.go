package components

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/lipgloss/v2"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type KeyBar struct {
	bindings []key.Binding
	width    int
}

func NewKeyBar(bindings ...key.Binding) *KeyBar {
	return &KeyBar{bindings: bindings}
}

func (k *KeyBar) SetBindings(b []key.Binding) {
	k.bindings = b
}

func (k *KeyBar) SetWidth(w int) {
	k.width = w
}

func (k *KeyBar) View() string {
	var parts []string
	for _, b := range k.bindings {
		help := b.Help()
		keyText := help.Key
		desc := help.Desc
		if keyText == "" {
			continue
		}
		part := fmt.Sprintf("<%s> %s",
			theme.KeyStyle.Render(keyText),
			theme.KeyDescStyle.Render(desc),
		)
		parts = append(parts, part)
	}
	line := strings.Join(parts, "  ")
	if k.width > 0 {
		line = lipgloss.NewStyle().Width(k.width).Render(line)
	}
	return line
}
