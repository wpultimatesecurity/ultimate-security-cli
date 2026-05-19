package components

import (
	"fmt"
	"strings"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/api"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/tui/theme"
)

type ScoreMeter struct {
	score *api.SecurityScore
	width int
}

func NewScoreMeter() *ScoreMeter {
	return &ScoreMeter{}
}

func (m *ScoreMeter) SetScore(s *api.SecurityScore) {
	m.score = s
}

func (m *ScoreMeter) SetWidth(w int) {
	m.width = w
}

func (m *ScoreMeter) View() string {
	if m.score == nil {
		return theme.StatusMutedStyle.Render("No score data")
	}

	tier := m.score.Tier
	points := m.score.Points

	tierStyle := theme.TierStyle(tier.Name)

	var b strings.Builder
	b.WriteString(tierStyle.Render(tier.Name))
	b.WriteString("  ")
	b.WriteString(fmt.Sprintf("%d / %d points", points.Earned, points.Max))

	if m.width > 0 {
		b.WriteString("\n")
		barWidth := m.width - 20
		if barWidth < 10 {
			barWidth = 10
		}
		if points.Max > 0 {
			filled := points.Earned * barWidth / points.Max
			bar := strings.Repeat("#", filled) + strings.Repeat("-", barWidth-filled)
			b.WriteString("[")
			b.WriteString(bar)
			b.WriteString("]")
		}

		if m.score.NextTier != nil {
			b.WriteString(" next: ")
			b.WriteString(theme.LabelStyle.Render(m.score.NextTier.Name))
		}
	}

	return b.String()
}

type UnsavedIndicator struct {
	dirty bool
}

func NewUnsavedIndicator() *UnsavedIndicator {
	return &UnsavedIndicator{}
}

func (u *UnsavedIndicator) SetDirty(d bool) {
	u.dirty = d
}

func (u *UnsavedIndicator) View() string {
	if !u.dirty {
		return ""
	}
	return theme.UnsavedIndicatorStyle.Render("unsaved changes")
}
