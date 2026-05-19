package theme

import (
	"charm.land/lipgloss/v2"
)

var (
	Background = lipgloss.Color("#000000")
	Foreground = lipgloss.Color("#d7e0e0")
	Primary    = lipgloss.Color("#00ffff")
	Secondary  = lipgloss.Color("#1e90ff")
	Brand      = lipgloss.Color("#ffa500")
	Success    = lipgloss.Color("#adff2f")
	Warning    = lipgloss.Color("#ff8c00")
	Error      = lipgloss.Color("#ff4500")
	Muted      = lipgloss.Color("#808080")
	Surface    = lipgloss.Color("#0b0f14")
)

var (
	TitleStyle = lipgloss.NewStyle().
			Foreground(Primary).
			Bold(true)

	BrandStyle = lipgloss.NewStyle().
			Foreground(Brand).
			Bold(true)

	BorderStyle = lipgloss.NewStyle().
			BorderForeground(Secondary)

	StatusOKStyle = lipgloss.NewStyle().
			Foreground(Success)

	StatusWarnStyle = lipgloss.NewStyle().
			Foreground(Warning)

	StatusErrStyle = lipgloss.NewStyle().
			Foreground(Error)

	StatusMutedStyle = lipgloss.NewStyle().
				Foreground(Muted)

	LabelStyle = lipgloss.NewStyle().
			Foreground(Secondary)

	ValueStyle = lipgloss.NewStyle().
			Foreground(Primary)

	SeparatorStyle = lipgloss.NewStyle().
			Foreground(Muted)

	KeyStyle = lipgloss.NewStyle().
			Foreground(Secondary)

	KeyDescStyle = lipgloss.NewStyle().
			Foreground(Foreground)

	ActiveTabStyle = lipgloss.NewStyle().
			Foreground(Primary).
			Bold(true)

	InactiveTabStyle = lipgloss.NewStyle().
				Foreground(Muted)

	TableHeaderStyle = lipgloss.NewStyle().
				Foreground(Primary).
				Bold(true)

	SelectedRowStyle = lipgloss.NewStyle().
				Background(Primary).
				Foreground(Background)

	DialogStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(Warning).
			Padding(1, 2)

	DialogConfirmStyle = lipgloss.NewStyle().
				Foreground(Error).
				Bold(true)

	ErrorBannerStyle = lipgloss.NewStyle().
				Foreground(Error).
				Background(Surface).
				Padding(0, 1)

	SuccessBannerStyle = lipgloss.NewStyle().
				Foreground(Success)

	TierVulnerable = lipgloss.NewStyle().Foreground(Error).Bold(true)
	TierBasic      = lipgloss.NewStyle().Foreground(Warning)
	TierProtected  = lipgloss.NewStyle().Foreground(Success)
	TierHardened   = lipgloss.NewStyle().Foreground(Success).Bold(true)
	TierFortress   = lipgloss.NewStyle().Foreground(Primary).Bold(true)

	UnsavedIndicatorStyle = lipgloss.NewStyle().
				Foreground(Warning).
				Bold(true)
)

func TierStyle(tier string) lipgloss.Style {
	switch tier {
	case "Vulnerable":
		return TierVulnerable
	case "Basic":
		return TierBasic
	case "Protected":
		return TierProtected
	case "Hardened":
		return TierHardened
	case "Fortress":
		return TierFortress
	default:
		return StatusMutedStyle
	}
}

func StatusDot(ok bool, text string) string {
	if ok {
		return StatusOKStyle.Render("●") + " " + StatusOKStyle.Render(text)
	}
	return StatusErrStyle.Render("●") + " " + StatusErrStyle.Render(text)
}
