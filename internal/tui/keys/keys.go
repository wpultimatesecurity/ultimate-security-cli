package keys

import (
	"charm.land/bubbles/v2/key"
)

type KeyMap struct {
	Quit         key.Binding
	Help         key.Binding
	Refresh      key.Binding
	ForceRefresh key.Binding
	Redraw       key.Binding
	Back         key.Binding
	TabNext      key.Binding
	TabPrev      key.Binding

	Page1 key.Binding
	Page2 key.Binding
	Page3 key.Binding
	Page4 key.Binding
	Page5 key.Binding
	Page6 key.Binding

	Up     key.Binding
	Down   key.Binding
	Enter  key.Binding
	PageUp key.Binding
	PageDn key.Binding
	Home   key.Binding
	End    key.Binding

	Search key.Binding
	Filter key.Binding
	Save   key.Binding

	NextPage key.Binding
	PrevPage key.Binding
}

var Global = KeyMap{
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "help"),
	),
	Refresh: key.NewBinding(
		key.WithKeys("r"),
		key.WithHelp("r", "refresh"),
	),
	ForceRefresh: key.NewBinding(
		key.WithKeys("ctrl+r"),
		key.WithHelp("ctrl+r", "force refresh"),
	),
	Redraw: key.NewBinding(
		key.WithKeys("ctrl+l"),
		key.WithHelp("ctrl+l", "redraw"),
	),
	Back: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "back"),
	),
	TabNext: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next"),
	),
	TabPrev: key.NewBinding(
		key.WithKeys("shift+tab"),
		key.WithHelp("shift+tab", "prev"),
	),
	Page1: key.NewBinding(
		key.WithKeys("1"),
		key.WithHelp("1", "dashboard"),
	),
	Page2: key.NewBinding(
		key.WithKeys("2"),
		key.WithHelp("2", "score"),
	),
	Page3: key.NewBinding(
		key.WithKeys("3"),
		key.WithHelp("3", "login"),
	),
	Page4: key.NewBinding(
		key.WithKeys("4"),
		key.WithHelp("4", "2fa"),
	),
	Page5: key.NewBinding(
		key.WithKeys("5"),
		key.WithHelp("5", "settings"),
	),
	Page6: key.NewBinding(
		key.WithKeys("6"),
		key.WithHelp("6", "logs"),
	),
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "down"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "details"),
	),
	PageUp: key.NewBinding(
		key.WithKeys("pgup"),
	),
	PageDn: key.NewBinding(
		key.WithKeys("pgdown"),
	),
	Home: key.NewBinding(
		key.WithKeys("g", "home"),
	),
	End: key.NewBinding(
		key.WithKeys("G", "end"),
	),
	Search: key.NewBinding(
		key.WithKeys("/"),
		key.WithHelp("/", "search"),
	),
	Filter: key.NewBinding(
		key.WithKeys("f"),
		key.WithHelp("f", "filter"),
	),
	Save: key.NewBinding(
		key.WithKeys("ctrl+s"),
		key.WithHelp("ctrl+s", "save"),
	),
	NextPage: key.NewBinding(
		key.WithKeys("n", "right"),
	),
	PrevPage: key.NewBinding(
		key.WithKeys("p", "left"),
	),
}

func GlobalHelpEntries() []key.Binding {
	return []key.Binding{
		Global.Quit,
		Global.Help,
		Global.Refresh,
		Global.Search,
		Global.Enter,
		Global.Back,
	}
}
