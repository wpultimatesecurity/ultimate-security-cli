package pageid

type ID int

const (
	Setup ID = iota
	Dashboard
	Score
	Login
	TFA
	Settings
	Logs
)

func (p ID) String() string {
	switch p {
	case Setup:
		return "setup"
	case Dashboard:
		return "dashboard"
	case Score:
		return "score"
	case Login:
		return "login"
	case TFA:
		return "2fa"
	case Settings:
		return "settings"
	case Logs:
		return "logs"
	default:
		return "unknown"
	}
}

func (p ID) Title() string {
	switch p {
	case Setup:
		return "Connect"
	case Dashboard:
		return "Dashboard"
	case Score:
		return "Score"
	case Login:
		return "Login"
	case TFA:
		return "2FA"
	case Settings:
		return "Settings"
	case Logs:
		return "Logs"
	default:
		return ""
	}
}

var Order = []ID{
	Dashboard,
	Score,
	Login,
	TFA,
	Settings,
	Logs,
}
