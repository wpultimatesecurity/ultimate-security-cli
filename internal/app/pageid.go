package app

import "github.com/wpultimatesecurity/ultimate-security-cli/internal/pageid"

type PageID = pageid.ID

const (
	PageSetup     = pageid.Setup
	PageDashboard = pageid.Dashboard
	PageScore     = pageid.Score
	PageLogin     = pageid.Login
	PageTFA       = pageid.TFA
	PageSettings  = pageid.Settings
	PageLogs      = pageid.Logs
)

var PageOrder = pageid.Order
