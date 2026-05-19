package messages

import (
	"context"
	"time"

	"github.com/wpultimatesecurity/ultimate-security-cli/internal/api"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/cache"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/config"
	"github.com/wpultimatesecurity/ultimate-security-cli/internal/pageid"
)

type PageDeps struct {
	Site  *config.SiteConfig
	API   *api.Client
	Cache *cache.Cache[cache.SiteKey, interface{}]
	Ctx   context.Context
}

type NavigateMsg struct {
	Target pageid.ID
}

type RefreshMsg struct {
	Page  pageid.ID
	Force bool
}

type APIErrorMsg struct {
	Page pageid.ID
	Err  error
}

type StatusMsg struct {
	Text  string
	Level StatusLevel
}

type StatusLevel int

const (
	StatusInfo StatusLevel = iota
	StatusSuccess
	StatusWarning
	StatusError
)

type ConnectionChangedMsg struct {
	Site      *config.SiteConfig
	Connected bool
	Version   string
	Err       error
}

type PluginInfoLoadedMsg struct {
	Info *api.PluginInfo
	Err  error
}

type SystemInfoLoadedMsg struct {
	Info api.SystemInfo
	Err  error
}

type SecurityScoreLoadedMsg struct {
	Score *api.SecurityScore
	Err   error
}

type ScoreChecksLoadedMsg struct {
	Checks *api.ScoreChecks
	Err    error
}

type FailedLoginsLoadedMsg struct {
	Result *api.FailedLoginResult
	Err    error
}

type WhosOnlineLoadedMsg struct {
	Result *api.WhosOnlineResult
	Err    error
}

type SiteStatusLoadedMsg struct {
	Status api.SiteStatus
	Err    error
}

type ServerStatusLoadedMsg struct {
	Status api.ServerStatus
	Err    error
}

type OptionsLoadedMsg struct {
	Options api.OptionsResult
	Err     error
}

type OptionsSavedMsg struct {
	Result *api.OptionsSaveResult
	Err    error
}

type AuditLogsLoadedMsg struct {
	Result *api.AuditLogResult
	Err    error
}

type AuditLogStatsLoadedMsg struct {
	Stats api.AuditLogStats
	Err   error
}

type EventTypesLoadedMsg struct {
	Types api.EventTypesResult
	Err   error
}

type SettingsExportedMsg struct {
	Export *api.SettingsExport
	Err    error
}

type SettingsImportedMsg struct {
	Result *api.SettingsImportResult
	Err    error
}

type CachePurgedMsg struct {
	Result *api.CachePurgeResult
	Err    error
}

type SettingsResetMsg struct {
	Result *api.TFASimpleResult
	Err    error
}

type DeactivationURLMsg struct {
	Result *api.DeactivationURLResult
	Err    error
}

type TFAStatusMsg struct {
	Status *api.TFAStatus
	Err    error
}

type TFAProviderMsg struct {
	Status *api.TFAProviderStatus
	Err    error
}

type TFABackupCodesMsg struct {
	Status *api.TFABackupCodesStatus
	Err    error
}

type TFAEmailStatusMsg struct {
	Status *api.TFAEmailStatus
	Err    error
}

type TFASecretMsg struct {
	Result *api.TFASecretResult
	Err    error
}

type TFASimpleMsg struct {
	Result *api.TFASimpleResult
	Err    error
}

type TFAGenericStatusMsg struct {
	Status *api.TFAGenericStatus
	Err    error
}

type ClockTickMsg struct {
	Time time.Time
}
