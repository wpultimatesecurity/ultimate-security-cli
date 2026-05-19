package cache

import "time"

type Key string

const (
	KeyPluginInfo          Key = "plugin_info"
	KeySystemInfo          Key = "system_info"
	KeySecurityScore       Key = "security_score"
	KeySecurityScoreChecks Key = "security_score_checks"
	KeyFailedLoginSummary  Key = "failed_login_summary"
	KeyWhosOnline          Key = "whos_online"
	KeyOptions             Key = "options"
	KeyAuditLogs           Key = "audit_logs"
	KeyAuditLogStats       Key = "audit_log_stats"
	KeyTFA                 Key = "twofa"
	KeySettings            Key = "settings"
	KeySiteStatus          Key = "site_status"
	KeyServerStatus        Key = "server_status"
	KeyEventTypes          Key = "event_types"
)

type SiteKey struct {
	Site   string
	Key    Key
	Params string
}

func PluginInfoKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeyPluginInfo}
}

func SystemInfoKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeySystemInfo}
}

func SecurityScoreKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeySecurityScore}
}

func SecurityScoreChecksKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeySecurityScoreChecks}
}

func FailedLoginSummaryKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeyFailedLoginSummary}
}

func WhosOnlineKey(site, params string) SiteKey {
	return SiteKey{Site: site, Key: KeyWhosOnline, Params: params}
}

func OptionsKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeyOptions}
}

func AuditLogsKey(site, params string) SiteKey {
	return SiteKey{Site: site, Key: KeyAuditLogs, Params: params}
}

func AuditLogStatsKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeyAuditLogStats}
}

func TFAKey(site string, kind string) SiteKey {
	return SiteKey{Site: site, Key: KeyTFA, Params: kind}
}

func SettingsKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeySettings}
}

func SiteStatusKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeySiteStatus}
}

func ServerStatusKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeyServerStatus}
}

func EventTypesKey(site string) SiteKey {
	return SiteKey{Site: site, Key: KeyEventTypes}
}

func IsSitePrefix(site string) func(SiteKey) bool {
	return func(k SiteKey) bool {
		return k.Site == site
	}
}

func IsOptionsKeys(k SiteKey) bool {
	return k.Key == KeyOptions
}

func IsScoreKeys(k SiteKey) bool {
	return k.Key == KeySecurityScore || k.Key == KeySecurityScoreChecks
}

func IsDashboardKeys(k SiteKey) bool {
	switch k.Key {
	case KeyPluginInfo, KeySystemInfo, KeySecurityScore, KeySecurityScoreChecks,
		KeyFailedLoginSummary, KeyWhosOnline, KeySiteStatus, KeyServerStatus:
		return true
	}
	return false
}

func IsTFAKeys(k SiteKey) bool {
	return k.Key == KeyTFA
}

var TTLs = map[Key]time.Duration{
	KeyPluginInfo:          5 * time.Minute,
	KeySystemInfo:          5 * time.Minute,
	KeySecurityScore:       60 * time.Second,
	KeySecurityScoreChecks: 60 * time.Second,
	KeyFailedLoginSummary:  30 * time.Second,
	KeyWhosOnline:          30 * time.Second,
	KeyOptions:             5 * time.Minute,
	KeyAuditLogs:           30 * time.Second,
	KeyAuditLogStats:       30 * time.Second,
	KeyTFA:                 30 * time.Second,
	KeySettings:            5 * time.Minute,
	KeySiteStatus:          5 * time.Minute,
	KeyServerStatus:        5 * time.Minute,
	KeyEventTypes:          5 * time.Minute,
}

func TTL(k Key) time.Duration {
	if t, ok := TTLs[k]; ok {
		return t
	}
	return 60 * time.Second
}
