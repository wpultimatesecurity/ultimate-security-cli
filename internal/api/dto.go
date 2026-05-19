package api

import (
	"encoding/json"
	"fmt"
	"time"
)

type PluginInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type SystemInfo map[string]interface{}

type SiteStatus map[string]interface{}
type ServerStatus map[string]interface{}

type SecurityScore struct {
	Tier       ScoreTier                `json:"tier"`
	Points     ScorePoints              `json:"points"`
	NextTier   *ScoreNextTier           `json:"nextTier"`
	Categories map[string]ScoreCategory `json:"categories"`
	Gates      map[string]ScoreGate     `json:"gates"`
}

type ScoreTier struct {
	Level int    `json:"level"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

type ScorePoints struct {
	Earned int `json:"earned"`
	Max    int `json:"max"`
}

type ScoreNextTier struct {
	Level        int      `json:"level"`
	Name         string   `json:"name"`
	PointsNeeded int      `json:"pointsNeeded"`
	BlockedBy    []string `json:"blockedBy"`
}

type ScoreCategory struct {
	Earned int        `json:"earned"`
	Max    int        `json:"max"`
	Items  []CheckDef `json:"items"`
}

type ScoreGate struct {
	Passed          bool `json:"passed"`
	RequiredForTier int  `json:"requiredForTier"`
}

type ScoreChecks struct {
	Score  SecurityScore       `json:"-"`
	Tiers  map[string]TierDef  `json:"tiers"`
	Checks map[string]CheckDef `json:"checks"`
}

type TierDef struct {
	Level     int           `json:"level"`
	Name      string        `json:"name"`
	MinPoints int           `json:"minPoints"`
	MaxPoints int           `json:"maxPoints"`
	Color     string        `json:"color"`
	Gates     []interface{} `json:"gates"`
}

type CheckDef struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Points      int    `json:"points"`
	Category    string `json:"category"`
	GateForTier int    `json:"gate_for_tier"`
	ProOnly     bool   `json:"pro_only"`
}

type FailedLoginResult struct {
	TotalFailed int              `json:"total_failed"`
	Logs        []FailedLoginLog `json:"logs"`
}

type FailedLoginLog struct {
	ID        int    `json:"id"`
	EventType string `json:"event_type"`
	UserID    int    `json:"user_id"`
	Username  string `json:"username"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

type WhosOnlineResult struct {
	Users []OnlineUser `json:"users"`
	Count int          `json:"count"`
}

type OnlineUser struct {
	UserID       int    `json:"user_id"`
	Username     string `json:"username"`
	IPAddress    string `json:"ip_address"`
	LastActivity string `json:"last_activity"`
	Status       string `json:"status"`
}

type AuditLogResult struct {
	Logs       []AuditLog `json:"logs"`
	Total      int        `json:"total"`
	Page       int        `json:"page"`
	PerPage    int        `json:"per_page"`
	TotalPages int        `json:"total_pages"`
}

type AuditLog struct {
	ID        int             `json:"id"`
	EventType string          `json:"event_type"`
	UserID    int             `json:"user_id"`
	Username  string          `json:"username"`
	IPAddress string          `json:"ip_address"`
	UserAgent string          `json:"user_agent"`
	Message   string          `json:"message"`
	Severity  string          `json:"severity"`
	Context   json.RawMessage `json:"context"`
	CreatedAt string          `json:"created_at"`
}

type AuditLogStats map[string]interface{}

type EventTypesResult map[string]string

type OptionsResult map[string]interface{}

type SettingsExport struct {
	Version       string                 `json:"version"`
	PluginVersion string                 `json:"plugin_version"`
	ExportedAt    string                 `json:"exported_at"`
	Settings      map[string]interface{} `json:"settings"`
}

type SettingsImportResult struct {
	Success  bool                      `json:"success"`
	DryRun   bool                      `json:"dry_run"`
	Changes  map[string]SettingsChange `json:"changes"`
	Errors   []string                  `json:"errors"`
	Warnings []string                  `json:"warnings"`
}

type SettingsChange struct {
	Action string      `json:"action"`
	Old    interface{} `json:"old"`
	New    interface{} `json:"new"`
}

type OptionsSaveResult struct {
	Success        bool                   `json:"success"`
	Message        string                 `json:"msg"`
	UpdatedOptions map[string]interface{} `json:"updated_options"`
}

type DeactivationURLResult struct {
	Success bool   `json:"success"`
	URL     string `json:"url"`
}

type TFAStatus struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
}

type TFAProviderStatus struct {
	Provider  string   `json:"provider"`
	Available []string `json:"available"`
}

type TFASecretResult struct {
	Success bool   `json:"success"`
	Secret  string `json:"secret"`
	QRCode  string `json:"qr_code"`
	Counter int    `json:"counter,omitempty"`
}

type TFAEmailStatus struct {
	Enabled bool   `json:"enabled"`
	Email   string `json:"email"`
}

type TFABackupCodesStatus struct {
	Available bool `json:"available"`
	Count     int  `json:"count"`
}

type TFAGenericStatus struct {
	Enabled bool `json:"enabled"`
}

type TFASimpleResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type CachePurgeResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func ParseTime(s string) (time.Time, error) {
	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time: %s", s)
}
