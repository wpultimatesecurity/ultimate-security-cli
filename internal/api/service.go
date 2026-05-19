package api

import (
	"context"
	"encoding/json"
	"net/url"
)

type ConnectionService struct {
	client *Client
}

func NewConnectionService(c *Client) *ConnectionService {
	return &ConnectionService{client: c}
}

func (s *ConnectionService) TestConnection(ctx context.Context) (*PluginInfo, error) {
	data, err := s.client.Get(ctx, RoutePluginInfo, nil)
	if err != nil {
		return nil, err
	}
	var info PluginInfo
	if err := DecodeDirect(data, &info); err != nil {
		if err2 := DecodeResponse(data, &info); err2 != nil {
			return nil, ValidationError("cannot parse plugin-info response")
		}
	}
	return &info, nil
}

func (s *ConnectionService) GetSystemInfo(ctx context.Context) (SystemInfo, error) {
	data, err := s.client.Get(ctx, RouteSystemInfo, nil)
	if err != nil {
		return nil, err
	}
	var info SystemInfo
	if err := DecodeDirect(data, &info); err != nil {
		return nil, err
	}
	return info, nil
}

func (s *ConnectionService) GetSiteStatus(ctx context.Context) (SiteStatus, error) {
	data, err := s.client.Get(ctx, RouteSiteStatus, nil)
	if err != nil {
		return nil, err
	}
	var status SiteStatus
	_ = DecodeDirect(data, &status)
	return status, nil
}

func (s *ConnectionService) GetServerStatus(ctx context.Context) (ServerStatus, error) {
	data, err := s.client.Get(ctx, RouteServerStatus, nil)
	if err != nil {
		return nil, err
	}
	var status ServerStatus
	_ = DecodeDirect(data, &status)
	return status, nil
}

type ScoreService struct {
	client *Client
}

func NewScoreService(c *Client) *ScoreService {
	return &ScoreService{client: c}
}

func (s *ScoreService) GetScore(ctx context.Context) (*SecurityScore, error) {
	data, err := s.client.Get(ctx, RouteSecurityScore, nil)
	if err != nil {
		return nil, err
	}
	var score SecurityScore
	if err := DecodeResponse(data, &score); err != nil {
		return nil, err
	}
	return &score, nil
}

func (s *ScoreService) GetChecks(ctx context.Context) (*ScoreChecks, error) {
	data, err := s.client.Get(ctx, RouteSecurityScoreChecks, nil)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, ValidationError("cannot parse score checks response")
	}

	result := &ScoreChecks{}

	if d, ok := raw["success"]; ok {
		var success bool
		if json.Unmarshal(d, &success) == nil && success {
			if inner, ok := raw["data"]; ok {
				raw = map[string]json.RawMessage{}
				json.Unmarshal(inner, &raw)
			}
		}
	}

	if d, ok := raw["tiers"]; ok {
		_ = json.Unmarshal(d, &result.Tiers)
	}
	if d, ok := raw["checks"]; ok {
		_ = json.Unmarshal(d, &result.Checks)
	}

	score := &SecurityScore{}
	if d, ok := raw["tier"]; ok {
		_ = json.Unmarshal(d, &score.Tier)
	}
	if d, ok := raw["points"]; ok {
		_ = json.Unmarshal(d, &score.Points)
	}
	if d, ok := raw["nextTier"]; ok {
		_ = json.Unmarshal(d, &score.NextTier)
	}
	if d, ok := raw["categories"]; ok {
		_ = json.Unmarshal(d, &score.Categories)
	}
	if d, ok := raw["gates"]; ok {
		_ = json.Unmarshal(d, &score.Gates)
	}
	result.Score = *score

	return result, nil
}

func (s *ScoreService) Refresh(ctx context.Context) (*SecurityScore, error) {
	data, err := s.client.Post(ctx, RouteSecurityScoreRefresh, nil, nil)
	if err != nil {
		return nil, err
	}
	var score SecurityScore
	if err := DecodeResponse(data, &score); err != nil {
		return nil, err
	}
	return &score, nil
}

type OptionsService struct {
	client *Client
}

func NewOptionsService(c *Client) *OptionsService {
	return &OptionsService{client: c}
}

func (s *OptionsService) GetOptions(ctx context.Context, section string) (OptionsResult, error) {
	params := url.Values{}
	addQueryParam(params, "section", section)
	data, err := s.client.Get(ctx, RouteOptions, params)
	if err != nil {
		return nil, err
	}
	var opts OptionsResult
	if err := DecodeDirect(data, &opts); err != nil {
		return nil, err
	}
	return opts, nil
}

func (s *OptionsService) SaveOptions(ctx context.Context, subtree map[string]interface{}) (*OptionsSaveResult, error) {
	body := map[string]interface{}{
		"ultimate_security_options": subtree,
	}
	data, err := s.client.Post(ctx, RouteOptions, nil, body)
	if err != nil {
		return nil, err
	}
	var result OptionsSaveResult
	if err := DecodeDirect(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *OptionsService) ResetSettings(ctx context.Context) (*TFASimpleResult, error) {
	data, err := s.client.Post(ctx, RouteResetSettings, nil, nil)
	if err != nil {
		return nil, err
	}
	var result TFASimpleResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *OptionsService) PurgeCache(ctx context.Context) (*CachePurgeResult, error) {
	data, err := s.client.Post(ctx, RouteSettingsPurgeCache, nil, nil)
	if err != nil {
		return nil, err
	}
	var result CachePurgeResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *OptionsService) ClearCache(ctx context.Context) (*CachePurgeResult, error) {
	data, err := s.client.Post(ctx, RouteClearCache, nil, nil)
	if err != nil {
		return nil, err
	}
	var result CachePurgeResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *OptionsService) RegenerateDeactivationURL(ctx context.Context) (*DeactivationURLResult, error) {
	data, err := s.client.Post(ctx, RouteRegenerateDeactivation, nil, nil)
	if err != nil {
		return nil, err
	}
	var result DeactivationURLResult
	if err := DecodeDirect(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type SettingsService struct {
	client *Client
}

func NewSettingsService(c *Client) *SettingsService {
	return &SettingsService{client: c}
}

func (s *SettingsService) Export(ctx context.Context, includeSecrets bool) (*SettingsExport, error) {
	params := url.Values{}
	addQueryBool(params, "include_secrets", includeSecrets)
	data, err := s.client.Get(ctx, RouteSettings, params)
	if err != nil {
		return nil, err
	}
	var exp SettingsExport
	if err := DecodeDirect(data, &exp); err != nil {
		return nil, err
	}
	return &exp, nil
}

func (s *SettingsService) Import(ctx context.Context, settings interface{}, dryRun bool) (*SettingsImportResult, error) {
	params := url.Values{}
	addQueryBool(params, "dry_run", dryRun)
	data, err := s.client.Post(ctx, RouteSettings, params, settings)
	if err != nil {
		return nil, err
	}
	var result SettingsImportResult
	if err := DecodeDirect(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type TFAService struct {
	client *Client
}

func NewTFAService(c *Client) *TFAService {
	return &TFAService{client: c}
}

func (s *TFAService) GetStatus(ctx context.Context) (*TFAStatus, error) {
	data, err := s.client.Get(ctx, RouteTFAStatus, nil)
	if err != nil {
		return nil, err
	}
	var status TFAStatus
	if err := DecodeResponse(data, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (s *TFAService) GetProvider(ctx context.Context) (*TFAProviderStatus, error) {
	data, err := s.client.Get(ctx, RouteTFAProvider, nil)
	if err != nil {
		return nil, err
	}
	var status TFAProviderStatus
	_ = DecodeResponse(data, &status)
	return &status, nil
}

func (s *TFAService) SetProvider(ctx context.Context, provider string) (*TFASimpleResult, error) {
	body := map[string]string{"provider": provider}
	data, err := s.client.Post(ctx, RouteTFAProvider, nil, body)
	if err != nil {
		return nil, err
	}
	var result TFASimpleResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *TFAService) GetBackupCodesStatus(ctx context.Context) (*TFABackupCodesStatus, error) {
	data, err := s.client.Get(ctx, RouteTFABackupCodesStatus, nil)
	if err != nil {
		return nil, err
	}
	var status TFABackupCodesStatus
	_ = DecodeResponse(data, &status)
	return &status, nil
}

func (s *TFAService) GetEmailStatus(ctx context.Context) (*TFAEmailStatus, error) {
	data, err := s.client.Get(ctx, RouteTFAEmailStatus, nil)
	if err != nil {
		return nil, err
	}
	var status TFAEmailStatus
	_ = DecodeResponse(data, &status)
	return &status, nil
}

func (s *TFAService) EmailSendCode(ctx context.Context) (*TFASimpleResult, error) {
	data, err := s.client.Post(ctx, RouteTFAEmailSendCode, nil, nil)
	if err != nil {
		return nil, err
	}
	var result TFASimpleResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *TFAService) EmailVerify(ctx context.Context, code string) (*TFASimpleResult, error) {
	body := map[string]string{"code": code}
	data, err := s.client.Post(ctx, RouteTFAEmailVerify, nil, body)
	if err != nil {
		return nil, err
	}
	var result TFASimpleResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *TFAService) EmailDisable(ctx context.Context) (*TFASimpleResult, error) {
	data, err := s.client.Post(ctx, RouteTFAEmailDisable, nil, nil)
	if err != nil {
		return nil, err
	}
	var result TFASimpleResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *TFAService) GetTOTPStatus(ctx context.Context) (*TFAGenericStatus, error) {
	data, err := s.client.Get(ctx, RouteTFATOTPStatus, nil)
	if err != nil {
		return nil, err
	}
	var status TFAGenericStatus
	_ = DecodeResponse(data, &status)
	return &status, nil
}

func (s *TFAService) TOTPSetup(ctx context.Context) (*TFASecretResult, error) {
	data, err := s.client.Post(ctx, RouteTFATOTPSetup, nil, nil)
	if err != nil {
		return nil, err
	}
	var result TFASecretResult
	if err := DecodeResponse(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *TFAService) TOTPVerify(ctx context.Context, code string) (*TFASimpleResult, error) {
	body := map[string]string{"code": code}
	data, err := s.client.Post(ctx, RouteTFATOTPVerify, nil, body)
	if err != nil {
		return nil, err
	}
	var result TFASimpleResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *TFAService) TOTPDisable(ctx context.Context) (*TFASimpleResult, error) {
	data, err := s.client.Post(ctx, RouteTFATOTPDisable, nil, nil)
	if err != nil {
		return nil, err
	}
	var result TFASimpleResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *TFAService) GetHOTPStatus(ctx context.Context) (*TFAGenericStatus, error) {
	data, err := s.client.Get(ctx, RouteTFAHOTPStatus, nil)
	if err != nil {
		return nil, err
	}
	var status TFAGenericStatus
	_ = DecodeResponse(data, &status)
	return &status, nil
}

func (s *TFAService) HOTPSetup(ctx context.Context) (*TFASecretResult, error) {
	data, err := s.client.Post(ctx, RouteTFAHOTPSetup, nil, nil)
	if err != nil {
		return nil, err
	}
	var result TFASecretResult
	if err := DecodeResponse(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *TFAService) HOTPVerify(ctx context.Context, code string) (*TFASimpleResult, error) {
	body := map[string]string{"code": code}
	data, err := s.client.Post(ctx, RouteTFAHOTPVerify, nil, body)
	if err != nil {
		return nil, err
	}
	var result TFASimpleResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *TFAService) HOTPDisable(ctx context.Context) (*TFASimpleResult, error) {
	data, err := s.client.Post(ctx, RouteTFAHOTPDisable, nil, nil)
	if err != nil {
		return nil, err
	}
	var result TFASimpleResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

type LogsService struct {
	client *Client
}

func NewLogsService(c *Client) *LogsService {
	return &LogsService{client: c}
}

type AuditLogParams struct {
	Page      int
	PerPage   int
	EventType string
	Severity  string
	UserID    int
	Search    string
	DateFrom  string
	DateTo    string
}

func (s *LogsService) GetLogs(ctx context.Context, params AuditLogParams) (*AuditLogResult, error) {
	q := url.Values{}
	addQueryInt(q, "page", params.Page)
	addQueryInt(q, "per_page", params.PerPage)
	addQueryParam(q, "event_type", params.EventType)
	addQueryParam(q, "severity", params.Severity)
	addQueryInt(q, "user_id", params.UserID)
	addQueryParam(q, "search", params.Search)
	addQueryParam(q, "date_from", params.DateFrom)
	addQueryParam(q, "date_to", params.DateTo)

	data, err := s.client.Get(ctx, RouteAuditLogs, q)
	if err != nil {
		return nil, err
	}
	var result AuditLogResult
	if err := DecodeResponse(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *LogsService) GetStats(ctx context.Context) (AuditLogStats, error) {
	data, err := s.client.Get(ctx, RouteAuditLogStats, nil)
	if err != nil {
		return nil, err
	}
	var stats AuditLogStats
	_ = DecodeResponse(data, &stats)
	return stats, nil
}

func (s *LogsService) GetEventTypes(ctx context.Context) (EventTypesResult, error) {
	data, err := s.client.Get(ctx, RouteAuditLogEventTypes, nil)
	if err != nil {
		return nil, err
	}
	var types EventTypesResult
	if err := DecodeResponse(data, &types); err != nil {
		return nil, err
	}
	return types, nil
}

func (s *LogsService) Cleanup(ctx context.Context, days int) (*TFASimpleResult, error) {
	params := url.Values{}
	addQueryInt(params, "days", days)
	data, err := s.client.Delete(ctx, RouteAuditLogCleanup, params)
	if err != nil {
		return nil, err
	}
	var result TFASimpleResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}

func (s *LogsService) GetFailedLoginLogs(ctx context.Context) (*FailedLoginResult, error) {
	data, err := s.client.Get(ctx, RouteGetLoginFailedLogs, nil)
	if err != nil {
		return nil, err
	}
	var result FailedLoginResult
	if err := DecodeDirect(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *LogsService) GetWhosOnline(ctx context.Context, limit int, includeSelf bool, status string) (*WhosOnlineResult, error) {
	params := url.Values{}
	addQueryInt(params, "limit", limit)
	addQueryBool(params, "include_self", includeSelf)
	addQueryParam(params, "status", status)

	data, err := s.client.Get(ctx, RouteWhosOnline, params)
	if err != nil {
		return nil, err
	}
	var result WhosOnlineResult
	_ = DecodeDirect(data, &result)
	return &result, nil
}
