package checks

func init() {
	Register(Simple{
		Meta: Meta{
			ID:          "XMLRPC_ENABLED",
			Title:       "XML-RPC is enabled",
			Category:    CatHardning,
			Description: "XML-RPC enables some brute-force amplification (system.multicall) and is rarely needed unless a specific integration uses it. It is NOT automatically a vulnerability — most sites simply don't need it. Determined from the live filter; static file presence proves nothing, so without WP-CLI this check skips.",
			References: []string{
				"https://developer.wordpress.org/advanced-administration/security/securing-your-site/",
			},
		},
		Run: runXMLRPC,
	})
}

func runXMLRPC(ctx *Context) []Finding {
	m := Meta{ID: "XMLRPC_ENABLED", Title: "XML-RPC is enabled", Category: CatHardning,
		References: []string{"https://developer.wordpress.org/advanced-administration/security/securing-your-site/"}}
	if ctx.WP == nil || ctx.WP.XMLRPC == nil {
		return []Finding{m.skipf("live filter state requires WP-CLI; file presence is not proof")}
	}
	if *ctx.WP.XMLRPC {
		return []Finding{Finding{
			ID: m.ID, Title: m.Title, Category: m.Category,
			Severity: SevLow, Status: StatusFailed, Confidence: ConfHigh,
			Description:    "The xmlrpc_enabled filter is true. XML-RPC is unused by most sites and enables multi-call brute-force; if nothing integrates with it, disable it.",
			Evidence:       map[string]string{"filter": "xmlrpc_enabled", "value": "true"},
			Recommendation: "If no integration needs XML-RPC, disable it (e.g. add_filter( 'xmlrpc_enabled', '__return_false' ) in a must-use plugin).",
			References:     m.References,
		}}
	}
	return []Finding{Finding{ID: m.ID, Title: "XML-RPC disabled", Category: m.Category,
		Severity: SevInfo, Status: StatusPassed, Confidence: ConfHigh,
		Description: "The xmlrpc_enabled filter is false."}}
}
