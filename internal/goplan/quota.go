package goplan

import (
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/MoeForge/moego/json"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const PluginID = "builtin.opencode-go"

func Covers(a *coreauth.Auth) bool {
	if a == nil || a.AuthSourceKind() != coreauth.AuthSourceConfig {
		return false
	}
	if provider := strings.ToLower(strings.TrimSpace(a.Provider)); provider != "openai-compatibility" && !strings.HasPrefix(provider, "openai-compatible-") {
		return false
	}
	base, errParse := url.Parse(strings.TrimSpace(a.Attributes["base_url"]))
	if errParse != nil || !strings.EqualFold(base.Hostname(), "opencode.ai") {
		return false
	}
	return base.Path == "/inference/go" || strings.HasPrefix(base.Path, "/inference/go/") ||
		base.Path == "/zen/go" || strings.HasPrefix(base.Path, "/zen/go/")
}

type Window struct {
	UsedPct  float64
	Limited  bool
	ResetsAt time.Time
}

type Reading struct {
	Windows [3]Window
}

type Cause uint8

const (
	OK Cause = iota
	NoSubscription
	KeyRejected
	UpstreamDown
	SchemaDrift
)

func CauseMessage(cause Cause) string {
	const prefix = "OpenCode Go usage unavailable: "
	switch cause {
	case OK:
		return ""
	case NoSubscription:
		return prefix + "subscription required"
	case KeyRejected:
		return prefix + "key rejected"
	case SchemaDrift:
		return prefix + "unexpected usage data"
	default:
		return prefix + "upstream unavailable"
	}
}

type usageWindow struct {
	Status   string   `json:"status"`
	Percent  *float64 `json:"percent"`
	ResetsAt string   `json:"resetsAt"`
}

type usageResponse struct {
	Usage struct {
		Rolling *usageWindow `json:"rolling"`
		Weekly  *usageWindow `json:"weekly"`
		Monthly *usageWindow `json:"monthly"`
	} `json:"usage"`
}

func parseUsage(body []byte) (Reading, bool) {
	var wire usageResponse
	if errDecode := json.Unmarshal(body, &wire); errDecode != nil {
		return Reading{}, false
	}
	var reading Reading
	for i, window := range [3]*usageWindow{wire.Usage.Rolling, wire.Usage.Weekly, wire.Usage.Monthly} {
		if window == nil || (window.Status != "ok" && window.Status != "rate-limited") || window.Percent == nil {
			return Reading{}, false
		}
		used := *window.Percent
		if math.IsNaN(used) || used < 0 || used > 100 {
			return Reading{}, false
		}
		reset, errParse := time.Parse(time.RFC3339, window.ResetsAt)
		if errParse != nil {
			return Reading{}, false
		}
		reading.Windows[i] = Window{UsedPct: used, Limited: window.Status == "rate-limited", ResetsAt: reset}
	}
	return reading, true
}

func Render(reading Reading) pluginapi.QuotaFetchResponse {
	response := pluginapi.QuotaFetchResponse{
		Subscription: &pluginapi.QuotaSubscription{Plan: "OpenCode Go"},
		Groups:       make([]pluginapi.QuotaGroup, len(reading.Windows)),
	}
	for i, label := range [3]string{"5-hour", "Weekly", "Monthly"} {
		window := reading.Windows[i]
		group := &response.Groups[i]
		group.DisplayName = label
		if window.Limited {
			group.Description = "Rate-limited"
		}
		group.Buckets = []pluginapi.QuotaBucket{{
			Window:            label,
			RemainingFraction: 1 - window.UsedPct/100,
			ResetTime:         window.ResetsAt.UTC().Format(time.RFC3339),
		}}
	}
	return response
}
