package claude

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MoeForge/moego/json"
)

const UsageURL = "https://api.anthropic.com/api/oauth/usage"
const oauthUsageBodyLimit = 64 * 1024

type OAuthUsage struct {
	Windows  map[string]float64
	Complete bool
}
type OAuthUsageStatusError struct {
	Status     int
	RetryAfter time.Duration
}

func (e *OAuthUsageStatusError) Error() string {
	return fmt.Sprintf("Claude OAuth usage failed with status %d", e.Status)
}

func (o *ClaudeAuth) FetchOAuthUsage(ctx context.Context, accessToken string) (*OAuthUsage, error) {
	body, errFetch := o.fetchOAuthControlPlaneJSON(ctx, UsageURL, accessToken, "usage")
	if errFetch != nil {
		return nil, errFetch
	}
	return parseOAuthUsage(body)
}

func oauthUsageRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && seconds > 0 && seconds <= math.MaxInt64/int64(time.Second) {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}

func parseOAuthUsage(body []byte) (*OAuthUsage, error) {
	if len(body) > oauthUsageBodyLimit || !json.Valid(body) {
		return nil, fmt.Errorf("invalid Claude OAuth usage response")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := rejectUsageDuplicates(dec, 0); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing Claude OAuth usage data")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("Claude OAuth usage must be an object")
	}
	usage := &OAuthUsage{Windows: make(map[string]float64)}
	_, hasFive := fields["five_hour"]
	seven, hasSeven := fields["seven_day"]
	usage.Complete = hasFive && hasSeven && !isUsageNull(seven)
	fable, hasFable, errFable := parseOAuthFableLimit(fields["limits"])
	if errFable != nil {
		return nil, errFable
	}
	for key, raw := range fields {
		known := key == "five_hour" || key == "seven_day" || strings.HasPrefix(key, "seven_day_") || key == "iguana_necktie"
		if !known {
			if key == "limits" || key == "extra_usage" {
				continue
			}
			var obj map[string]json.RawMessage
			_ = json.Unmarshal(raw, &obj)
			_, utilization := obj["utilization"]
			_, resets := obj["resets_at"]
			if utilization || resets || strings.HasPrefix(key, "five_hour_") {
				return nil, fmt.Errorf("unrecognized Claude OAuth usage window")
			}
			continue
		}
		if isUsageNull(raw) {
			if key == "five_hour" {
				usage.Windows["five_hour"] = 0
			}
			continue
		}
		var window map[string]json.RawMessage
		if err := json.Unmarshal(raw, &window); err != nil || window == nil {
			return nil, fmt.Errorf("invalid Claude OAuth usage window")
		}
		used, errUsed := usagePercent(window["utilization"])
		if errUsed != nil {
			return nil, errUsed
		}
		if err := validateUsageReset(window["resets_at"]); err != nil {
			return nil, err
		}
		if key == "iguana_necktie" && hasFable {
			credit := false
			for _, field := range []string{"limit_dollars", "used_dollars", "remaining_dollars"} {
				if v, ok := window[field]; ok && !isUsageNull(v) {
					var n float64
					if json.Unmarshal(v, &n) != nil {
						var text string
						if json.Unmarshal(v, &text) != nil {
							return nil, fmt.Errorf("invalid Claude OAuth dollar balance")
						}
						parsed, errParse := strconv.ParseFloat(strings.TrimSpace(text), 64)
						if errParse != nil {
							return nil, fmt.Errorf("invalid Claude OAuth dollar balance")
						}
						n = parsed
					}
					if math.IsNaN(n) || math.IsInf(n, 0) {
						return nil, fmt.Errorf("invalid Claude OAuth dollar balance")
					}
					credit = true
				}
			}
			if !credit {
				continue
			}
		}
		usage.Windows[key] = used
	}
	if hasFable {
		usage.Windows["limits/fable"] = fable
	}
	return usage, nil
}
func isUsageNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }
func usagePercent(raw json.RawMessage) (float64, error) {
	var value float64
	if len(raw) == 0 || isUsageNull(raw) {
		return 0, fmt.Errorf("missing Claude OAuth usage utilization")
	}
	if err := json.Unmarshal(raw, &value); err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100 {
		return 0, fmt.Errorf("invalid Claude OAuth usage utilization")
	}
	return value, nil
}
func validateUsageReset(raw json.RawMessage) error {
	if len(raw) == 0 || isUsageNull(raw) {
		return nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("invalid Claude OAuth usage reset")
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return fmt.Errorf("invalid Claude OAuth usage reset")
	}
	return nil
}
func parseOAuthFableLimit(raw json.RawMessage) (float64, bool, error) {
	if len(raw) == 0 || isUsageNull(raw) {
		return 0, false, nil
	}
	var limits []struct {
		Kind  string `json:"kind"`
		Scope struct {
			Model struct {
				DisplayName string `json:"display_name"`
			} `json:"model"`
		} `json:"scope"`
		Percent  json.RawMessage `json:"percent"`
		ResetsAt json.RawMessage `json:"resets_at"`
		Active   bool            `json:"is_active"`
	}
	if err := json.Unmarshal(raw, &limits); err != nil {
		return 0, false, fmt.Errorf("invalid Claude OAuth usage limits")
	}
	var chosen float64
	found, active := false, false
	for _, limit := range limits {
		name := strings.ToLower(strings.TrimSpace(limit.Scope.Model.DisplayName))
		if strings.ToLower(strings.TrimSpace(limit.Kind)) != "weekly_scoped" || (name != "fable" && name != "fable 5") {
			continue
		}
		percent, err := usagePercent(limit.Percent)
		if err != nil {
			return 0, false, err
		}
		if err := validateUsageReset(limit.ResetsAt); err != nil {
			return 0, false, err
		}
		if !found || !active && limit.Active {
			chosen, found, active = percent, true, limit.Active
		}
	}
	return chosen, found, nil
}

// Validate object keys before unmarshalling maps, which otherwise lose duplicates.
func rejectUsageDuplicates(dec *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("Claude OAuth usage nesting too deep")
	}
	token, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid Claude OAuth usage JSON")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			key, errKey := dec.Token()
			if errKey != nil {
				return fmt.Errorf("invalid Claude OAuth usage key")
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate Claude OAuth usage key")
			}
			seen[name] = true
			if err := rejectUsageDuplicates(dec, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := rejectUsageDuplicates(dec, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid Claude OAuth usage delimiter")
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("invalid Claude OAuth usage JSON")
	}
	return nil
}
