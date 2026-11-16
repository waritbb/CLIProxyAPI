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
	body, errFetch := o.fetchOAuthUsageJSON(ctx, accessToken)
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
	for _, key := range []string{"five_hour", "seven_day"} {
		raw, present := fields[key]
		if !present {
			continue
		}
		if isUsageNull(raw) {
			if key == "five_hour" {
				usage.Windows[key] = 0
			}
			continue
		}
		var window map[string]json.RawMessage
		if err := json.Unmarshal(raw, &window); err != nil || window == nil {
			return nil, fmt.Errorf("invalid Claude OAuth usage window")
		}
		used, err := usagePercent(window["utilization"])
		if err != nil {
			return nil, err
		}
		if err := validateUsageReset(window["resets_at"]); err != nil {
			return nil, err
		}
		usage.Windows[key] = used
	}
	return usage, nil
}
func isUsageNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }
func usagePercent(raw json.RawMessage) (float64, error) {
	var value float64
	if len(raw) == 0 || isUsageNull(raw) {
		return 0, fmt.Errorf("missing Claude OAuth usage utilization")
	}
	if err := json.Unmarshal(raw, &value); err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
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
