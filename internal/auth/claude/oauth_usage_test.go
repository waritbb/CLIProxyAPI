package claude

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseOAuthUsage(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		complete   bool
		windows    map[string]float64
	}{
		{"empty", `{}`, false, map[string]float64{}},
		{"reset", `{"five_hour":null,"seven_day":{"utilization":0}}`, true, map[string]float64{"five_hour": 0, "seven_day": 0}},
		{"limited", `{"five_hour":null,"seven_day":{"utilization":100}}`, true, map[string]float64{"five_hour": 0, "seven_day": 100}},
		{"nonzero", `{"five_hour":{"utilization":17.5},"seven_day":{"utilization":89}}`, true, map[string]float64{"five_hour": 17.5, "seven_day": 89}},
		{"over_limit", `{"five_hour":{"utilization":101},"seven_day":{"utilization":150}}`, true, map[string]float64{"five_hour": 101, "seven_day": 150}},
		{"missing_five", `{"seven_day":{"utilization":23}}`, false, map[string]float64{"seven_day": 23}},
		{"null_seven", `{"five_hour":null,"seven_day":null}`, false, map[string]float64{"five_hour": 0}},
		{"missing_seven", `{"five_hour":null}`, false, map[string]float64{"five_hour": 0}},
		{"case_aliases_cannot_override", `{"five_hour":{"utilization":50,"Utilization":0},"seven_day":{"utilization":100,"Utilization":0},"Seven_day":{"utilization":0}}`, true, map[string]float64{"five_hour": 50, "seven_day": 100}},
		{"top_case_alias_only", `{"Five_hour":null,"Seven_day":{"utilization":0}}`, false, map[string]float64{}},
		{"ignored_model_limits", `{"five_hour":null,"seven_day":{"utilization":37},"seven_day_opus":{"utilization":100},"seven_day_new":42,"iguana_necktie":{"utilization":100},"limits":[{"kind":"weekly_scoped","scope":{"model":{"display_name":"Fable 5"}},"percent":100,"Percent":0}]}`, true, map[string]float64{"five_hour": 0, "seven_day": 37}},
		{"ignored_malformed_metadata", `{"five_hour":null,"seven_day":{"utilization":37},"limits":"unknown","iguana_necktie":42,"new_window":{"utilization":100}}`, true, map[string]float64{"five_hour": 0, "seven_day": 37}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := parseOAuthUsage([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if u.Complete != tc.complete || !reflect.DeepEqual(u.Windows, tc.windows) {
				t.Fatalf("got %+v, want complete=%v windows=%v", u, tc.complete, tc.windows)
			}
		})
	}

	for _, body := range []string{
		`[]`, `null`, `{"five_hour":null,"five_hour":null,"seven_day":{"utilization":0}}`,
		`{"five_hour":null,"seven_day":{"utilization":0,"utilization":1}}`,
		`{"five_hour":null,"seven_day":{"utilization":"0"}}`,
		`{"five_hour":null,"seven_day":{"utilization":null}}`,
		`{"five_hour":null,"seven_day":{"utilization":-1}}`,
		`{"five_hour":null,"seven_day":{"utilization":1e999}}`,
		`{"five_hour":null,"seven_day":{"Utilization":0}}`,
		`{"five_hour":null,"seven_day":{"utilization":0,"resets_at":"bad"}}`,
		`{"five_hour":null,"seven_day":{"utilization":0}} {}`,
		strings.Repeat(" ", 65537) + `{}`,
	} {
		_, err := parseOAuthUsage([]byte(body))
		if err == nil {
			t.Fatalf("unsafe response accepted: %.100s", body)
		}
	}
}
func TestFetchOAuthUsage(t *testing.T) {
	for _, status := range []int{200, 429} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			o := &ClaudeAuth{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != UsageURL || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("anthropic-beta") != "oauth-2025-04-20" || r.Header.Get("Cache-Control") != "no-cache" {
					t.Fatal("usage request headers or URL incorrect")
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"900"}}, Body: io.NopCloser(strings.NewReader(`{"five_hour":null,"seven_day":{"utilization":0}}`))}, nil
			})}}
			u, err := o.FetchOAuthUsage(context.Background(), "test-token")
			if status == 200 {
				if err != nil || !u.Complete {
					t.Fatalf("usage=%v err=%v", u, err)
				}
			} else {
				var se *OAuthUsageStatusError
				if !errors.As(err, &se) || se.Status != 429 || se.RetryAfter != 15*time.Minute {
					t.Fatalf("status error=%v", err)
				}
			}
		})
	}
}
func TestFetchOAuthUsageBodyLimit(t *testing.T) {
	o := &ClaudeAuth{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", 65537)))}, nil
	})}}
	if _, err := o.FetchOAuthUsage(context.Background(), "test-token"); err == nil {
		t.Fatal("oversized body accepted")
	}
}

func TestFetchOAuthUsageCompressedBodyLimit(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(strings.Repeat(" ", 65537))); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	o := &ClaudeAuth{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": []string{"gzip"}}, Body: io.NopCloser(bytes.NewReader(compressed.Bytes()))}, nil
	})}}
	if _, err := o.FetchOAuthUsage(context.Background(), "test-token"); err == nil {
		t.Fatal("oversized decoded body accepted")
	}
}
func TestOAuthUsageRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"900", 15 * time.Minute}, {now.Add(time.Hour).Format(http.TimeFormat), time.Hour}, {"bad", 0}, {"-1", 0}, {"9223372036854775807", 0},
	} {
		if got := oauthUsageRetryAfter(tc.value, now); got != tc.want {
			t.Fatalf("Retry-After %q=%v, want %v", tc.value, got, tc.want)
		}
	}
}
