package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestClaudeProbeQuota(t *testing.T) {
	a := &cliproxyauth.Auth{Metadata: map[string]any{"access_token": "sk-ant-oat-test"}, ProxyURL: "http://proxy.invalid"}
	e := &ClaudeExecutor{oauthUsageFetcher: func(ctx context.Context, auth *cliproxyauth.Auth, token string) (*claudeauth.OAuthUsage, error) {
		if token != "sk-ant-oat-test" || auth.ProxyURL != a.ProxyURL {
			t.Fatal("credential snapshot not forwarded")
		}
		return &claudeauth.OAuthUsage{Complete: true, Windows: map[string]float64{"five_hour": 0, "seven_day": 0}}, nil
	}}
	before := time.Now()
	p, err := e.ProbeQuota(context.Background(), a)
	if err != nil || !p.Complete || p.SentAt.Before(before) || p.SentAt.After(time.Now()) {
		t.Fatalf("probe=%+v err=%v", p, err)
	}
	e.oauthUsageFetcher = func(context.Context, *cliproxyauth.Auth, string) (*claudeauth.OAuthUsage, error) {
		return nil, &claudeauth.OAuthUsageStatusError{Status: 429, RetryAfter: 45 * time.Minute}
	}
	_, err = e.ProbeQuota(context.Background(), a)
	var pe *cliproxyauth.QuotaProbeError
	if !errors.As(err, &pe) || pe.Status != 429 || pe.RetryAfter != 45*time.Minute {
		t.Fatalf("error=%v", err)
	}
	for _, auth := range []*cliproxyauth.Auth{nil, {}, {Attributes: map[string]string{"api_key": "key"}}, {Attributes: map[string]string{"base_url": "https://other.invalid"}, Metadata: a.Metadata}} {
		if _, err := e.ProbeQuota(context.Background(), auth); !errors.Is(err, cliproxyauth.ErrQuotaProbeUnsupported) {
			t.Fatalf("unsupported credential: %v", err)
		}
	}
}
