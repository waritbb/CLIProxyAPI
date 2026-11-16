package executor

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

var _ cliproxyauth.QuotaProber = (*ClaudeExecutor)(nil)

func (e *ClaudeExecutor) ProbeQuota(ctx context.Context, auth *cliproxyauth.Auth) (cliproxyauth.QuotaProbe, error) {
	token, baseURL := claudeCreds(auth)
	if e == nil || auth == nil || strings.TrimSpace(token) == "" || auth.Attributes["api_key"] != "" {
		return cliproxyauth.QuotaProbe{}, cliproxyauth.ErrQuotaProbeUnsupported
	}
	if baseURL != "" {
		upstream, errParse := url.Parse(baseURL)
		if errParse != nil || !helps.IsAnthropicUpstreamURL(upstream) {
			return cliproxyauth.QuotaProbe{}, cliproxyauth.ErrQuotaProbeUnsupported
		}
	}
	sentAt := time.Now()
	fetch := e.oauthUsageFetcher
	if fetch == nil {
		fetch = func(ctx context.Context, a *cliproxyauth.Auth, token string) (*claudeauth.OAuthUsage, error) {
			return claudeauth.NewClaudeAuthWithProxyURL(e.cfg, a.ProxyURL).FetchOAuthUsage(ctx, token)
		}
	}
	usage, err := fetch(ctx, auth, token)
	if err != nil {
		probeErr := &cliproxyauth.QuotaProbeError{Err: err}
		var statusErr *claudeauth.OAuthUsageStatusError
		if errors.As(err, &statusErr) {
			probeErr.Status = statusErr.Status
			probeErr.RetryAfter = statusErr.RetryAfter
		}
		return cliproxyauth.QuotaProbe{}, probeErr
	}
	if usage == nil {
		return cliproxyauth.QuotaProbe{SentAt: sentAt}, nil
	}
	return cliproxyauth.QuotaProbe{SentAt: sentAt, Windows: usage.Windows, Complete: usage.Complete}, nil
}
