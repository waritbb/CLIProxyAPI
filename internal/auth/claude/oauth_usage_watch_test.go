package claude

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type usageWatchExecutor struct {
	coreauth.ProviderExecutor
	oauth *ClaudeAuth
	calls int
}

func (*usageWatchExecutor) Identifier() string { return "claude" }
func (e *usageWatchExecutor) ProbeQuota(ctx context.Context, a *coreauth.Auth) (coreauth.QuotaProbe, error) {
	sentAt := time.Now()
	e.calls++
	usage, err := e.oauth.FetchOAuthUsage(ctx, a.Metadata["access_token"].(string))
	if err != nil {
		return coreauth.QuotaProbe{}, err
	}
	return coreauth.QuotaProbe{SentAt: sentAt, Complete: usage.Complete, Windows: usage.Windows}, nil
}

type usageWatchHook struct {
	cancel   context.CancelFunc
	decision string
}

func (*usageWatchHook) Levels() []log.Level { return log.AllLevels }
func (h *usageWatchHook) Fire(entry *log.Entry) error {
	if strings.HasPrefix(entry.Message, "quota watch: ") {
		h.decision = entry.Message
		h.cancel()
	}
	return nil
}
func TestOAuthUsageEndpointWatchVerdict(t *testing.T) {
	for _, used := range []int{0, 100, 150} {
		t.Run(fmt.Sprint(used), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			hook := &usageWatchHook{cancel: cancel}
			logger := log.StandardLogger()
			oldHooks := logger.ReplaceHooks(make(log.LevelHooks))
			t.Cleanup(func() { logger.ReplaceHooks(oldHooks) })
			logger.AddHook(hook)
			e := &usageWatchExecutor{oauth: &ClaudeAuth{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != UsageURL {
					t.Fatal("unexpected endpoint")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"five_hour":null,"seven_day":{"utilization":%d}}`, used)))}, nil
			})}}}
			m := coreauth.NewManager(nil, nil, nil)
			a, err := m.Register(ctx, &coreauth.Auth{ID: t.Name(), Provider: "claude", Status: coreauth.StatusActive, Metadata: map[string]any{"access_token": "fixture-token"}})
			if err != nil {
				t.Fatal(err)
			}
			retry := time.Hour * 72
			m.MarkResult(ctx, coreauth.Result{AuthID: a.ID, Provider: "claude", CredentialVersion: a.CredentialVersion, Model: "fixture-model", Error: &coreauth.Error{HTTPStatus: 429, Code: "rate_limit"}, RetryAfter: &retry, CredentialScope: true})
			m.RegisterExecutor(e)
			coreauth.RunQuotaWatch(ctx, m)
			got, _ := m.GetByID(a.ID)
			wantDecision := "quota watch: hold"
			if used == 0 {
				wantDecision = "quota watch: released"
			}
			if e.calls != 1 || hook.decision != wantDecision || got.Quota.Exceeded != (used >= 100) {
				t.Fatalf("calls=%d decision=%s quota=%+v", e.calls, hook.decision, got.Quota)
			}
		})
	}
}
