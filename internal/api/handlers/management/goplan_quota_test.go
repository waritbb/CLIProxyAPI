package management

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/goplan"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/httptransport"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	goQuotaBearerA   = "synthetic-goplan-a"
	goQuotaBearerB   = "synthetic-goplan-b"
	otherQuotaBearer = "synthetic-compat-c"
)

func goQuotaFixture(t *testing.T) (*gin.Engine, *coreauth.Manager, []*coreauth.Auth, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		AuthDir: dir,
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:          "arbitrary-config-name",
				BaseURL:       "https://opencode.ai/inference/go/openai/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: goQuotaBearerA}, {APIKey: goQuotaBearerB}},
			},
			{
				Name:          "unrelated-provider",
				BaseURL:       "https://opencode.ai/zen/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: otherQuotaBearer}},
			},
		},
	}
	auths, err := synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{
		Config: cfg, Now: time.Now(), IDGenerator: synthesizer.NewStableIDGenerator(),
	})
	if err != nil || len(auths) != 3 {
		t.Fatal("could not synthesize fixture credentials")
	}
	manager := coreauth.NewManager(nil, nil, nil)
	for i, auth := range auths {
		registered, errRegister := manager.Register(t.Context(), auth)
		if errRegister != nil {
			t.Fatal("could not register fixture credential")
		}
		auths[i] = registered
	}
	h := NewHandlerWithoutConfigFilePath(cfg, manager)
	router := gin.New()
	v8 := router.Group("/v8/management", func(c *gin.Context) { c.Set(ConfigV8ContextKey, true) })
	v8.GET("/credentials", h.ListAuthFiles)
	v8.DELETE("/credentials", h.DeleteAuthFileV8)
	v8.POST("/plugins/:id/quota", h.FetchPluginQuota)
	return router, manager, auths, dir
}

func TestGoQuotaCredentials(t *testing.T) {
	router, manager, auths, dir := goQuotaFixture(t)
	assertListing := func(want ...*coreauth.Auth) {
		t.Helper()
		for _, query := range []string{"", "?page=1&page_size=50"} {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v8/management/credentials"+query, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("listing status = %d", rec.Code)
			}
			for _, secret := range []string{goQuotaBearerA, goQuotaBearerB, otherQuotaBearer} {
				if strings.Contains(rec.Body.String(), secret) {
					t.Fatal("listing leaked a credential")
				}
			}
			var payload struct {
				Files []struct {
					ID            string `json:"id"`
					AuthIndex     string `json:"auth_index"`
					RuntimeOnly   bool   `json:"runtime_only"`
					SupportsQuota bool   `json:"supports_quota"`
					PluginID      string `json:"quota_plugin_id"`
				} `json:"files"`
				Total int `json:"total"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatal("could not decode credential listing")
			}
			if len(payload.Files) != len(want) || (query != "" && payload.Total != len(want)) {
				t.Fatalf("listing rows = %d, total = %d, want %d", len(payload.Files), payload.Total, len(want))
			}
			seen := make(map[string]bool)
			for _, row := range payload.Files {
				if row.AuthIndex == "" || seen[row.AuthIndex] || !row.RuntimeOnly || !row.SupportsQuota || row.PluginID != goplan.PluginID {
					t.Fatal("missing or duplicate quota identity or capability")
				}
				seen[row.AuthIndex] = true
				if !slices.ContainsFunc(want, func(a *coreauth.Auth) bool {
					return row.ID == a.ID && row.AuthIndex == a.EnsureIndex()
				}) {
					t.Fatal("listing contains an unexpected credential")
				}
			}
		}
	}
	assertListing(auths[:2]...)

	if runtime.GOOS != "windows" {
		// If a same-name file exists, the generic file-delete path could accept the config ID.
		collidingFile := filepath.Join(dir, auths[0].ID)
		if err := os.WriteFile(collidingFile, []byte("{}"), 0600); err != nil {
			t.Fatal("could not create same-name fixture file")
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v8/management/credentials?name="+auths[0].ID, nil))
		if rec.Code != http.StatusConflict {
			t.Fatalf("config-credential deletion status = %d", rec.Code)
		}
		if _, err := os.Stat(collidingFile); err != nil {
			t.Fatal("file deletion changed the same-name fixture")
		}
	}
	assertListing(auths[:2]...)

	manager.Remove(t.Context(), auths[0].ID)
	assertListing(auths[1])
}

type goQuotaRoundTrip func(*http.Request) (*http.Response, error)

func (f goQuotaRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDispatchGoQuota(t *testing.T) {
	router, _, auths, _ := goQuotaFixture(t)
	const usage = `{"usage":{"rolling":{"status":"ok","percent":25,"resetsAt":"2026-11-18T15:03:46+07:00"},"weekly":{"status":"rate-limited","percent":100,"resetsAt":"2026-11-23T00:00:00Z"},"monthly":{"status":"ok","percent":40,"resetsAt":"2026-12-01T04:29:48Z"}}}`

	for _, tc := range []struct {
		name     string
		auth     *coreauth.Auth
		bearer   string
		upstream int
		response int
	}{
		{name: "success", auth: auths[0], bearer: goQuotaBearerA, upstream: 200, response: 200},
		{name: "failure", auth: auths[1], bearer: goQuotaBearerB, upstream: 403, response: 502},
		{name: "non-Go auth", auth: auths[2], response: 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v8/management/plugins/"+goplan.PluginID+"/quota", strings.NewReader(`{"auth_index":"`+tc.auth.EnsureIndex()+`"}`))
			ctx := httptransport.WithDecorator(req.Context(), func(http.RoundTripper) http.RoundTripper {
				return goQuotaRoundTrip(func(r *http.Request) (*http.Response, error) {
					if tc.upstream == 0 || r.Header.Get("Authorization") != "Bearer "+tc.bearer {
						t.Fatal("unexpected credential sent upstream")
					}
					return &http.Response{StatusCode: tc.upstream, Body: io.NopCloser(strings.NewReader(usage))}, nil
				})
			})
			router.ServeHTTP(rec, req.WithContext(ctx))
			if rec.Code != tc.response {
				t.Fatalf("status = %d, want %d", rec.Code, tc.response)
			}
			if tc.response == 502 {
				if rec.Body.String() != `{"error":"OpenCode Go usage unavailable: subscription required"}` {
					t.Fatal("expected only the fixed error message")
				}
				return
			}
			if tc.response != 200 {
				return
			}

			var response pluginapi.QuotaFetchResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Subscription == nil || response.Subscription.Plan != "OpenCode Go" || len(response.Groups) != 3 {
				t.Fatal("unexpected quota response shape")
			}
			labels := [3]string{"5-hour", "Weekly", "Monthly"}
			resets := [3]string{"2026-11-18T08:03:46Z", "2026-11-23T00:00:00Z", "2026-12-01T04:29:48Z"}
			for i, used := range [3]float64{25, 100, 40} {
				group := response.Groups[i]
				if group.DisplayName != labels[i] || len(group.Buckets) != 1 {
					t.Fatalf("wrong group shape for window %d", i)
				}
				bucket := group.Buckets[0]
				if bucket.RemainingFraction != 1-used/100 || bucket.ResetTime != resets[i] {
					t.Fatalf("wrong remaining fraction or UTC reset for window %d", i)
				}
				description := ""
				if i == 1 {
					description = "Rate-limited"
				}
				if group.Description != description {
					t.Fatalf("wrong description for window %d", i)
				}
			}
		})
	}
}
