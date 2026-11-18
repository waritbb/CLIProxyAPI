package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretboundary"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	secretFixtureKey    = "provider-fixture-key-one"
	secretFixtureToken  = "oauth-fixture-token-one"
	secretFixtureShort  = "a@bc"
	secretFixtureClient = "panel-fixture-client-key"
	staleFixtureHandle  = "cpx_h1_AAAAAAAAAAAAAAAAAAAAAAAAAA_0000"
)

func secretFixture(t *testing.T, opts ...ServerOption) (*Server, *coreauth.Manager, string, string) {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "fixture-management")
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	raw := fmt.Sprintf(`# Deliberately use the legacy layout and flow style.
auth-dir: %s
api-keys: [%s]
openai-compatibility:
  - name: test-go
    base-url: https://opencode.ai/inference/go/openai/v1
    api-key-entries: [{api-key: %s}]
claude-api-key:
  - api-key: another-claude-key
    base-url: https://cl.invalid
  - api-key: %s
    base-url: https://cl.invalid
`, authDir, secretFixtureClient, secretFixtureKey, secretFixtureShort)
	if err := os.WriteFile(configPath, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(authDir, "fixture.json")
	if err := os.WriteFile(path, []byte(`{"type":"claude","email":"fixture@example.invalid","access_token":"`+secretFixtureToken+`","nested":{"note":"extra-private-value"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	store := sdkauth.NewFileTokenStore()
	store.SetBaseDir(authDir)
	manager := coreauth.NewManager(store, nil, nil)
	if err := manager.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	auth := &coreauth.Auth{ID: "fixture-provider", Provider: "claude", Attributes: map[string]string{"api_key": secretFixtureShort, "base_url": "https://cl.invalid"}}
	if _, err := manager.Register(t.Context(), auth); err != nil {
		t.Fatal(err)
	}
	enable := true
	cfg.ServerResponseCompression.Enabled = &enable
	cfg.ServerResponseCompression.MinBytes = 1
	s := NewServer(cfg, manager, nil, configPath, opts...)
	return s, manager, configPath, path
}

func secretRequest(s *Server, method, path, media string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer fixture-management")
	if media != "" {
		req.Header.Set("Content-Type", media)
	}
	rec := httptest.NewRecorder()
	s.engine.ServeHTTP(rec, req)
	return rec
}

func TestManagementSecretPanelRoundTrip(t *testing.T) {
	s, _, configPath, authPath := secretFixture(t)
	call := func(method, route, contentType string, data []byte, status int) []byte {
		t.Helper()
		w := secretRequest(s, method, route, contentType, data)
		if w.Code != status || bytes.Contains(w.Body.Bytes(), []byte(secretFixtureKey)) || bytes.Contains(w.Body.Bytes(), []byte(secretFixtureToken)) {
			t.Fatalf("%s %s: unexpected status or unredacted response (%d)", method, route, w.Code)
		}
		return w.Body.Bytes()
	}
	disk := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	const v0 = "/v0/management"
	const v8 = "/v8/management"
	const compat = v8 + "/config/api-keys/openai-compatibility"
	baseline := disk(configPath)
	for _, path := range []string{v0 + "/config", v0 + "/config.yaml", v8 + "/config", v8 + "/config.yaml"} {
		body := call("GET", path, "", nil, 200)
		if !bytes.Contains(body, []byte(secretFixtureClient)) || !secretboundary.ContainsHandle(body) {
			t.Fatalf("missing client key or provider handle on %s", path)
		}
	}
	groups := call("GET", compat, "", nil, 200)
	call("PUT", compat, "application/json", groups, 200)
	yaml := call("GET", v8+"/config.yaml", "", nil, 200)
	call("PUT", v8+"/config.yaml", "application/yaml", yaml, 200)
	if !bytes.Equal(baseline, disk(configPath)) {
		t.Fatal("unchanged panel saves modified the config")
	}
	const added = "new-provider-fixture-credential"
	var providers []struct {
		Keys    []map[string]any `json:"keys"`
		Name    string           `json:"name"`
		BaseURL string           `json:"base-url"`
	}
	if err := json.Unmarshal(groups, &providers); err != nil || len(providers) != 1 {
		t.Fatal("could not read panel provider groups")
	}
	providers[0].Keys = append(providers[0].Keys, map[string]any{"api-key": added})
	data, err := json.Marshal(providers)
	if err != nil {
		t.Fatal(err)
	}
	written := call("PUT", compat, "application/json", data, 200)
	readback := call("GET", compat, "", nil, 200)
	for _, result := range [][]byte{written, readback} {
		if bytes.Contains(result, []byte(added)) || !bytes.Contains(result, []byte("_"+added[len(added)-4:])) {
			t.Fatal("new key did not render as a handle")
		}
	}
	updated := disk(configPath)
	if !bytes.Contains(updated, []byte(added)) || !bytes.Contains(updated, []byte(secretFixtureKey)) || secretboundary.ContainsHandle(updated) {
		t.Fatal("provider keys did not round-trip to disk")
	}
	bad := bytes.Replace(data, []byte(added), []byte(staleFixtureHandle), 1)
	call("PUT", compat, "application/json", bad, 409)
	if !bytes.Equal(updated, disk(configPath)) {
		t.Fatal("an unknown handle changed disk state")
	}
	for _, path := range []string{v0 + "/api-key-usage", v8 + "/observability/usage/api-keys"} {
		body := call("GET", path, "", nil, 200)
		if bytes.Contains(body, []byte(secretFixtureShort)) || !secretboundary.ContainsHandle(body) {
			t.Fatal("usage map key was not redacted")
		}
	}
	for _, path := range []string{v0 + "/auth-files/download", v8 + "/credentials/download"} {
		body := call("GET", path+"?name=fixture.json", "", nil, 200)
		if !secretboundary.ContainsHandle(body) || bytes.Contains(body, []byte("extra-private-value")) ||
			!bytes.Contains(body, []byte("fixture@example.invalid")) {
			t.Fatal("auth download lost metadata or exposed a private leaf")
		}
	}
	call("PATCH", v8+"/credentials/fields", "application/json", []byte(`{"name":"fixture.json","prefix":"panel-edit"}`), 200)
	content := disk(authPath)
	if !bytes.Contains(content, []byte(secretFixtureToken)) || !bytes.Contains(content, []byte("panel-edit")) {
		t.Fatal("auth file prefix edit did not preserve the token")
	}
	claude := call("GET", v0+"/claude-api-key", "", nil, 200)
	var list struct {
		Claude []struct {
			Key string `json:"api-key"`
		} `json:"claude-api-key"`
	}
	if err := json.Unmarshal(claude, &list); err != nil || len(list.Claude) != 2 {
		t.Fatal("could not read Claude keys")
	}
	key := list.Claude[1].Key
	call("PATCH", v0+"/claude-api-key", "application/json", []byte(fmt.Sprintf(`{"match":%q,"value":{"prefix":"targeted"}}`, key)), 200)
	cfg, err := config.LoadConfig(configPath)
	if err != nil || cfg.ClaudeKey[1].Prefix != "targeted" || cfg.ClaudeKey[0].Prefix != "" {
		t.Fatal("PATCH by handle selected the wrong row")
	}
	call("DELETE", v0+"/claude-api-key?api-key="+url.QueryEscape(key), "", nil, 200)
	cfg, err = config.LoadConfig(configPath)
	if err != nil || len(cfg.ClaudeKey) != 1 || cfg.ClaudeKey[0].APIKey != "another-claude-key" {
		t.Fatal("DELETE by handle selected the wrong row")
	}
}

func TestManagementSecretRouteCoverage(t *testing.T) {
	s, _, _, _ := secretFixture(t)
	probed := 0
	for _, route := range s.engine.Routes() {
		if !strings.HasPrefix(route.Path, "/v0/management/") && !strings.HasPrefix(route.Path, "/v8/management/") {
			continue
		}
		path := strings.NewReplacer(":id", "boundary-probe", ":channel", "codex", ":name", "boundary.json", "*path", "debug").Replace(route.Path)
		query := "?api-key=" + url.QueryEscape(secretFixtureKey) + "&stamp=" + staleFixtureHandle
		if strings.HasSuffix(path, "/oauth-callback") || strings.HasSuffix(path, "/oauth/callback") {
			// Exercise a successful callback without an OAuth worker or upstream.
			state := fmt.Sprintf("boundary-callback-%d", probed)
			management.RegisterOAuthSession(state, "anthropic")
			t.Cleanup(func() { management.CompleteOAuthSession(state) })
			body := []byte(fmt.Sprintf(`{"code":%q,"state":%q}`, secretFixtureToken, state))
			query := url.Values{"code": {secretFixtureToken}, "state": {state}}
			w := secretRequest(s, route.Method, path+"?"+query.Encode(), "application/json", body)
			if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(secretFixtureToken)) {
				t.Fatalf("callback reflected an OAuth code or returned unexpected status (%d)", w.Code)
			}
		} else {
			// Fail before dispatch, including routes that could invoke upstreams.
			w := secretRequest(s, route.Method, path+query, "", nil)
			if w.Code != 409 || bytes.Contains(w.Body.Bytes(), []byte(secretFixtureKey)) ||
				!strings.Contains(w.Body.String(), "stale secret handle; reload") {
				t.Fatalf("%s %s does not apply the secret boundary (%d)", route.Method, route.Path, w.Code)
			}
		}
		probed++
	}
	if probed == 0 {
		t.Fatal("no management routes probed")
	}
	t.Logf("probed %d registered management routes", probed)
}

type secretEchoPlugin struct{}

func (p secretEchoPlugin) RegisterManagement(context.Context, pluginapi.ManagementRegistrationRequest) (pluginapi.ManagementRegistrationResponse, error) {
	return pluginapi.ManagementRegistrationResponse{Routes: []pluginapi.ManagementRoute{
		{Method: "GET", Path: "/plugins/secret-echo/probe", Handler: p},
	}}, nil
}

func (secretEchoPlugin) HandleManagement(_ context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	data, err := json.Marshal(map[string]string{"echo": req.Query.Get("value")})
	return pluginapi.ManagementResponse{
		Headers: http.Header{"Content-Type": {"application/json"}}, Body: data,
	}, err
}

func TestManagementSecretPluginAPIAndCompression(t *testing.T) {
	host := pluginhost.New()
	host.RegisterPluginForTest("secret-echo", pluginapi.Plugin{Capabilities: pluginapi.Capabilities{ManagementAPI: secretEchoPlugin{}}})
	s, manager, _, _ := secretFixture(t, WithPluginHost(host))
	const replacement = "updated-oauth-token-fixture"
	item, ok := manager.GetByID("fixture.json")
	if !ok {
		t.Fatal("could not load fixture auth")
	}
	item.Metadata["access_token"] = replacement
	if _, err := manager.Update(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	plugin := secretRequest(s, "GET", "/v0/management/plugins/secret-echo/probe?value="+replacement, "", nil)
	if plugin.Code != 200 || bytes.Contains(plugin.Body.Bytes(), []byte(replacement)) || !secretboundary.ContainsHandle(plugin.Body.Bytes()) {
		t.Fatal("plugin fallback failed to redact a rotated credential")
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("upstream body ", 100) + replacement))
	}))
	t.Cleanup(upstream.Close)
	relay := "/v8/management/requests/api-call"
	var echoed struct {
		Echo string `json:"echo"`
	}
	if err := json.Unmarshal(plugin.Body.Bytes(), &echoed); err != nil {
		t.Fatal(err)
	}
	bad := fmt.Sprintf(`{"method":"GET","url":%q,"header":{"authorization":%q}}`, upstream.URL, echoed.Echo)
	if w := secretRequest(s, "POST", relay, "application/json", []byte(bad)); w.Code != 409 {
		t.Fatal("relay accepted a credential handle for forwarding")
	}
	body := fmt.Sprintf(`{"method":"GET","url":%q}`, upstream.URL)
	req := httptest.NewRequest("POST", relay, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer fixture-management")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	s.engine.ServeHTTP(w, req)
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("management APICall did not pass through outer compression")
	}
	decoded := compressionTestBody(t, "gzip", w.Body.Bytes())
	if !bytes.Contains(decoded, []byte("upstream body")) || bytes.Contains(decoded, []byte(replacement)) || !secretboundary.ContainsHandle(decoded) {
		t.Fatal("APICall exposed the rotated auth token")
	}
}

func TestManagementSecretPersistenceRejectsHandles(t *testing.T) {
	_, _, configPath, _ := secretFixture(t)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	bad := []byte("claude-api-key: [{api-key: " + staleFixtureHandle + "}]\n")
	if err := management.WriteConfig(configPath, bad); err == nil {
		t.Fatal("raw config writer accepted a handle")
	}
	cfg := &config.Config{ClaudeKey: []config.ClaudeKey{{APIKey: staleFixtureHandle}}}
	if err := config.SaveConfigPreserveComments(configPath, cfg); err == nil {
		t.Fatal("comment-preserving config writer accepted a handle")
	}
	if after, err := os.ReadFile(configPath); err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected writes modified the config")
	}
	if _, err := config.ParseConfigBytes(bad); err == nil || !strings.Contains(err.Error(), "claude-api-key.[0].api-key") {
		t.Fatal("load of a handle did not identify its field")
	}
}
