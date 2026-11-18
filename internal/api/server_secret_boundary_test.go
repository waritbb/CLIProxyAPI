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

	"github.com/MoeForge/moego/base64"
	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretboundary"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"gopkg.in/yaml.v3"
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

func TestManagementSecretPluginConfig(t *testing.T) {
	host := pluginhost.New()
	s, _, configPath, _ := secretFixture(t, WithPluginHost(host))
	const key = "fixture-plugin-tavily-private"
	const nestedKey = "fixture-plugin-nested-private"
	const untyped = "fixture-plugin-untyped-private"
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(f, `routing: {strategy: round-robin}
plugins:
  configs:
    router:
      enabled: true
      priority: 42
      mode: round-robin
      default_provider: claude
      model: grok-4
      feature_enabled: true
      threshold: 2.5
      untyped: %s
      tavily_api_keys: [%s]
      nested: {CREDENTIALS: [[%s]], pin: 76543210}
`, untyped, key, nestedKey)
	if closeErr := f.Close(); err != nil || closeErr != nil {
		t.Fatal("could not write fixture config")
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	s.mgmt.SetConfig(cfg)
	// Registration can complete after the management boundary has read config.
	secretRequest(s, "GET", "/v8/management/config", "", nil)
	host.RegisterPluginForTest("router", pluginapi.Plugin{Metadata: pluginapi.Metadata{ConfigFields: []pluginapi.ConfigField{
		{Name: "mode", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"round-robin"}},
		{Name: "default_provider", Type: pluginapi.ConfigFieldTypeString},
		{Name: "model", Type: pluginapi.ConfigFieldTypeString},
		{Name: "feature_enabled", Type: pluginapi.ConfigFieldTypeBoolean},
		{Name: "threshold", Type: pluginapi.ConfigFieldTypeNumber},
		{Name: "tavily_api_keys", Type: pluginapi.ConfigFieldTypeArray},
		{Name: "nested", Type: pluginapi.ConfigFieldTypeObject},
	}}})
	models := registry.GetGlobalRegistry()
	models.RegisterClient("fixture.json", "claude", []*registry.ModelInfo{{ID: "grok-4"}})
	t.Cleanup(func() { models.UnregisterClient("fixture.json") })

	read := func(t *testing.T, route string, dst any) []byte {
		t.Helper()
		got := secretRequest(s, "GET", route, "", nil)
		if got.Code != 200 {
			t.Fatalf("%s: HTTP %d", route, got.Code)
		}
		body := got.Body.Bytes()
		for name, value := range map[string]string{"tavily_api_keys": key, "nested credentials": nestedKey, "untyped": untyped} {
			if bytes.Contains(body, []byte(value)) {
				t.Errorf("%s: exposed %s", route, name)
			}
		}
		if dst != nil {
			decode := json.Unmarshal
			if strings.HasSuffix(route, ".yaml") {
				decode = yaml.Unmarshal
			}
			if err := decode(body, dst); err != nil {
				t.Fatalf("%s: invalid response", route)
			}
		}
		return body
	}
	assertPlugin := func(t *testing.T, plugin map[string]any) {
		t.Helper()
		for field, want := range map[string]any{
			"enabled": true, "mode": "round-robin", "feature_enabled": true, "threshold": 2.5,
			"default_provider": "claude", "model": "grok-4",
		} {
			if plugin[field] != want {
				t.Errorf("plugin field %s did not retain its value and type", field)
			}
		}
		nested, _ := plugin["nested"].(map[string]any)
		for name, raw := range map[string]any{
			"tavily_api_keys": plugin["tavily_api_keys"], "nested credentials": nested["CREDENTIALS"], "untyped": plugin["untyped"],
		} {
			encoded, _ := json.Marshal(raw)
			if !secretboundary.ContainsHandle(encoded) {
				t.Errorf("plugin field %s is missing its handle", name)
			}
		}
		if pin := nested["pin"]; pin != 76543210 && pin != float64(76543210) {
			t.Error("untyped numeric setting did not remain public")
		}
	}
	for _, route := range []string{"/v0/management/config.yaml", "/v8/management/config.yaml", "/v8/management/config"} {
		t.Run(route, func(t *testing.T) {
			var config struct {
				Routing struct{ Strategy string }
				Plugins struct{ Configs map[string]map[string]any }
			}
			read(t, route, &config)
			if config.Routing.Strategy != "round-robin" {
				t.Error("routing strategy collided with plugin mode")
			}
			assertPlugin(t, config.Plugins.Configs["router"])
		})
	}
	t.Run("v8 plugin JSON subpath", func(t *testing.T) {
		var plugin map[string]any
		read(t, "/v8/management/config/plugins/configs/router", &plugin)
		assertPlugin(t, plugin)
	})
	t.Run("legacy routing", func(t *testing.T) {
		var routing struct{ Strategy string }
		read(t, "/v0/management/routing/strategy", &routing)
		if routing.Strategy != "round-robin" {
			t.Error("routing strategy collided with plugin mode")
		}
	})
	t.Run("legacy plugin JSON", func(t *testing.T) {
		var plugin map[string]any
		read(t, "/v0/management/plugins/router/config", &plugin)
		assertPlugin(t, plugin)
	})
	t.Run("auth identity and models", func(t *testing.T) {
		var auth struct{ Type, Provider string }
		var rows struct{ Models []struct{ ID string } }
		var listing struct {
			Files []struct{ Type, Provider string }
		}
		read(t, "/v8/management/credentials?name=fixture.json", &listing)
		if len(listing.Files) == 1 {
			auth = listing.Files[0]
		}
		if auth.Type != "claude" || auth.Provider != "claude" {
			t.Error("auth type or provider collided with plugin default_provider")
		}
		read(t, "/v8/management/credentials/models?name=fixture.json", &rows)
		if len(rows.Models) != 1 || rows.Models[0].ID != "grok-4" {
			t.Error("auth model collided with plugin model")
		}
	})
	t.Run("log download", func(t *testing.T) {
		dir := t.TempDir()
		s.mgmt.SetLogDirectory(dir)
		const name = "error-plugin-probe.log"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join([]string{key, nestedKey, untyped, "round-robin claude grok-4"}, " ")), 0600); err != nil {
			t.Fatal(err)
		}
		body := read(t, "/v8/management/observability/logs/errors/"+name, nil)
		if !secretboundary.ContainsHandle(body) || !bytes.Contains(body, []byte("round-robin claude grok-4")) {
			t.Error("log did not preserve public values alongside redacted credentials")
		}
	})
	baseline, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	yaml := secretRequest(s, "GET", "/v8/management/config.yaml", "", nil)
	saved := secretRequest(s, "PUT", "/v8/management/config.yaml", "application/yaml", yaml.Body.Bytes())
	after, err := os.ReadFile(configPath)
	if err != nil || saved.Code != 200 || !bytes.Equal(baseline, after) {
		t.Fatalf("plugin YAML round trip changed bytes or returned %d", saved.Code)
	}
}

func TestManagementSecretPanelAntigravityQuota(t *testing.T) {
	s, manager, _, _ := secretFixture(t)
	const project = "fixture-antigravity-project"
	const token = "fixture-antigravity-access"
	_, err := manager.Register(t.Context(), &coreauth.Auth{
		ID: "antigravity-fixture.json", Provider: "antigravity",
		Metadata: map[string]any{"type": "antigravity", "email": "fixture@example.invalid", "project_id": project, "access_token": token, "expired": "2099-01-01T00:00:00Z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+token ||
			r.Header.Get("User-Agent") != "antigravity/hub/fixture darwin/arm64" ||
			json.NewDecoder(r.Body).Decode(&body) != nil || body["project"] != project {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	for _, route := range []struct{ list, relay string }{
		{"/v0/management/auth-files", "/v0/management/api-call"},
		{"/v8/management/credentials", "/v8/management/requests/api-call"},
	} {
		listing := secretRequest(s, "GET", route.list, "", nil)
		var rows struct {
			Files []struct {
				ID        string `json:"id"`
				Project   string `json:"project_id"`
				AuthIndex string `json:"auth_index"`
			} `json:"files"`
		}
		if listing.Code != 200 || json.Unmarshal(listing.Body.Bytes(), &rows) != nil {
			t.Fatalf("%s: invalid auth listing (%d)", route.list, listing.Code)
		}
		found := false
		for _, row := range rows.Files {
			if row.ID != "antigravity-fixture.json" {
				continue
			}
			found = true
			data := fmt.Sprintf(`{"project":%q}`, row.Project)
			body := fmt.Sprintf(`{"authIndex":%q,"method":"POST","url":%q,"header":{"Authorization":"Bearer $TOKEN$","Content-Type":"application/json","User-Agent":"antigravity/hub/fixture darwin/arm64"},"data":%q}`, row.AuthIndex, upstream.URL, data)
			got := secretRequest(s, "POST", route.relay, "application/json", []byte(body))
			var response struct {
				StatusCode int `json:"status_code"`
			}
			if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &response) != nil || response.StatusCode != 204 {
				t.Errorf("%s: relay HTTP %d, upstream HTTP %d", route.relay, got.Code, response.StatusCode)
			}
		}
		if !found {
			t.Fatal("Antigravity credential missing")
		}
	}
}

func TestManagementSecretPanelPlanType(t *testing.T) {
	s, manager, _, _ := secretFixture(t)
	item, _ := manager.GetByID("fixture.json")
	item.Metadata["plan_type"] = "promax"
	if _, err := manager.Update(t.Context(), item); err != nil {
		t.Fatal(err)
	}
	const jwtClaims = `{"https://api.openai.com/auth":{"chatgpt_plan_type":"promax","chatgpt_account_id":"fixture-account-id"}}`
	jwt := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(jwtClaims)) + ".fixture"
	if _, err := manager.Register(t.Context(), &coreauth.Auth{
		ID: "codex-plan-fixture.json", Provider: "codex",
		Metadata: map[string]any{"type": "codex", "email": "fixture@example.invalid", "id_token": jwt},
	}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/v0/management/auth-files", "/v8/management/credentials"} {
		got := secretRequest(s, "GET", route, "", nil)
		var listing struct {
			Files []struct {
				ID     string `json:"id"`
				Claims struct {
					Plan string `json:"plan_type"`
				} `json:"id_token"`
			} `json:"files"`
		}
		if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &listing) != nil || bytes.Contains(got.Body.Bytes(), []byte(jwt)) {
			t.Fatalf("%s: invalid credential listing or raw ID token (%d)", route, got.Code)
		}
		found := false
		for _, row := range listing.Files {
			if row.ID == "codex-plan-fixture.json" {
				found = row.Claims.Plan == "promax"
			}
		}
		if !found {
			t.Errorf("%s: plan badge claim did not remain plain", route)
		}
	}
	for _, route := range []string{"/v0/management/auth-files/download", "/v8/management/credentials/download"} {
		got := secretRequest(s, "GET", route+"?name=fixture.json", "", nil)
		var fields map[string]any
		if got.Code != 200 || json.Unmarshal(got.Body.Bytes(), &fields) != nil || fields["plan_type"] != "promax" {
			t.Errorf("%s: plan_type did not remain plain (%d)", route, got.Code)
		}
	}
}

func TestManagementSecretLargeLogDownloads(t *testing.T) {
	s, _, _, _ := secretFixture(t)
	dir := t.TempDir()
	s.mgmt.SetLogDirectory(dir)
	const id = "secret-log-probe"
	name := "error-fixture-" + logging.ShortRequestID(id) + ".log"
	// The credential straddles the first 32 KiB read. The full file exceeds 32 MiB.
	const chunk = 32 << 10
	data := strings.Repeat("x", chunk-3) + secretFixtureKey + strings.Repeat("y", 32<<20)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct{ path, media string }{
		{"/v0/management/request-error-logs/" + name, "text/plain; charset=utf-8"},
		{"/v8/management/observability/logs/requests/" + id, "application/octet-stream"},
	} {
		if route.media == "application/octet-stream" {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("\x00"+data[1:]), 0600); err != nil {
				t.Fatal(err)
			}
		}
		got := secretRequest(s, "GET", route.path, "", nil)
		body := got.Body.Bytes()
		if got.Code != 200 || got.Header().Get("Content-Type") != route.media ||
			!bytes.Equal(body[max(0, len(body)-(32<<20)):], []byte(data[len(data)-(32<<20):])) ||
			bytes.Contains(body, []byte(secretFixtureKey)) || !secretboundary.ContainsHandle(body) {
			t.Errorf("%s: large log failed or was not redacted (%d, %d bytes)", route.path, got.Code, len(body))
		}
	}
}
