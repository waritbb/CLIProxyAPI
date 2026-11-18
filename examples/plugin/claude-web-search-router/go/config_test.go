package main

import "testing"

func TestConfigurePreservesDefaultBooleansWhenConfigIsPartial(t *testing.T) {
	raw := mustJSON(t, lifecycleRequest{ConfigYAML: []byte("route: codex_web_search\n")})

	if errConfigure := configure(raw); errConfigure != nil {
		t.Fatalf("configure() error = %v", errConfigure)
	}

	cfg := loadedConfig()
	if !cfg.Enabled {
		t.Fatal("Enabled = false, want default true")
	}
	if !cfg.RequireWebSearchOnly {
		t.Fatal("RequireWebSearchOnly = false, want default true")
	}
	if cfg.Route != string(backendCodexWebSearch) {
		t.Fatalf("Route = %q, want codex_web_search", cfg.Route)
	}
}

func TestRegistrationMarksTavilyKeysSecret(t *testing.T) {
	for _, field := range pluginRegistration().Metadata.ConfigFields {
		if field.Name == "tavily_api_keys" && field.Secret {
			return
		}
	}
	t.Fatal("the Tavily key list must be declared secret")
}
