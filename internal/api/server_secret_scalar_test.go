package api

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretboundary"
	"gopkg.in/yaml.v3"
)

func TestManagementSecretTypedConfigScalars(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "fixture-management")
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	baseline := []byte(fmt.Sprintf(`auth-dir: %s
disable-cooling: TRUE
request-retry: 123456789
claude-api-key:
  - api-key: 123456789
    base-url: https://integer.invalid
  - api-key: 0x075bcd15
    base-url: https://hex.invalid
  - api-key: 6.02e+23
    base-url: https://float.invalid
  - api-key: TRUE
    base-url: https://boolean.invalid
`, authDir))
	if err := os.WriteFile(path, baseline, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil || cfg.AuthDir != authDir {
		t.Fatal("config did not load with the temporary auth directory")
	}
	s := NewServer(cfg, nil, nil, path)
	assertRedacted := func(t *testing.T, body []byte) {
		t.Helper()
		var doc yaml.Node
		if err := yaml.Unmarshal(body, &doc); err != nil {
			t.Fatal("invalid config response")
		}
		handles := make(map[string]bool)
		count := 0
		public := 0
		var visit func(*yaml.Node)
		visit = func(node *yaml.Node) {
			if node.Kind == yaml.MappingNode {
				for i := 0; i < len(node.Content); i += 2 {
					key, value := node.Content[i], node.Content[i+1]
					switch key.Value {
					case "disable-cooling":
						if value.ShortTag() != "!!bool" {
							t.Error("public boolean was changed")
						}
						public++
					case "request-retry":
						if value.ShortTag() != "!!int" {
							t.Error("public integer was changed")
						}
						public++
					case "api-key":
						count++
						if value.ShortTag() != "!!str" || !secretboundary.ContainsHandle([]byte(value.Value)) {
							t.Errorf("credential %d was not returned as a handle", count)
						}
						handles[value.Value] = true
					}
				}
			}
			for _, child := range node.Content {
				visit(child)
			}
		}
		visit(&doc)
		if public != 2 {
			t.Fatal("expected both public settings")
		}
		if count != 4 || len(handles) != count {
			t.Fatal("expected four distinct credential handles")
		}
	}
	for _, version := range []string{"v0", "v8"} {
		for _, endpoint := range []string{"/config", "/config.yaml"} {
			route := "/" + version + "/management" + endpoint
			t.Run(version+endpoint, func(t *testing.T) {
				view := secretRequest(s, http.MethodGet, route, "", nil)
				if view.Code != http.StatusOK {
					t.Fatalf("config GET returned %d", view.Code)
				}
				assertRedacted(t, view.Body.Bytes())
			})
		}
		t.Run(version+"/yaml-save", func(t *testing.T) {
			route := "/" + version + "/management/config.yaml"
			view := secretRequest(s, http.MethodGet, route, "", nil)
			if view.Code != http.StatusOK {
				t.Fatalf("config GET returned %d", view.Code)
			}
			assertRedacted(t, view.Body.Bytes())
			saved := secretRequest(s, http.MethodPut, route, "application/yaml", view.Body.Bytes())
			after, err := os.ReadFile(path)
			if err != nil || saved.Code != http.StatusOK || !bytes.Equal(baseline, after) {
				t.Fatalf("whole-YAML save changed config bytes or returned %d", saved.Code)
			}
		})
	}
}
