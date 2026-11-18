package pluginhost

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/goplan"
)

func TestApplyConfigDoesNotLoadReservedGoQuotaPlugin(t *testing.T) {
	loader := newTestSymbolLoader()
	host := NewForTest(loader)
	host.ApplyConfig(t.Context(), &config.Config{
		Plugins: config.PluginsConfig{
			Enabled: true,
			Dir:     makePluginDir(t, goplan.PluginID),
			Configs: enabledPluginConfigs(goplan.PluginID),
		},
	})
	if loader.openCalls != 0 {
		t.Fatal("plugin host tried to open a file with the reserved quota ID")
	}
}
