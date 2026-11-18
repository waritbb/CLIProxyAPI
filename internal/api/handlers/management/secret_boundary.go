package management

import (
	"os"
	"path/filepath"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretboundary"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

func (h *Handler) ManagementSecretBoundary() *secretboundary.Boundary {
	h.secretBoundaryOnce.Do(func() {
		cfg := h.configSnapshot()
		var dir string
		if cfg != nil {
			dir = cfg.RemoteManagement.SecretStateDir
		}
		if dir == "" && h.configFilePath != "" {
			dir = "state"
		}
		if dir != "" && !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(h.configFilePath), dir)
		}
		boundary, err := secretboundary.Open(dir, h.secretSnapshot)
		if err != nil {
			log.Error("management: could not initialize the secret boundary")
			return
		}
		h.secretBoundary = boundary
	})
	return h.secretBoundary
}

type secretSourceVersion struct {
	modified       time.Time
	size           int64
	config         *config.Config
	manager        *coreauth.Manager
	authGeneration uint64
	plugins        *pluginhost.Snapshot
}

func (h *Handler) secretSnapshot() *secretboundary.Snapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	version := secretSourceVersion{config: h.cfg, manager: h.authManager}
	if h.authManager != nil {
		version.authGeneration = h.authManager.AuthGeneration()
	}
	if h.pluginHost != nil {
		version.plugins = h.pluginHost.Snapshot()
	}
	cacheable := true
	if h.configFilePath != "" {
		if info, err := os.Stat(h.configFilePath); err == nil {
			version.modified, version.size = info.ModTime(), info.Size()
		} else {
			cacheable = false
		}
	}
	if cacheable && h.secretSource != nil && h.secretSourceVersion == version {
		return h.secretSource
	}
	var disk config.Config
	var raw []byte
	if h.configFilePath != "" {
		var err error
		raw, err = os.ReadFile(h.configFilePath)
		if err == nil {
			if err := yaml.Unmarshal(raw, &disk); err != nil {
				return nil
			}
		} else if !os.IsNotExist(err) {
			return nil
		}
	}
	var auths []map[string]any
	var liveKeys struct {
		Keys []string `secret:"value"`
	}
	if h.authManager != nil {
		for _, auth := range h.authManager.List() {
			if auth != nil {
				auths = append(auths, auth.Metadata)
				if kind, key := auth.AccountInfo(); kind == "api_key" {
					liveKeys.Keys = append(liveKeys.Keys, key)
				}
			}
		}
	}
	runtime := h.cfg.CloneForRuntime()
	source := &secretboundary.Snapshot{Config: []any{runtime, &disk, liveKeys}, ConfigYAML: raw, Auths: auths}
	if version.plugins != nil {
		source.PluginFields = version.plugins.ConfigFieldPolicies()
	}
	if runtime != nil {
		source.PluginConfigs = make(map[string]yaml.Node, len(runtime.Plugins.Configs))
		for id, instance := range runtime.Plugins.Configs {
			source.PluginConfigs[id] = instance.Raw
		}
	}
	if cacheable {
		h.secretSource, h.secretSourceVersion = source, version
	}
	return source
}

func includeConfigSource(c *gin.Context, raw []byte) {
	var cfg config.Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		secretboundary.IncludeConfig(c, nil, nil)
		return
	}
	secretboundary.IncludeConfig(c, &cfg, raw)
}
