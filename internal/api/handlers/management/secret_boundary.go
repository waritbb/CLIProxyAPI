package management

import (
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
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

func (h *Handler) secretSnapshot() (any, []map[string]any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var disk config.Config
	if raw, err := os.ReadFile(h.configFilePath); err == nil {
		_ = yaml.Unmarshal(raw, &disk)
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
	return []any{h.cfg.CloneForRuntime(), &disk, liveKeys}, auths
}

func includeConfigSource(c *gin.Context, raw []byte) {
	var cfg config.Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		secretboundary.IncludeConfig(c, nil)
		return
	}
	secretboundary.IncludeConfig(c, &cfg)
}
