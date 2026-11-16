package auth

import (
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

func (m *Manager) projectAuthModels(auth *Auth, now time.Time) {
	supportedModels, regEpoch := registry.GetGlobalRegistry().GetModelsAndEpochForClient(auth.ID)
	projections := make([]registry.ClientModelProjection, 0, len(supportedModels))
	for _, sm := range supportedModels {
		if sm == nil || strings.TrimSpace(sm.ID) == "" {
			continue
		}
		projections = append(projections, m.clientModelProjectionForAuth(auth, sm.ID, now))
	}
	if len(projections) > 0 {
		registry.GetGlobalRegistry().ApplyClientModelProjections(auth.ID, regEpoch, auth.Generation, projections)
	}
}
