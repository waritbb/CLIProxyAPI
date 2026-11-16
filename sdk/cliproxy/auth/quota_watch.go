package auth

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	quotaWatchTick         = 30 * time.Second
	quotaWatchProbeEvery   = 5 * time.Minute
	quotaWatchProbeTimeout = 30 * time.Second
	quotaWatchBounceMemory = 15 * time.Minute
)

// RunQuotaWatch derives cooling candidates from manager state, including restored
// cooldowns. Its disposable scheduling state has exactly one goroutine owner.
func RunQuotaWatch(ctx context.Context, m *Manager) {
	w := &quotaWatch{m: m, now: time.Now, entries: make(map[string]*quotaWatchEntry)}
	ticker := time.NewTicker(quotaWatchTick)
	defer ticker.Stop()
	w.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sweep(ctx)
		}
	}
}

type quotaWatch struct {
	m       *Manager
	now     func() time.Time
	entries map[string]*quotaWatchEntry
}
type quotaWatchEntry struct {
	nextProbe         time.Time
	failures, bounces int
	lastRelease       time.Time
	unsupported       *Auth
	cooling           bool
}

func quotaWatchCandidate(a *Auth, now time.Time) bool {
	return a != nil && !a.Disabled && a.Status != StatusDisabled && a.Quota.Exceeded && a.Quota.Reason == "credential_quota" && a.Quota.NextRecoverAt.After(now) && !hasUnauthorizedAuthFailure(a)
}
func (w *quotaWatch) sweep(ctx context.Context) {
	seen := make(map[string]bool)
	for _, a := range w.m.List() {
		if ctx.Err() != nil {
			return
		}
		now := w.now()
		if !quotaWatchCandidate(a, now) {
			continue
		}
		prober, ok := w.m.executorFor(executorKeyFromAuth(a)).(QuotaProber)
		if !ok {
			continue
		}
		seen[a.ID] = true
		e := w.entries[a.ID]
		if e == nil {
			e = &quotaWatchEntry{}
			w.entries[a.ID] = e
		}
		if e.unsupported != nil && (e.unsupported.CredentialVersion != a.CredentialVersion || CredentialsChanged(e.unsupported, a)) {
			e.nextProbe = now
			e.unsupported = nil
		}
		if !e.cooling && !e.lastRelease.IsZero() {
			if now.Sub(e.lastRelease) <= quotaWatchBounceMemory {
				e.bounces++
				if floor := e.lastRelease.Add(quotaWatchBounceHoldoff(e.bounces)); floor.After(e.nextProbe) {
					e.nextProbe = floor
				}
			} else {
				e.bounces = 0
			}
		}
		e.cooling = true
		if now.Before(e.nextProbe) {
			continue
		}
		w.probeOne(ctx, a, prober, e)
	}
	now := w.now()
	for id, e := range w.entries {
		if seen[id] {
			continue
		}
		a, ok := w.m.GetByID(id)
		if !ok || a.Disabled || e.lastRelease.IsZero() || (!now.Before(e.nextProbe) && now.Sub(e.lastRelease) > quotaWatchBounceMemory) {
			delete(w.entries, id)
		} else {
			e.cooling = false
		}
	}
}
func (w *quotaWatch) probeOne(ctx context.Context, base *Auth, prober QuotaProber, e *quotaWatchEntry) {
	now := w.now()
	e.nextProbe = now.Add(quotaWatchProbeEvery)
	fields := log.Fields{"auth_index": base.EnsureIndex(), "provider": base.Provider, "cooldown_until": base.Quota.NextRecoverAt, "bounces": e.bounces}
	decision, reason := "hold", "incomplete"
	status := 0
	defer func() {
		fields["reason"] = reason
		fields["next_probe_in"] = e.nextProbe.Sub(w.now())
		fields["status"] = status
		entry := log.WithFields(fields)
		if decision == "probe_error" || decision == "release_failed" {
			entry.Warn("quota watch: " + decision)
		} else {
			entry.Info("quota watch: " + decision)
		}
	}()
	if expiry, ok := base.ExpirationTime(); ok && !expiry.After(now) {
		reason = "token_expired"
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, quotaWatchProbeTimeout)
	probe, err := prober.ProbeQuota(probeCtx, base.Clone())
	if err == nil {
		err = probeCtx.Err()
	}
	cancel()
	e.unsupported = nil
	if errors.Is(err, ErrQuotaProbeUnsupported) {
		e.unsupported = base.Clone()
		decision = "unsupported"
		reason = "unsupported"
		e.nextProbe = base.Quota.NextRecoverAt
		return
	}
	if err != nil {
		e.failures++
		wait := quotaWatchErrorBackoff(e.failures)
		var probeErr *QuotaProbeError
		if errors.As(err, &probeErr) {
			status = probeErr.Status
			wait = max(wait, probeErr.RetryAfter)
		}
		err = quotaProbeLogError(base, err)
		fields["error"] = err.Error()
		e.nextProbe = w.now().Add(wait)
		decision, reason = "probe_error", "probe_failed"
		return
	}
	e.nextProbe = w.now().Add(max(quotaWatchProbeEvery, probe.RetryAfter))
	fields["windows"] = probe.Windows
	verdict, why := judgeQuotaWindows(probe)
	reason = why
	if verdict != QuotaVerdictClear {
		e.failures = 0
		return
	}
	updated := base.Clone()
	updated.Quota.Signals = encodeQuotaWatchSignals(probe)
	updated.Quota.ObservedAt = probe.SentAt
	saved, errUpdate := w.m.updateInternal(context.WithoutCancel(ctx), base, updated, updateModeQuotaObservation)
	if errUpdate != nil || saved == nil {
		e.failures++
		e.nextProbe = w.now().Add(quotaWatchErrorBackoff(e.failures))
		decision, reason = "release_failed", "update_failed"
		return
	}
	e.failures = 0
	if saved.Disabled || saved.Quota.Exceeded && saved.Quota.Reason == "credential_quota" || !saved.Quota.ObservedAt.Equal(probe.SentAt) || !quotaWatchSignalsClear(saved.Quota.Signals) {
		decision, reason = "release_superseded", "state_changed"
		return
	}
	w.m.projectAuthModels(saved, w.now())
	e.lastRelease = w.now()
	e.cooling = false
	decision = "released"
}
func quotaWatchErrorBackoff(n int) time.Duration {
	wait := 5 * time.Minute
	for i := 1; i < n && wait < 30*time.Minute; i++ {
		wait *= 2
	}
	return min(wait, 30*time.Minute)
}
func quotaWatchBounceHoldoff(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	wait := 10 * time.Minute
	for i := 1; i < n && wait < 30*time.Minute; i++ {
		wait *= 2
	}
	return min(wait, 30*time.Minute)
}
