package auth

import (
	"context"
	"errors"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type quotaWatchTestExecutor struct {
	schedulerProviderTestExecutor
	probe func(context.Context, *Auth) (QuotaProbe, error)
}

func (e quotaWatchTestExecutor) ProbeQuota(ctx context.Context, a *Auth) (QuotaProbe, error) {
	return e.probe(ctx, a)
}

func quotaWatchFixture(t *testing.T) (*Manager, *Auth, string, string) {
	t.Helper()
	withQuotaCooldownEnabled(t)
	m, a, model, sibling := devinRefreshAuthFixture(t, t.Name())
	a.Provider = "claude"
	a.Metadata = map[string]any{"access_token": "test-oauth"}
	if _, err := m.Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(a.ID, "claude", []*registry.ModelInfo{{ID: model}, {ID: sibling}})
	m.RefreshSchedulerEntry(a.ID)
	a, _ = m.GetByID(a.ID)
	return m, a, model, sibling
}
func quotaWatchReject(m *Manager, a *Auth, model string) {
	retry := 72 * time.Hour
	m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: "claude", CredentialVersion: a.CredentialVersion, Model: model, Error: &Error{HTTPStatus: 429, Code: "rate_limit", Message: "weekly quota"}, RetryAfter: &retry, CredentialScope: true})
}
func quotaWatchClearProbe() QuotaProbe {
	return QuotaProbe{SentAt: time.Now(), Complete: true, Windows: map[string]float64{"five_hour": 0, "seven_day": 0}}
}
func newTestQuotaWatch(m *Manager, now *time.Time) *quotaWatch {
	return &quotaWatch{m: m, now: func() time.Time { return *now }, entries: map[string]*quotaWatchEntry{}}
}

func TestQuotaWatchRestoredCooldownRelease(t *testing.T) {
	for _, shadow := range []bool{false, true} {
		t.Run(map[bool]string{false: "reporting_plain_quota", true: "independent_shadow"}[shadow], func(t *testing.T) {
			m, a, model, sibling := quotaWatchFixture(t)
			if shadow {
				retry := 30 * time.Minute
				m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: "claude", CredentialVersion: a.CredentialVersion, Model: sibling, RetryAfter: &retry, Error: &Error{HTTPStatus: http.StatusTooManyRequests, Code: "rate_limit"}})
			}
			quotaWatchReject(m, a, model)
			before, _ := m.GetByID(a.ID)
			if before.ModelStates[model].Quota.Reason != "quota" {
				t.Fatal("reporting model should carry plain quota")
			}
			m.mu.RLock()
			records := m.cooldownStateRecordsForAuthLocked(m.auths[a.ID], time.Now())
			m.mu.RUnlock()
			restored := NewManager(nil, nil, nil)
			if _, err := restored.Register(context.Background(), a.Clone()); err != nil {
				t.Fatal(err)
			}
			store := &recordingCooldownStateStore{load: records}
			restored.SetCooldownStateStore(store)
			if err := restored.RestoreCooldownStates(context.Background()); err != nil {
				t.Fatal(err)
			}
			restored.RefreshSchedulerEntry(a.ID)
			if _, err := restored.scheduler.pickSingle(context.Background(), "claude", model, cliproxyexecutor.Options{}, nil); err == nil {
				t.Fatal("restored credential should be blocked")
			}
			calls := 0
			restored.RegisterExecutor(quotaWatchTestExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}, probe: func(ctx context.Context, a *Auth) (QuotaProbe, error) {
				calls++
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 30*time.Second {
					t.Fatal("probe must have a 30s deadline")
				}
				return quotaWatchClearProbe(), nil
			}})
			now := time.Now()
			w := newTestQuotaWatch(restored, &now)
			saves := store.saveCount.Load()
			w.sweep(context.Background())
			got, _ := restored.GetByID(a.ID)
			if calls != 1 || got.Quota.Reason == "credential_quota" {
				t.Fatalf("calls=%d, credential quota not released: %+v", calls, got.Quota)
			}
			if blocked, _, _ := isAuthBlockedForModel(got, model, time.Now()); blocked {
				t.Fatal("reporting model stayed blocked")
			}
			if blocked, _, _ := isAuthBlockedForModel(got, sibling, time.Now()); blocked != shadow {
				t.Fatalf("sibling blocked=%v, want %v", blocked, shadow)
			}
			if _, err := restored.scheduler.pickSingle(context.Background(), "claude", model, cliproxyexecutor.Options{}, nil); err != nil {
				t.Fatalf("scheduler not upserted: %v", err)
			}
			if store.saveCount.Load() <= saves {
				t.Fatal("release not persisted")
			}
			for _, record := range store.savedRecords() {
				if record.Reason == "credential_quota" || record.Quota.Reason == "credential_quota" {
					t.Fatal("persisted credential quota survived")
				}
			}
		})
	}
}

func TestQuotaWatchMidProbe429Fence(t *testing.T) {
	m, a, model, _ := quotaWatchFixture(t)
	quotaWatchReject(m, a, model)
	m.RegisterExecutor(quotaWatchTestExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}, probe: func(context.Context, *Auth) (QuotaProbe, error) {
		p := quotaWatchClearProbe()
		quotaWatchReject(m, a, model)
		return p, nil
	}})
	now := time.Now()
	w := newTestQuotaWatch(m, &now)
	w.sweep(context.Background())
	got, _ := m.GetByID(a.ID)
	if !got.Quota.Exceeded {
		t.Fatal("mid-probe 429 was erased")
	}
	if w.entries[a.ID] == nil {
		t.Fatal("cooldown was never probed")
	}
	if !w.entries[a.ID].nextProbe.Equal(now.Add(5 * time.Minute)) {
		t.Fatal("superseded release should wait normal cadence")
	}
}
func TestQuotaWatchHoldAtWeeklyLimit(t *testing.T) {
	m, a, model, _ := quotaWatchFixture(t)
	quotaWatchReject(m, a, model)
	m.RegisterExecutor(quotaWatchTestExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}, probe: func(context.Context, *Auth) (QuotaProbe, error) {
		p := quotaWatchClearProbe()
		p.Windows["seven_day"] = 100
		return p, nil
	}})
	now := time.Now()
	w := newTestQuotaWatch(m, &now)
	w.sweep(context.Background())
	got, _ := m.GetByID(a.ID)
	if !got.Quota.Exceeded {
		t.Fatal("limited account released")
	}
}
func TestJudgeQuotaWindows(t *testing.T) {
	for _, tc := range []struct {
		name  string
		p     QuotaProbe
		clear bool
	}{
		{"reset", QuotaProbe{Complete: true, Windows: map[string]float64{"five_hour": 0, "seven_day": 0}}, true},
		{"incomplete", QuotaProbe{Windows: map[string]float64{"five_hour": 0, "seven_day": 0}}, false},
		{"missing_required", QuotaProbe{Complete: true, Windows: map[string]float64{"seven_day": 0}}, false},
		{"weekly_limit", QuotaProbe{Complete: true, Windows: map[string]float64{"five_hour": 0, "seven_day": 100}}, false},
		{"model_limit", QuotaProbe{Complete: true, Windows: map[string]float64{"five_hour": 0, "seven_day": 0, "seven_day_opus": 100}}, false},
		{"nan", QuotaProbe{Complete: true, Windows: map[string]float64{"five_hour": 0, "seven_day": math.NaN()}}, false},
		{"infinite", QuotaProbe{Complete: true, Windows: map[string]float64{"five_hour": 0, "seven_day": math.Inf(1)}}, false},
		{"negative", QuotaProbe{Complete: true, Windows: map[string]float64{"five_hour": 0, "seven_day": -1}}, false},
		{"over", QuotaProbe{Complete: true, Windows: map[string]float64{"five_hour": 0, "seven_day": 101}}, false},
		{"99", QuotaProbe{Complete: true, Windows: map[string]float64{"five_hour": 99, "seven_day": 99}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := judgeQuotaWindows(tc.p)
			if (v == QuotaVerdictClear) != tc.clear {
				t.Fatalf("verdict=%v", v)
			}
			if quotaWatchSignalsClear(encodeQuotaWatchSignals(tc.p)) != tc.clear {
				t.Fatal("signal roundtrip disagrees")
			}
		})
	}
	if quotaWatchSignalsClear(map[string]string{"quota-watch/complete": "true", "quota-watch/five_hour": "0", "quota-watch/seven_day": "oops"}) {
		t.Fatal("malformed signals cleared quota")
	}
}
func TestQuotaWatchSchedule(t *testing.T) {
	m, a, model, _ := quotaWatchFixture(t)
	quotaWatchReject(m, a, model)
	now := time.Now()
	w := newTestQuotaWatch(m, &now)
	calls := 0
	m.RegisterExecutor(quotaWatchTestExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}, probe: func(context.Context, *Auth) (QuotaProbe, error) {
		calls++
		return QuotaProbe{}, &QuotaProbeError{Status: 429, RetryAfter: 45 * time.Minute, Err: errors.New("limited")}
	}})
	w.sweep(context.Background())
	w.sweep(context.Background())
	if calls != 1 {
		t.Fatal("hot re-probe")
	}
	if !w.entries[a.ID].nextProbe.Equal(now.Add(45 * time.Minute)) {
		t.Fatal("Retry-After was not honored")
	}
	for i, want := range []time.Duration{5, 10, 20, 30, 30} {
		if got := quotaWatchErrorBackoff(i + 1); got != want*time.Minute {
			t.Fatalf("backoff=%v", got)
		}
	}
	for i, want := range []time.Duration{0, 10, 20, 30, 30} {
		if got := quotaWatchBounceHoldoff(i); got != want*time.Minute {
			t.Fatalf("bounce=%v", got)
		}
	}
	now = now.Add(45 * time.Minute)
	w.sweep(context.Background())
	if calls != 2 {
		t.Fatal("due retry not probed")
	}
}

func TestQuotaWatchBounceAndPruning(t *testing.T) {
	m, a, model, _ := quotaWatchFixture(t)
	quotaWatchReject(m, a, model)
	now := time.Now()
	w := newTestQuotaWatch(m, &now)
	calls := 0
	m.RegisterExecutor(quotaWatchTestExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}, probe: func(context.Context, *Auth) (QuotaProbe, error) { calls++; return quotaWatchClearProbe(), nil }})
	w.sweep(context.Background())
	if calls != 1 {
		t.Fatal("initial probe missing")
	}
	w.sweep(context.Background())
	quotaWatchReject(m, a, model)
	w.sweep(context.Background())
	if calls != 1 || w.entries[a.ID].bounces != 1 {
		t.Fatal("bounce retried before 10m")
	}
	now = now.Add(10 * time.Minute)
	w.sweep(context.Background())
	if calls != 2 {
		t.Fatal("bounce retry missing")
	}
	quotaWatchReject(m, a, model)
	w.sweep(context.Background())
	if calls != 2 || w.entries[a.ID].bounces != 2 {
		t.Fatal("second bounce retried before 20m")
	}
	now = now.Add(20 * time.Minute)
	w.sweep(context.Background())
	if calls != 3 {
		t.Fatal("second bounce retry missing")
	}
	now = now.Add(16 * time.Minute)
	w.sweep(context.Background())
	if len(w.entries) != 0 {
		t.Fatal("release history was not pruned")
	}
	quotaWatchReject(m, a, model)
	w.sweep(context.Background())
	if calls != 4 || w.entries[a.ID].bounces != 0 {
		t.Fatal("a later cooldown should not count as a bounce")
	}
}

func TestQuotaWatchCandidateFilters(t *testing.T) {
	now := time.Now()
	good := &Auth{Quota: QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: now.Add(time.Hour)}}
	if !quotaWatchCandidate(good, now) {
		t.Fatal("live credential quota excluded")
	}
	for _, change := range []func(*Auth){func(a *Auth) { a.Disabled = true }, func(a *Auth) { a.Status = StatusDisabled }, func(a *Auth) { a.Quota.Reason = "quota" }, func(a *Auth) { a.Quota.NextRecoverAt = now }, func(a *Auth) {
		a.Unavailable = true
		a.Status = StatusError
		a.LastError = &Error{HTTPStatus: 401, Code: "unauthorized"}
	}} {
		a := good.Clone()
		change(a)
		if quotaWatchCandidate(a, now) {
			t.Fatal("ineligible auth selected")
		}
	}
	if quotaWatchCandidate(nil, now) {
		t.Fatal("nil selected")
	}
}

func TestQuotaWatchCredentialRotationFence(t *testing.T) {
	m, a, model, _ := quotaWatchFixture(t)
	quotaWatchReject(m, a, model)
	m.RegisterExecutor(quotaWatchTestExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}, probe: func(context.Context, *Auth) (QuotaProbe, error) {
		p := quotaWatchClearProbe()
		current, _ := m.GetByID(a.ID)
		current.Metadata["access_token"] = "replacement"
		if _, err := m.Update(context.Background(), current); err != nil {
			t.Fatal(err)
		}
		return p, nil
	}})
	now := time.Now()
	w := newTestQuotaWatch(m, &now)
	w.sweep(context.Background())
	got, _ := m.GetByID(a.ID)
	if !got.Quota.Exceeded || got.Metadata["access_token"] != "replacement" || !w.entries[a.ID].lastRelease.IsZero() {
		t.Fatal("stale credential observation applied")
	}
}

func TestQuotaWatchNormalCadenceAndErrorReset(t *testing.T) {
	m, a, model, _ := quotaWatchFixture(t)
	quotaWatchReject(m, a, model)
	calls := 0
	fail := true
	now := time.Now()
	w := newTestQuotaWatch(m, &now)
	m.RegisterExecutor(quotaWatchTestExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}, probe: func(context.Context, *Auth) (QuotaProbe, error) {
		calls++
		if fail {
			return QuotaProbe{}, errors.New("network")
		}
		p := quotaWatchClearProbe()
		p.Windows["seven_day"] = 100
		return p, nil
	}})
	for _, delay := range []time.Duration{5, 10, 20, 30, 30} {
		w.sweep(context.Background())
		if !w.entries[a.ID].nextProbe.Equal(now.Add(delay * time.Minute)) {
			t.Fatalf("backoff mismatch for call %d", calls)
		}
		now = now.Add(delay * time.Minute)
	}
	fail = false
	w.sweep(context.Background())
	if w.entries[a.ID].failures != 0 {
		t.Fatal("hold did not reset error streak")
	}
	count := calls
	w.sweep(context.Background())
	if calls != count {
		t.Fatal("normal cadence ignored")
	}
	now = now.Add(5 * time.Minute)
	w.sweep(context.Background())
	if calls != count+1 {
		t.Fatal("normal probe not due")
	}
}
