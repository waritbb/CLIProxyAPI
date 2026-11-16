package auth

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

type quotaWatchPanickingHook struct{ NoopHook }

func (quotaWatchPanickingHook) OnAuthUpdated(context.Context, *Auth) {
	panic("manager update hook panic")
}

func TestQuotaWatchManagerPanicPropagates(t *testing.T) {
	m, a, model, _ := quotaWatchFixture(t)
	quotaWatchReject(m, a, model)
	m.RegisterExecutor(quotaWatchTestExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}, probe: func(context.Context, *Auth) (QuotaProbe, error) {
		return quotaWatchClearProbe(), nil
	}})
	m.hook = quotaWatchPanickingHook{}
	now := time.Now()
	w := newTestQuotaWatch(m, &now)
	defer func() {
		if got := recover(); got != "manager update hook panic" {
			t.Errorf("manager panic = %v, want manager update hook panic", got)
		}
	}()
	w.sweep(context.Background())
}

func TestQuotaWatchRefusedObservationPreservesSnapshot(t *testing.T) {
	m, a, model, _ := quotaWatchFixture(t)
	a.Quota.Signals = map[string]string{
		"anthropic-ratelimit-unified-status":    "rejected",
		"anthropic-ratelimit-unified-7d-status": "rejected",
	}
	a.Quota.ObservedAt = time.Now().Add(-time.Minute)
	if _, err := m.Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	quotaWatchReject(m, a, model)
	oldHooks := log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(oldHooks) })
	hook := logtest.NewGlobal()
	var before *Auth
	m.RegisterExecutor(quotaWatchTestExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}, probe: func(context.Context, *Auth) (QuotaProbe, error) {
		quotaWatchReject(m, a, model)
		before, _ = m.GetByID(a.ID)
		p := quotaWatchClearProbe()
		p.SentAt = before.UpdatedAt.Add(-time.Nanosecond)
		return p, nil
	}})
	updateHook := &savedFieldsHook{}
	m.hook = updateHook
	now := time.Now()
	w := newTestQuotaWatch(m, &now)
	w.sweep(context.Background())
	got, _ := m.GetByID(a.ID)
	if !reflect.DeepEqual(got.Quota.Signals, before.Quota.Signals) || !got.Quota.ObservedAt.Equal(before.Quota.ObservedAt) {
		t.Errorf("refused observation changed signals/ObservedAt: got %+v, want %+v", got.Quota, before.Quota)
	}
	if !reflect.DeepEqual(got, before) || updateHook.auth != nil {
		t.Error("refused observation committed an auth update")
	}
	if !w.entries[a.ID].lastRelease.IsZero() {
		t.Error("refused observation recorded a release")
	}
	entry := hook.LastEntry()
	if entry == nil || entry.Message != "quota watch: release_superseded" || entry.Data["reason"] != "state_changed" {
		t.Fatalf("superseded observation log = %+v", entry)
	}
}

func TestQuotaWatchRetryAfterCeiling(t *testing.T) {
	for _, outcome := range []string{"error", "success"} {
		for _, tc := range []struct {
			name  string
			retry time.Duration
			want  time.Duration
		}{
			{"cadence_floor", 0, 5 * time.Minute},
			{"within_ceiling", 10 * time.Minute, 10 * time.Minute},
			{"one_day", 86400 * time.Second, 30 * time.Minute},
		} {
			t.Run(outcome+"/"+tc.name, func(t *testing.T) {
				m, a, model, _ := quotaWatchFixture(t)
				quotaWatchReject(m, a, model)
				calls := 0
				m.RegisterExecutor(quotaWatchTestExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}, probe: func(context.Context, *Auth) (QuotaProbe, error) {
					calls++
					if outcome == "error" {
						return QuotaProbe{}, &QuotaProbeError{Status: 429, RetryAfter: tc.retry, Err: errors.New("limited")}
					}
					p := quotaWatchClearProbe()
					p.Windows["seven_day"] = 100
					p.RetryAfter = tc.retry
					return p, nil
				}})
				now := time.Now()
				w := newTestQuotaWatch(m, &now)
				w.sweep(context.Background())
				if got := w.entries[a.ID].nextProbe.Sub(now); got != tc.want {
					t.Fatalf("probe delay = %v, want %v", got, tc.want)
				}
				now = now.Add(tc.want - time.Nanosecond)
				w.sweep(context.Background())
				if calls != 1 {
					t.Fatal("probed before Retry-After floor")
				}
				now = now.Add(time.Nanosecond)
				w.sweep(context.Background())
				if calls != 2 {
					t.Fatal("did not probe when capped Retry-After elapsed")
				}
			})
		}
	}
}
