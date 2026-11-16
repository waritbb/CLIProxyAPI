package auth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// QuotaProber optionally observes quota without refreshing or mutating credentials.
type QuotaProber interface {
	ProbeQuota(context.Context, *Auth) (QuotaProbe, error)
}

var ErrQuotaProbeUnsupported = errors.New("quota probe unsupported for this credential")

type QuotaProbeError struct {
	Status     int
	RetryAfter time.Duration
	Err        error
}

func (e *QuotaProbeError) Error() string {
	return fmt.Sprintf("quota probe failed with status %d: %v", e.Status, e.Err)
}
func (e *QuotaProbeError) Unwrap() error { return e.Err }

// SentAt precedes the request, so a failure written during the probe wins.
// A present but unused five_hour window is represented by zero utilization.
type QuotaProbe struct {
	SentAt     time.Time
	Windows    map[string]float64
	Complete   bool
	RetryAfter time.Duration
}

type QuotaVerdict int

const (
	QuotaVerdictHold QuotaVerdict = iota
	QuotaVerdictClear
)

func judgeQuotaWindows(p QuotaProbe) (QuotaVerdict, string) {
	if !p.Complete {
		return QuotaVerdictHold, "incomplete"
	}
	for _, key := range []string{"five_hour", "seven_day"} {
		used, ok := p.Windows[key]
		if !ok {
			return QuotaVerdictHold, "missing_required_window"
		}
		if math.IsNaN(used) || math.IsInf(used, 0) || used < 0 {
			return QuotaVerdictHold, "bad_value"
		}
		if used >= 100 {
			return QuotaVerdictHold, "window_at_limit"
		}
	}
	return QuotaVerdictClear, "all_windows_below_limit"
}

const quotaWatchSignalPrefix = "quota-watch/"

func encodeQuotaWatchSignals(p QuotaProbe) map[string]string {
	signals := map[string]string{quotaWatchSignalPrefix + "complete": strconv.FormatBool(p.Complete)}
	for key, used := range p.Windows {
		signals[quotaWatchSignalPrefix+key] = strconv.FormatFloat(used, 'g', -1, 64)
	}
	return signals
}
func quotaWatchSignalsClear(signals map[string]string) bool {
	if signals[quotaWatchSignalPrefix+"complete"] != "true" {
		return false
	}
	p := QuotaProbe{Complete: true, Windows: make(map[string]float64)}
	for _, key := range []string{"five_hour", "seven_day"} {
		used, err := strconv.ParseFloat(signals[quotaWatchSignalPrefix+key], 64)
		if err != nil {
			return false
		}
		p.Windows[key] = used
	}

	v, _ := judgeQuotaWindows(p)
	return v == QuotaVerdictClear
}

func quotaProbeLogError(a *Auth, err error) error {
	message := err.Error()
	for _, token := range []string{authAccessToken(a), authRefreshToken(a), authSIWCTokenField(a, "access_token"), authSIWCTokenField(a, "refresh_token")} {
		if token != "" {
			message = strings.ReplaceAll(message, token, "[redacted]")
		}
	}
	return errors.New(sanitizeRenewalMessage(message))
}
