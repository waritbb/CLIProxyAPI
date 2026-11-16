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
	return fmt.Sprintf("quota probe failed with status %d", e.Status)
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
		if _, ok := p.Windows[key]; !ok {
			return QuotaVerdictHold, "missing_required_window"
		}
	}
	for _, used := range p.Windows {
		if math.IsNaN(used) || math.IsInf(used, 0) || used < 0 || used > 100 {
			return QuotaVerdictHold, "bad_value"
		}
		if used == 100 {
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
	for key, value := range signals {
		if !strings.HasPrefix(key, quotaWatchSignalPrefix) || key == quotaWatchSignalPrefix+"complete" {
			continue
		}
		used, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return false
		}
		p.Windows[strings.TrimPrefix(key, quotaWatchSignalPrefix)] = used
	}
	v, _ := judgeQuotaWindows(p)
	return v == QuotaVerdictClear
}
