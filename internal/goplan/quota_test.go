package goplan

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/httptransport"
	log "github.com/sirupsen/logrus"
)

const (
	rollingJSON = `"rolling":{"status":"ok","percent":25,"resetsAt":"2026-11-18T15:03:46.000Z"}`
	weeklyJSON  = `"weekly":{"status":"ok","percent":50,"resetsAt":"2026-11-23T00:00:00.000Z"}`
	monthlyJSON = `"monthly":{"status":"ok","percent":75,"resetsAt":"2026-12-01T04:29:48.000Z"}`
	usageJSON   = `{"usage":{` + rollingJSON + "," + weeklyJSON + "," + monthlyJSON + "}}"
)

func TestParseUsage(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		ok      bool
		limited bool
	}{
		{name: "200 shape", body: usageJSON, ok: true},
		{name: "rate-limited", body: strings.Replace(usageJSON, `"status":"ok"`, `"status":"rate-limited"`, 1), ok: true, limited: true},
		{name: "missing window", body: `{"usage":{` + rollingJSON + "," + weeklyJSON + "}}"},
		{name: "null window", body: strings.Replace(usageJSON, monthlyJSON, `"monthly":null`, 1)},
		{name: "null reset", body: strings.Replace(usageJSON, `"2026-11-18T15:03:46.000Z"`, "null", 1)},
		{name: "missing reset", body: strings.Replace(usageJSON, `,"resetsAt":"2026-11-18T15:03:46.000Z"`, "", 1)},
		{name: "invalid reset", body: strings.Replace(usageJSON, "2026-11-18T15:03:46.000Z", "tomorrow", 1)},
		{name: "above 100", body: strings.Replace(usageJSON, ":25,", ":101,", 1)},
		{name: "below zero", body: strings.Replace(usageJSON, ":25,", ":-1,", 1)},
		{name: "NaN", body: strings.Replace(usageJSON, ":25,", ":NaN,", 1)},
		{name: "overflow", body: strings.Replace(usageJSON, ":25,", ":1e400,", 1)},
		{name: "null percent", body: strings.Replace(usageJSON, ":25,", ":null,", 1)},
		{name: "missing percent", body: strings.Replace(usageJSON, `"percent":25,`, "", 1)},
		{name: "unknown status", body: strings.Replace(usageJSON, `"status":"ok"`, `"status":"unknown"`, 1)},
		{name: "extra fields ignored", body: strings.TrimSuffix(usageJSON, "}}}") + `,"extra":[1]}},"extra":true}`, ok: true},
		{name: "trailing garbage", body: usageJSON + " garbage"},
		{name: "trailing JSON", body: usageJSON + " {}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseUsage([]byte(tc.body))
			if ok != tc.ok {
				t.Fatalf("parse success = %v, want %v", ok, tc.ok)
			}
			if !ok {
				if got != (Reading{}) {
					t.Fatal("invalid body returned a partial reading")
				}
				return
			}
			resets := [3]string{"2026-11-18T15:03:46Z", "2026-11-23T00:00:00Z", "2026-12-01T04:29:48Z"}
			for i, used := range [3]float64{25, 50, 75} {
				window := got.Windows[i]
				if window.UsedPct != used || window.Limited != (i == 0 && tc.limited) || window.ResetsAt.Format(time.RFC3339) != resets[i] {
					t.Errorf("window %d = %+v", i, window)
				}
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func usageAt(t *testing.T, ctx context.Context, endpoint, bearer string) context.Context {
	t.Helper()
	target, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal("invalid test server endpoint")
	}
	return httptransport.WithDecorator(ctx, func(http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != usageURL || req.Method != http.MethodGet || req.Header.Get("Authorization") != "Bearer "+bearer {
				t.Error("unexpected upstream URL, method, or bearer")
			}
			clone := req.Clone(req.Context())
			clone.URL = target
			clone.Host = target.Host
			return http.DefaultTransport.RoundTrip(clone)
		})
	})
}

func TestFetch(t *testing.T) {
	const bearer = "synthetic-bearer-marker"
	const upstreamText = "synthetic-upstream-text"
	logger := log.StandardLogger()
	previousOutput, previousLevel := logger.Out, logger.GetLevel()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	logger.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		logger.SetOutput(previousOutput)
		logger.SetLevel(previousLevel)
	})

	tests := []struct {
		name   string
		status int
		body   string
		want   Cause
	}{
		{name: "200", status: 200, body: usageJSON},
		{name: "401", status: 401, body: upstreamText, want: KeyRejected},
		{name: "403", status: 403, body: upstreamText, want: NoSubscription},
		{name: "429", status: 429, body: upstreamText, want: UpstreamDown},
		{name: "500", status: 500, body: upstreamText, want: UpstreamDown},
		{name: "timeout", want: UpstreamDown},
		{name: "transport", status: -1, want: UpstreamDown},
		{name: "redirect refused", status: 302, want: UpstreamDown},
		{name: "oversized", status: 200, body: usageJSON + strings.Repeat(" ", usageBodyCap) + upstreamText, want: SchemaDrift},
		{name: "malformed", status: 200, body: upstreamText, want: SchemaDrift},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs.Reset()
			var hits atomic.Int32
			redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("followed a redirect")
			}))
			defer redirect.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if tc.status == 0 {
					<-r.Context().Done()
					return
				}
				w.Header().Set("Location", redirect.URL)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			if tc.status == -1 {
				server.Close()
			}
			ctx := usageAt(t, t.Context(), server.URL, bearer)
			if tc.status == 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			var fetcher Fetcher
			auth := &coreauth.Auth{ID: "usage-test", Attributes: map[string]string{"api_key": bearer}}
			reading, cause := fetcher.Fetch(ctx, auth, nil)
			if cause != tc.want {
				t.Fatalf("cause = %d, want %d", cause, tc.want)
			}
			if (reading == (Reading{})) != (cause != OK) {
				t.Fatal("reading returned for failure or absent on success")
			}
			if tc.status == 302 && hits.Load() != 1 {
				t.Fatal("redirect test did not reach the upstream once")
			}
			for _, marker := range []string{bearer, upstreamText, usageURL, server.URL, redirect.URL} {
				if strings.Contains(CauseMessage(cause), marker) || strings.Contains(logs.String(), marker) {
					t.Fatal("sensitive upstream data reached messages or logs")
				}
			}
		})
	}
}

func TestFetchCache(t *testing.T) {
	const bearer = "synthetic-cache-bearer"
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, usageJSON)
	}))
	defer server.Close()
	ctx := usageAt(t, t.Context(), server.URL, bearer)
	var fetcher Fetcher
	first := &coreauth.Auth{ID: "one", Attributes: map[string]string{"api_key": bearer}}
	second := &coreauth.Auth{ID: "two", Attributes: map[string]string{"api_key": bearer}}
	for _, auth := range []*coreauth.Auth{first, first, second} {
		if _, cause := fetcher.Fetch(ctx, auth, nil); cause != OK {
			t.Fatalf("cause = %d, want success", cause)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want two for two identities", hits.Load())
	}
	cached := fetcher.readings[first.ID]
	cached.expiresAt = time.Now().Add(-time.Second)
	fetcher.readings[first.ID] = cached
	if reading, cause := fetcher.Fetch(ctx, first, nil); cause != UpstreamDown || reading != (Reading{}) {
		t.Fatal("expired reading survived an upstream failure")
	}
	if _, cause := fetcher.Fetch(ctx, first, nil); cause != OK || hits.Load() != 4 {
		t.Fatal("failed fetch prevented a subsequent upstream refresh")
	}
}
