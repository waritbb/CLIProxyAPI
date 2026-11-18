package goplan

import (
	"context"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	usageURL     = "https://opencode.ai/zen/go/v1/usage"
	usageTimeout = 10 * time.Second
	usageBodyCap = 64 << 10
	readingTTL   = 30 * time.Second
)

type cachedReading struct {
	reading   Reading
	expiresAt time.Time
}

type Fetcher struct {
	mu       sync.Mutex
	readings map[string]cachedReading
}

// Fetch reads quota for an auth already checked by Covers.
func (f *Fetcher) Fetch(ctx context.Context, a *coreauth.Auth, cfg *config.Config) (Reading, Cause) {
	f.mu.Lock()
	cached := f.readings[a.ID]
	f.mu.Unlock()
	if time.Now().Before(cached.expiresAt) {
		return cached.reading, OK
	}

	ctx, cancel := context.WithTimeout(ctx, usageTimeout)
	defer cancel()
	bearer := strings.TrimSpace(a.Attributes["api_key"])
	if bearer == "" {
		log.WithField("cause", KeyRejected).Debug("OpenCode Go quota fetch failed")
		return Reading{}, KeyRejected
	}
	client := helps.NewProxyAwareHTTPClient(ctx, cfg, a, 0)
	reading, cause := fetchUsage(ctx, client, bearer)
	if cause != OK {
		log.WithField("cause", cause).Debug("OpenCode Go quota fetch failed")
		return Reading{}, cause
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.readings == nil {
		f.readings = make(map[string]cachedReading)
	}
	maps.DeleteFunc(f.readings, func(_ string, entry cachedReading) bool {
		return !now.Before(entry.expiresAt)
	})
	f.readings[a.ID] = cachedReading{reading: reading, expiresAt: now.Add(readingTTL)}
	return reading, OK
}

func fetchUsage(ctx context.Context, client *http.Client, bearer string) (Reading, Cause) {
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, usageURL, nil)
	if errRequest != nil {
		return Reading{}, UpstreamDown
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")

	resp, errDo := client.Do(req)
	if errDo != nil {
		return Reading{}, UpstreamDown
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return Reading{}, KeyRejected
	case http.StatusForbidden:
		return Reading{}, NoSubscription
	case http.StatusOK:
	default:
		return Reading{}, UpstreamDown
	}

	body, errRead := io.ReadAll(io.LimitReader(resp.Body, usageBodyCap+1))
	if errRead != nil {
		return Reading{}, UpstreamDown
	}
	if len(body) > usageBodyCap {
		return Reading{}, SchemaDrift
	}
	reading, ok := parseUsage(body)
	if !ok {
		return Reading{}, SchemaDrift
	}
	return reading, OK
}
