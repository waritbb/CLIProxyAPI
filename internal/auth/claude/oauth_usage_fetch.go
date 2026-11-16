package claude

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
)

func (o *ClaudeAuth) fetchOAuthUsageJSON(ctx context.Context, accessToken string) ([]byte, error) {
	if o == nil || o.httpClient == nil {
		return nil, fmt.Errorf("fetch Claude OAuth usage: HTTP client is nil")
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, fmt.Errorf("fetch Claude OAuth usage: access token is empty")
	}
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, UsageURL, nil)
	if errRequest != nil {
		return nil, fmt.Errorf("create Claude OAuth usage request: %w", errRequest)
	}
	applyClaudeOAuthAxiosHeaders(req)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	resp, errDo := o.httpClient.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("fetch Claude OAuth usage: %w", errDo)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, &OAuthUsageStatusError{Status: resp.StatusCode, RetryAfter: oauthUsageRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}
	body, errRead := readOAuthUsageBytes(resp.Body)
	if errRead != nil {
		return nil, fmt.Errorf("read Claude OAuth usage: %w", errRead)
	}
	encodings := strings.Split(strings.Join(resp.Header.Values("Content-Encoding"), ","), ",")
	for i := len(encodings) - 1; i >= 0; i-- {
		encoding := strings.ToLower(strings.TrimSpace(encodings[i]))
		if encoding == "" || encoding == "identity" {
			continue
		}
		body, errRead = decodeOAuthUsageEncoding(body, encoding)
		if errRead != nil {
			return nil, errRead
		}
	}
	return body, nil
}

func readOAuthUsageBytes(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, oauthUsageBodyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > oauthUsageBodyLimit {
		return nil, fmt.Errorf("Claude OAuth usage exceeds body limit")
	}
	return body, nil
}

func decodeOAuthUsageEncoding(body []byte, encoding string) ([]byte, error) {
	var reader io.ReadCloser
	switch encoding {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("decode Claude OAuth usage gzip: %w", err)
		}
		reader = r
	case "deflate":
		r, err := zlib.NewReader(bytes.NewReader(body))
		if err == nil {
			reader = r
		} else {
			reader = flate.NewReader(bytes.NewReader(body))
		}
	case "br":
		reader = io.NopCloser(brotli.NewReader(bytes.NewReader(body)))
	case "compress":
		reader = lzw.NewReader(bytes.NewReader(body), lzw.MSB, 8)
	default:
		return nil, fmt.Errorf("unsupported Claude OAuth usage content encoding")
	}
	decoded, errRead := readOAuthUsageBytes(reader)
	errClose := reader.Close()
	if errRead != nil {
		return nil, fmt.Errorf("decode Claude OAuth usage: %w", errRead)
	}
	if errClose != nil {
		return nil, fmt.Errorf("close Claude OAuth usage decoder: %w", errClose)
	}
	return decoded, nil
}
