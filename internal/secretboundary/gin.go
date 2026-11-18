package secretboundary

import (
	"bufio"
	"bytes"
	"errors"
	"gopkg.in/yaml.v3"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
)

const maxBody = 32 << 20
const authFileKey = "secretboundary.authFile"
const configSourceKey = "secretboundary.configSource"
const protectedKey = "secretboundary.protected"

// Protected reports whether the request is behind the response boundary.
func Protected(c *gin.Context) bool { return c.GetBool(protectedKey) }

// IncludeAuthFile adds the exact download bytes to the response's credential
// index, even when the file is not registered or changed during the request.
func IncludeAuthFile(c *gin.Context, data []byte) { c.Set(authFileKey, data) }

// IncludeConfig adds the exact config version read by the handler.
func IncludeConfig(c *gin.Context, cfg any) { c.Set(configSourceKey, cfg) }

func (b *Boundary) Gin() gin.HandlerFunc {
	return b.Wrap(func(c *gin.Context) { c.Next() })
}

// Callback protects callback responses without translating opaque OAuth parameters.
func (b *Boundary) Callback() gin.HandlerFunc {
	return b.wrap(func(c *gin.Context) { c.Next() }, false)
}

// Wrap also protects plugin routes dispatched outside Gin router groups.
func (b *Boundary) Wrap(next gin.HandlerFunc) gin.HandlerFunc {
	return b.wrap(next, true)
}

func (b *Boundary) wrap(next gin.HandlerFunc, resolve bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if b == nil || c.Writer.Written() || len(c.Writer.Header().Values("Content-Encoding")) != 0 {
			failClosed(c)
			return
		}
		before := b.refresh()
		if before == nil {
			failClosed(c)
			return
		}
		if resolve && !resolveManagementRequest(c, before) {
			return
		}

		outer := c.Writer
		buffer := &capture{ResponseWriter: outer, header: outer.Header().Clone(), status: outer.Status()}
		c.Writer = buffer
		c.Set(protectedKey, true)
		c.Set(pluginScalarKey, b.redactPluginScalars)
		func() {
			defer func() { c.Writer = outer }()
			next(c)
		}()

		if buffer.failed || len(buffer.header.Values("Content-Encoding")) != 0 {
			failClosed(c)
			return
		}
		after := b.refresh()
		if after == nil {
			failClosed(c)
			return
		}
		idx := after
		authFile, hasAuthFile := c.Get(authFileKey)
		cfg, hasConfig := c.Get(configSourceKey)
		if before != after || hasAuthFile || hasConfig {
			values := maps.Clone(after.values)
			if values == nil {
				values = make(candidates)
			}
			if before != after {
				for key, segment := range before.values {
					values[key] = values[key] || segment
				}
			}
			if hasAuthFile {
				var metadata map[string]any
				if err := json.Unmarshal(authFile.([]byte), &metadata); err != nil || metadata == nil {
					failClosed(c)
					return
				}
				values.auth(metadata)
			}
			if hasConfig && (cfg == nil || values.addConfig(cfg) != nil) {
				failClosed(c)
				return
			}
			if !maps.Equal(values, after.values) {
				idx = b.build(values)
			}
		}
		if entry, ok := c.Get(logDownloadKey); ok {
			if buffer.body.Len() != 0 || !streamLog(outer, buffer.header, idx, entry.(logDownload)) {
				failClosed(c)
			}
			return
		}
		var prepare func(*yaml.Node) bool
		if strings.HasSuffix(c.FullPath(), "/config.yaml") {
			prepare = func(root *yaml.Node) bool { return visitPluginConfigs(root, b.redactPluginScalars) }
		}
		body, err := redactResponse(buffer, idx, prepare)
		if err != nil || len(body) > maxBody {
			failClosed(c)
			return
		}
		redactHeaders(outer.Header(), buffer.header, idx)
		outer.Header().Del("Content-Length")
		outer.WriteHeader(buffer.status)
		if buffer.body.Len() != 0 {
			_, _ = outer.Write(body)
		}
	}
}

func redactHeaders(dst, src http.Header, idx *index) {
	for key, values := range src {
		safe := make([]string, len(values))
		for i, value := range values {
			safe[i] = idx.redact(value)
		}
		dst[key] = safe
	}
}

func resolveManagementRequest(c *gin.Context, idx *index) bool {
	typed := idx.typed
	convert := idx.resolve
	switch c.FullPath() {
	case "/v0/management/api-call", "/v8/management/requests/api-call":
		// An arbitrary upstream relay must not accept a credential handle as
		// input for forwarding. Existing auth-index requests are unchanged.
		convert = rejectRelayHandle
		typed = nil
	}
	err := resolveRequest(c.Request, convert, typed)
	if err == nil {
		return true
	}
	status := http.StatusBadRequest
	message := "invalid management request"
	if errors.Is(err, errStaleHandle) {
		status, message = http.StatusConflict, errStaleHandle.Error()
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		status, message = http.StatusRequestEntityTooLarge, "management request too large"
	}
	c.AbortWithStatusJSON(status, gin.H{"error": message})
	return false
}

func failClosed(c *gin.Context) {
	for _, key := range []string{"Content-Encoding", "Content-Length", "Content-Type", "Content-Range", "Content-Disposition", "ETag", "Location"} {
		c.Writer.Header().Del(key)
	}
	c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "unsafe management response"})
}

func mediaType(header http.Header) string {
	value, _, _ := mime.ParseMediaType(header.Get("Content-Type"))
	return value
}

func isJSON(media string) bool {
	return media == "application/json" || strings.HasSuffix(media, "+json")
}

func isYAML(media string) bool {
	return media == "application/yaml" || media == "text/yaml" || media == "application/x-yaml"
}

func rejectRelayHandle(value string) (string, error) {
	if ContainsHandle([]byte(value)) {
		return "", errStaleHandle
	}
	return value, nil
}

func resolveRequest(req *http.Request, convert transform, typed map[string]yaml.Node) error {
	if req.URL.RawQuery != "" {
		values, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			return err
		}
		changed := false
		for _, entries := range values {
			for i, original := range entries {
				value, err := convert(original)
				if err != nil {
					return err
				}
				entries[i] = value
				changed = changed || value != original
			}
		}
		if changed {
			req.URL.RawQuery = values.Encode()
		}
	}
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	media, params, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	yamlRoute := strings.HasSuffix(req.URL.Path, "/config.yaml")
	original := req.Body
	defer original.Close()
	data, err := io.ReadAll(io.LimitReader(original, maxBody+1))
	if err != nil {
		return err
	}
	if len(data) > maxBody {
		return &http.MaxBytesError{Limit: maxBody}
	}
	out := data
	switch {
	case len(bytes.TrimSpace(data)) == 0:
	case strings.HasPrefix(media, "multipart/"):
		err = rejectMultipartHandles(data, params["boundary"])
	case yamlRoute || isYAML(media):
		out, err = transformYAMLNodes(data, convert, true, nil, typed)
	case json.Valid(data):
		out, err = transformJSONScalars(data, convert, func(handle string) (any, bool, error) {
			node, ok := typed[handle]
			if !ok {
				return nil, false, nil
			}
			var value any
			err := node.Decode(&value)
			return value, true, err
		})
	case ContainsHandle(data):
		return errStaleHandle
	}
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(out))
	req.ContentLength = int64(len(out))
	if req.Header.Get("Content-Length") != "" {
		req.Header.Set("Content-Length", strconv.Itoa(len(out)))
	}
	return nil
}

// Auth-file uploads are backups, so a redacted download must not silently
// become a replacement credential. Check all parts before any writes.
func rejectMultipartHandles(data []byte, boundary string) error {
	reader := multipart.NewReader(bytes.NewReader(data), boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		content, err := io.ReadAll(part)
		if err != nil {
			return err
		}
		if err := ValidateAuthFile(content); err != nil {
			return errStaleHandle
		}
	}
}

func redactResponse(buffer *capture, idx *index, prepare func(*yaml.Node) bool) ([]byte, error) {
	data := buffer.body.Bytes()
	if len(data) == 0 {
		return data, nil
	}
	convert := func(value string) (string, error) { return idx.redact(value), nil }
	media := mediaType(buffer.header)
	switch {
	case isJSON(media):
		return transformJSON(data, convert)
	case isYAML(media):
		return transformYAMLNodes(data, convert, true, prepare, nil)
	case media == "text/plain" || media == "text/html":
		return []byte(idx.redact(string(data))), nil
	default:
		return nil, errors.New("unsupported management response content type")
	}
}

type capture struct {
	gin.ResponseWriter
	header  http.Header
	body    bytes.Buffer
	status  int
	written bool
	failed  bool
}

func (w *capture) Header() http.Header { return w.header }
func (w *capture) Status() int         { return w.status }
func (w *capture) Size() int {
	if !w.written {
		return -1
	}
	return w.body.Len()
}
func (w *capture) Written() bool { return w.written }
func (w *capture) WriteHeader(status int) {
	if !w.written && status >= 100 {
		w.status = status
	}
}
func (w *capture) WriteHeaderNow() { w.written = true }
func (w *capture) Write(p []byte) (int, error) {
	w.WriteHeaderNow()
	if w.failed || len(p) > maxBody-w.body.Len() {
		w.failed = true
		return 0, errors.New("management response exceeds limit")
	}
	return w.body.Write(p)
}
func (w *capture) WriteString(s string) (int, error) { return w.Write([]byte(s)) }

// Management routes use bounded responses. A plugin flush cannot bypass the
// buffer, and event streams fail closed with the unsupported content type.
func (w *capture) Flush()              { w.WriteHeaderNow() }
func (w *capture) Pusher() http.Pusher { return nil }
func (w *capture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.failed = true
	return nil, nil, errors.New("management response cannot hijack the connection")
}
