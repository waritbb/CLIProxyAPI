package secretboundary

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type testCredential struct {
	Key string `secret:"value"`
}

func TestHandleStableAndShortMatching(t *testing.T) {
	dir := t.TempDir()
	const long = "fixture-long-key"
	const short = "p@ss!"
	const tiny = "tiny"
	cfg := []testCredential{{long}, {short}, {tiny}}
	check := func() string {
		b, err := Open(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		b.Rebuild(cfg, []map[string]any{{"token": "abc"}})
		idx := b.current.Load()
		handle := idx.redact(long)
		if len(handle) != 38 || !ContainsHandle([]byte(handle)) || !strings.HasSuffix(handle, "_-key") {
			t.Fatal("unexpected handle grammar")
		}
		if idx.redact(short) == short || idx.redact(tiny) == tiny || strings.Contains(idx.redact(tiny), tiny) ||
			idx.redact("embedded "+short) != "embedded "+short {
			t.Fatal("short credential matching or suffix is unsafe")
		}
		if got := idx.redact(long + "|" + short); !ContainsHandle([]byte(got)) || strings.Contains(got, short) {
			t.Fatal("pipe-separated credential leaked")
		}
		if idx.redact("url|abc") != "url|abc" || idx.redact("abc") == "abc" {
			t.Fatal("short auth token must match a whole string")
		}
		if got, err := idx.resolve(handle); err != nil || got != long {
			t.Fatal("could not resolve handle")
		}
		return handle
	}
	if a, b := check(), check(); a != b {
		t.Fatal("handle changed after reopening the same state directory")
	}
	if info, err := os.Stat(filepath.Join(dir, "handle.key")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("handle key file permissions")
	}
}

func TestBoundaryCoversBeforeAndAfterSnapshots(t *testing.T) {
	const old = "fixture-original-key"
	const next = "fixture-new-key"
	cfg := testCredential{old}
	b, err := Open("", func() (any, []map[string]any) { return cfg, nil })
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.POST("/", b.Gin(), func(c *gin.Context) {
		if c.GetHeader("Authorization") != b.handle(old) {
			t.Error("management Authorization header was changed")
		}
		cfg.Key = next
		c.JSON(200, gin.H{old: next})
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", b.handle(old))
	r.ServeHTTP(w, req)
	if w.Code != 200 || strings.Contains(w.Body.String(), old) || strings.Contains(w.Body.String(), next) ||
		!strings.Contains(w.Body.String(), b.handle(old)) || !strings.Contains(w.Body.String(), b.handle(next)) {
		t.Fatal("response must redact both the old object key and the new value")
	}
}

func TestBoundaryFailsClosed(t *testing.T) {
	const key = "fixture-original-key"
	for _, tc := range []struct {
		name, media, encoding string
		body                  []byte
	}{
		{"unknown type", "application/octet-stream", "", []byte(key)},
		{"invalid JSON", "application/json", "", []byte(key)},
		{"encoded", "text/plain", "gzip", []byte(key)},
		{"oversized", "text/plain", "", bytes.Repeat([]byte("x"), maxBody+1)},
		{"event stream", "text/event-stream", "", []byte(key)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Open("", nil)
			if err != nil {
				t.Fatal(err)
			}
			b.Rebuild(testCredential{key}, nil)
			router := gin.New()
			router.GET("/", b.Gin(), func(c *gin.Context) {
				c.Header("X-Original", key)
				c.Header("Content-Encoding", tc.encoding)
				c.Data(200, tc.media, tc.body)
				c.Writer.Flush()
			})
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if w.Code != 502 || strings.Contains(w.Body.String(), key) || w.Header().Get("X-Original") != "" || w.Header().Get("Content-Encoding") != "" {
				t.Fatal("unsafe response or headers escaped the buffer")
			}
		})
	}
}

func TestBoundaryRejectsMultipartHandleBeforeDispatch(t *testing.T) {
	b, err := Open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	upload := multipart.NewWriter(&body)
	for _, item := range []struct{ name, content string }{
		{"first.json", `{"token":"candidate-plaintext"}`},
		{"later.json", `{"token":"\u0063px_h1_AAAAAAAAAAAAAAAAAAAAAAAAAA_0000"}`},
	} {
		part, err := upload.CreateFormFile("file", item.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(item.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := upload.Close(); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.POST("/", b.Gin(), func(c *gin.Context) { t.Error("upload dispatched before all parts were checked") })
	req := httptest.NewRequest("POST", "/", &body)
	req.Header.Set("Content-Type", upload.FormDataContentType())
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("multipart handle returned %d", w.Code)
	}
}
