// Package secretboundary translates credential values at the management HTTP boundary.
package secretboundary

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/MoeForge/moego/regexp"
)

const handlePrefix = "cpx_h1_"

var handlePattern = regexp.MustCompile(handlePrefix + "[A-Z2-7]{26}_[A-Za-z0-9_.~-]{4}")

var ErrHandleInStorage = errors.New("secret handles cannot be persisted")
var errStaleHandle = errors.New("stale secret handle; reload")

func ContainsHandle(data []byte) bool { return handlePattern.Match(data) }

// Snapshot supplies the config and the auth manager's current credential metadata.
type Snapshot func() (cfg any, auths []map[string]any)

type Boundary struct {
	key      []byte
	snapshot Snapshot
	current  atomic.Pointer[index]
}

func Open(stateDir string, snapshot Snapshot) (*Boundary, error) {
	key, err := openKey(stateDir)
	if err != nil {
		return nil, err
	}
	b := &Boundary{key: key, snapshot: snapshot}
	if snapshot != nil {
		b.Rebuild(snapshot())
	} else {
		b.Rebuild(nil, nil)
	}
	return b, nil
}

func openKey(dir string) ([]byte, error) {
	key := make([]byte, sha256.Size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if dir == "" {
		return key, nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	// Publish a complete key with an exclusive link so another process cannot
	// read a half-written key if both instances start on the same state dir.
	temp, err := os.CreateTemp(dir, ".handle-key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(temp.Name())
	_, errWrite := temp.Write(key)
	errSync := temp.Sync()
	errClose := temp.Close()
	if err := errors.Join(errWrite, errSync, errClose); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "handle.key")
	if err = os.Link(temp.Name(), path); err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != sha256.Size {
		return nil, fmt.Errorf("invalid management handle key file")
	}
	return os.ReadFile(path)
}

func (b *Boundary) handle(secret string) string {
	mac := hmac.New(sha256.New, b.key)
	_, _ = mac.Write([]byte(secret))
	suffix := []byte("____")
	// Never expose a complete short credential through its display suffix.
	if len(secret) > len(suffix) {
		for i, ch := range []byte(secret[len(secret)-len(suffix):]) {
			if ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || strings.ContainsRune("-._~", rune(ch)) {
				suffix[i] = ch
			}
		}
	}
	return handlePrefix + base32.StdEncoding.EncodeToString(mac.Sum(nil))[:26] + "_" + string(suffix)
}

type candidates map[string]bool // true permits short pipe-delimited segments

func (c candidates) add(value string, segment bool) {
	if value != "" {
		c[value] = c[value] || segment
	}
}

type index struct {
	values   candidates
	byHandle map[string]string
	byValue  map[string]string
	long     *strings.Replacer
}

func (b *Boundary) build(values candidates) *index {
	idx := &index{values: values, byHandle: make(map[string]string), byValue: make(map[string]string)}
	long := make([]string, 0, len(values))
	for val := range values {
		handle := b.handle(val)
		idx.byHandle[handle] = val
		idx.byValue[val] = handle
		if len(val) >= 8 {
			long = append(long, val)
		}
	}
	sort.Slice(long, func(i, j int) bool { return len(long[i]) > len(long[j]) })
	pairs := make([]string, 0, 2*len(long))
	for _, val := range long {
		pairs = append(pairs, val, idx.byValue[val])
	}
	idx.long = strings.NewReplacer(pairs...)
	return idx
}

func (b *Boundary) Rebuild(cfg any, auths []map[string]any) {
	values := make(candidates)
	values.addConfig(cfg)
	for _, auth := range auths {
		values.auth(auth)
	}
	b.current.Store(b.build(values))
}

func (b *Boundary) refresh() *index {
	if b.snapshot == nil {
		return b.current.Load()
	}
	cfg, auths := b.snapshot()
	values := make(candidates)
	values.addConfig(cfg)
	for _, auth := range auths {
		values.auth(auth)
	}
	if existing := b.current.Load(); existing != nil && maps.Equal(existing.values, values) {
		return existing
	}
	idx := b.build(values)
	b.current.Store(idx)
	return idx
}

func (idx *index) redact(value string) string {
	if handle := idx.byValue[value]; handle != "" {
		return handle
	}
	// Match short segments on the original text. Long secrets can themselves
	// contain a pipe, so apply longest-first replacement across the whole value.
	long := idx.long.Replace(value)
	if !strings.Contains(long, "|") {
		return idx.redactURL(long)
	}
	parts := strings.Split(long, "|")
	for i, part := range parts {
		if len(part) < 8 && idx.values[part] {
			parts[i] = idx.byValue[part]
		} else {
			parts[i] = idx.redactURL(part)
		}
	}
	return strings.Join(parts, "|")
}

func (idx *index) redactURL(value string) string {
	if end, start, ok := userinfoBounds(value); ok {
		if handle := idx.byValue[value[start:end]]; handle != "" {
			return value[:start] + handle + value[end:]
		}
	}
	return value
}

func userinfoBounds(value string) (end, start int, ok bool) {
	scheme, rest, absolute := strings.Cut(value, "://")
	if !absolute {
		return 0, 0, false
	}
	authority, _, _ := strings.Cut(rest, "/")
	authority, _, _ = strings.Cut(authority, "?")
	authority, _, _ = strings.Cut(authority, "#")
	start = len(scheme) + 3
	end = strings.LastIndexByte(authority, '@')
	return start + end, start, end >= 0
}

func (idx *index) resolve(value string) (string, error) {
	var err error
	out := handlePattern.ReplaceAllStringFunc(value, func(match string) string {
		if resolved, ok := idx.byHandle[match]; ok {
			return resolved
		}
		err = errStaleHandle
		return match
	})
	return out, err
}

func (c candidates) addConfig(cfg any) { c.config(reflect.ValueOf(cfg), "") }

func (c candidates) config(v reflect.Value, tag string) {
	if tag == "public" || !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		c.config(v.Elem(), tag)
	case reflect.Struct:
		for i := range v.NumField() {
			field := v.Type().Field(i)
			if field.IsExported() && (field.Tag.Get("yaml") != "-" || field.Tag.Get("json") != "-") {
				c.config(v.Field(i), field.Tag.Get("secret"))
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			c.config(v.Index(i), tag)
		}
	case reflect.Map:
		if tag == "" {
			return
		}
		iter := v.MapRange()
		for iter.Next() {
			mode := tag
			if mode == "sensitive-header-values" {
				c.header(iter.Key().String(), iter.Value().String(), true)
				continue
			}
			c.config(iter.Value(), mode)
		}
	case reflect.String:
		switch tag {
		case "value":
			c.add(v.String(), true)
		case "url-userinfo":
			c.url(v.String())
		}
	}
}

func (c candidates) url(value string) {
	if u, err := url.Parse(value); err == nil && u.User != nil {
		// Preserve a usable URL for the panel. Resolve the complete userinfo
		// component, including its original percent escapes, on the way back.
		if end, start, ok := userinfoBounds(value); ok {
			c.add(value[start:end], false)
		}
		c.add(u.User.Username(), false)
		if password, ok := u.User.Password(); ok {
			c.add(password, false)
		}
	}
}

func (c candidates) header(name, value string, shortSegments bool) {
	lower := strings.ToLower(name)
	if lower == "authorization" || lower == "proxy-authorization" ||
		strings.Contains(lower, "token") || strings.Contains(lower, "secret") ||
		strings.Contains(lower, "key") || strings.Contains(lower, "cookie") ||
		strings.Contains(lower, "credential") || strings.Contains(lower, "password") {
		c.add(value, shortSegments)
		if scheme, token, ok := strings.Cut(value, " "); ok && strings.EqualFold(scheme, "Bearer") {
			c.add(strings.TrimSpace(token), shortSegments)
		}
	}
}

// These top-level fields feed the panel's auth listing and metadata editor.
// Nested objects do not inherit the allowlist (including OAuth token payloads).
var publicAuthFields = map[string]bool{
	"type": true, "provider": true, "email": true, "expired": true,
	"prefix": true, "priority": true, "note": true, "disabled": true,
	"weight": true, "exclude_models": true, "excluded_models": true, "excluded-models": true,
	"disable_cooling": true, "disable-cooling": true, "websockets": true,
	"use_siwc": true, "use-siwc": true, "using_api": true, "using-api": true,
}

func (c candidates) auth(auth map[string]any) {
	for key, val := range auth {
		switch key {
		case "proxy_url":
			if s, ok := val.(string); ok {
				c.url(s)
				continue
			}
		case "headers":
			if headers, ok := val.(map[string]any); ok {
				for name, value := range headers {
					if s, ok := value.(string); ok {
						c.header(name, s, false)
					} else {
						c.leaves(value)
					}
				}
				continue
			}
			if headers, ok := val.(map[string]string); ok {
				for name, value := range headers {
					c.header(name, value, false)
				}
				continue
			}
		}
		if !publicAuthFields[key] {
			c.leaves(val)
		}
	}
}

func (c candidates) leaves(value any) {
	switch v := value.(type) {
	case string:
		c.add(v, false)
	case map[string]any:
		for _, item := range v {
			c.leaves(item)
		}
	case map[string]string:
		for _, item := range v {
			c.leaves(item)
		}
	case []any:
		for _, item := range v {
			c.leaves(item)
		}
	case []string:
		for _, item := range v {
			c.add(item, false)
		}
	}
}
