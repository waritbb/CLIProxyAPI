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
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/MoeForge/moego/regexp"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const handlePrefix = "cpx_h1_"

var handlePattern = regexp.MustCompile(handlePrefix + "[A-Z2-7]{26}_[A-Za-z0-9_.~-]{4}")

var ErrHandleInStorage = errors.New("secret handles cannot be persisted")
var errStaleHandle = errors.New("stale secret handle; reload")

func ContainsHandle(data []byte) bool { return handlePattern.Match(data) }

// Snapshot supplies the config and the auth manager's current credential metadata.
type Snapshot struct {
	Config        any
	ConfigYAML    []byte
	Auths         []map[string]any
	PluginConfigs map[string]yaml.Node
	PluginFields  map[string]map[string]pluginapi.ConfigField
}

type Boundary struct {
	key      []byte
	snapshot func() *Snapshot
	mu       sync.Mutex
	previous *Snapshot
	current  *index
}

func Open(stateDir string, snapshot func() *Snapshot) (*Boundary, error) {
	key, err := openKey(stateDir)
	if err != nil {
		return nil, err
	}
	b := &Boundary{key: key, snapshot: snapshot}
	if snapshot != nil {
		if b.refresh() == nil {
			return nil, errors.New("invalid management secret snapshot")
		}
	} else {
		b.current = b.build(nil)
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
	return b.makeHandle(secret, "")
}

func (b *Boundary) makeHandle(secret, domain string) string {
	mac := hmac.New(sha256.New, b.key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte(secret))
	suffix := []byte("____")
	// Never expose a complete short credential through its display suffix.
	if domain == "" && len(secret) > len(suffix) {
		for i, ch := range []byte(secret[len(secret)-len(suffix):]) {
			if ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || strings.ContainsRune("-._~", rune(ch)) {
				suffix[i] = ch
			}
		}
	}
	return handlePrefix + base32.StdEncoding.EncodeToString(mac.Sum(nil))[:26] + "_" + string(suffix)
}

type candidate struct {
	value       string
	yamlTag     string
	yamlField   string
	resolveOnly bool
}

type candidates map[candidate]bool // true permits short pipe-delimited segments

func (c candidates) add(value string, segment bool) {
	if value != "" {
		key := candidate{value: value}
		c[key] = c[key] || segment
	}
}

type index struct {
	values       candidates
	byHandle     map[string]string
	byValue      map[string]string
	long         *strings.Replacer
	typed        map[string]yaml.Node
	byScalar     map[candidate]string
	logSecrets   [256][]string
	maxLogSecret int
	pluginFields map[string]map[string]pluginapi.ConfigField
}

func (b *Boundary) build(values candidates) *index {
	idx := &index{values: values, byHandle: make(map[string]string), byValue: make(map[string]string), typed: make(map[string]yaml.Node), byScalar: make(map[candidate]string)}
	long := make([]string, 0, len(values))
	for key := range values {
		val := key.value
		if key.yamlTag != "" {
			handle := b.scalarHandle(key)
			if key.yamlField != "" {
				idx.byScalar[key] = handle
			}
			idx.typed[handle] = yaml.Node{Kind: yaml.ScalarNode, Tag: key.yamlTag, Value: val}
			continue
		}
		if key.yamlField != "" {
			continue
		}
		handle := b.handle(val)
		idx.byHandle[handle] = val
		if key.resolveOnly {
			continue
		}
		idx.byValue[val] = handle
		if len(val) >= 8 {
			long = append(long, val)
		}
	}
	sort.Slice(long, func(i, j int) bool { return len(long[i]) > len(long[j]) })
	pairs := make([]string, 0, 2*len(long))
	for _, val := range long {
		pairs = append(pairs, val, idx.byValue[val])
		idx.logSecrets[val[0]] = append(idx.logSecrets[val[0]], val)
		idx.maxLogSecret = max(idx.maxLogSecret, len(val))
	}
	idx.long = strings.NewReplacer(pairs...)
	return idx
}

func (b *Boundary) setSnapshot(source *Snapshot) error {
	values := make(candidates)
	if err := values.addConfig(source.Config); err != nil {
		b.current = nil
		return err
	}
	if err := values.addConfigYAML(source.ConfigYAML, source.PluginFields); err != nil {
		b.current = nil
		return err
	}
	for id, node := range source.PluginConfigs {
		values.addPluginConfig(&node, source.PluginFields[id])
	}
	for _, auth := range source.Auths {
		values.auth(auth)
	}
	if b.current == nil || !maps.Equal(b.current.values, values) ||
		!maps.EqualFunc(b.current.pluginFields, source.PluginFields, func(a, b map[string]pluginapi.ConfigField) bool {
			return maps.EqualFunc(a, b, func(a, b pluginapi.ConfigField) bool {
				return a.Type == b.Type && a.Secret == b.Secret
			})
		}) {
		b.current = b.build(values)
		b.current.pluginFields = source.PluginFields
	}
	return nil
}

func (b *Boundary) Rebuild(cfg any, auths []map[string]any) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.previous = nil
	return b.setSnapshot(&Snapshot{Config: cfg, Auths: auths})
}

func (b *Boundary) refresh() *index {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.snapshot != nil {
		source := b.snapshot()
		if source == nil {
			b.previous, b.current = nil, nil
			return nil
		}
		if source != b.previous {
			_ = b.setSnapshot(source)
			b.previous = source
		}
	}
	return b.current
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
		if len(part) < 8 && idx.values[candidate{value: part}] {
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
	if node, ok := idx.typed[value]; ok {
		return node.Value, nil
	}
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

func (c candidates) addConfig(cfg any) error { return c.config(reflect.ValueOf(cfg), "", "") }

func (c candidates) config(v reflect.Value, tag, yamlField string) error {
	if tag == "public" || !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		return c.config(v.Elem(), tag, yamlField)
	case reflect.Struct:
		if v.Type() == reflect.TypeFor[yaml.Node]() {
			if tag != "plugin-config" {
				return errors.New("unclassified YAML config node")
			}
			// Plugin instances are scanned with their manifest fields in setSnapshot.
			return nil
		}
		for i := range v.NumField() {
			field := v.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			mode := field.Tag.Get("secret")
			if mode == "" && field.Tag.Get("yaml") == "-" && field.Tag.Get("json") == "-" {
				if field.Type != reflect.TypeFor[yaml.Node]() {
					continue
				}
			}
			name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if err := c.config(v.Field(i), mode, name); err != nil {
				return fmt.Errorf("%s: %w", field.Name, err)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			if err := c.config(v.Index(i), tag, yamlField); err != nil {
				return err
			}
		}
	case reflect.Map:
		if tag == "" {
			elem := v.Type().Elem()
			for elem.Kind() == reflect.Pointer || elem.Kind() == reflect.Slice || elem.Kind() == reflect.Array {
				elem = elem.Elem()
			}
			switch elem.Kind() {
			case reflect.Struct, reflect.Interface, reflect.Map:
				return errors.New("unclassified dynamic config map")
			}
			return nil
		}
		iter := v.MapRange()
		for iter.Next() {
			if tag == "sensitive-header-values" {
				name, value := iter.Key().String(), iter.Value().String()
				if sensitiveHeader(name) {
					c.header(name, value, true)
					c.addConfigField(name, value)
				}
				continue
			}
			if err := c.config(iter.Value(), tag, yamlField); err != nil {
				return err
			}
		}
	case reflect.String:
		switch tag {
		case "value":
			c.add(v.String(), true)
			c.addConfigField(yamlField, v.String())
		case "url-userinfo":
			c.url(v.String())
		}
	}
	return nil
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

func sensitiveHeader(name string) bool {
	lower := strings.ToLower(name)
	return lower == "authorization" || lower == "proxy-authorization" ||
		strings.Contains(lower, "token") || strings.Contains(lower, "secret") ||
		strings.Contains(lower, "key") || strings.Contains(lower, "cookie") ||
		strings.Contains(lower, "credential") || strings.Contains(lower, "password")
}

func (c candidates) header(name, value string, shortSegments bool) {
	if sensitiveHeader(name) {
		c.add(value, shortSegments)
		if scheme, token, ok := strings.Cut(value, " "); ok && strings.EqualFold(scheme, "Bearer") {
			c.add(strings.TrimSpace(token), shortSegments)
		}
	}
}

// These top-level fields feed the panel's auth listing and metadata editor.
// Nested objects do not inherit the allowlist (including OAuth token payloads
// and free-text fields such as note), except for exact copies of a top-level
// public string under the same name, such as the project_id that Antigravity
// copies into its capability hints.
var publicAuthFields = map[string]bool{
	"type": true, "provider": true, "email": true, "expired": true,
	"prefix": true, "priority": true, "note": true, "disabled": true,
	"weight": true, "exclude_models": true, "excluded_models": true, "excluded-models": true,
	"disable_cooling": true, "disable-cooling": true, "websockets": true,
	"use_siwc": true, "use-siwc": true, "using_api": true, "using-api": true,
	"project_id": true, "projectId": true, "gemini_virtual_project": true,
	"plan_type": true, "planType": true,
	"account_id": true, "accountId": true, "chatgpt_account_id": true, "chatgptAccountId": true,
	"oauth_provider": true, "oauthProvider": true, "portal": true,
	"last_refresh": true, "modtime": true, "updated_at": true,
	"quota_provider": true, "quotaProvider": true, "quota_plugin_id": true, "quotaPluginId": true,
	"siwc_expires_at":                   true,
	"chatgpt_subscription_active_until": true, "chatgptSubscriptionActiveUntil": true,
	"subscription_active_until": true, "subscriptionActiveUntil": true,
	"domain": true, "sub": true, "subject": true, "user_id": true, "userId": true,
}

func (c candidates) auth(auth map[string]any) {
	mirrors := map[string]string{}
	for key, val := range auth {
		if s, ok := val.(string); ok && s != "" && publicAuthFields[key] {
			mirrors[key] = s
		}
	}
	for key, val := range auth {
		switch key {
		case "proxy_url", "base_url", "base-url":
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
						c.leaves(value, nil)
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
		if publicAuthFields[key] {
			switch val.(type) {
			case string, bool, float64, int, int64, nil:
				continue
			}
			if key == "exclude_models" || key == "excluded_models" || key == "excluded-models" {
				continue
			}
		}
		c.leaves(val, mirrors)
	}
}

func (c candidates) leaves(value any, mirrors map[string]string) {
	switch v := value.(type) {
	case string:
		c.add(v, false)
	case map[string]any:
		for key, item := range v {
			if s, ok := item.(string); !ok || mirrors[key] != s {
				c.leaves(item, mirrors)
			}
		}
	case map[string]string:
		for key, item := range v {
			if mirrors[key] != item {
				c.add(item, false)
			}
		}
	case []any:
		for _, item := range v {
			c.leaves(item, mirrors)
		}
	case []string:
		for _, item := range v {
			c.add(item, false)
		}
	}
}
