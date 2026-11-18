package secretboundary

import (
	"github.com/MoeForge/moego/regexp"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const pluginViewKey = "secretboundary.pluginView"

var sensitiveName = regexp.MustCompile("(?i)(key|token|secret|password|credential|cookie)s?$")

// SensitiveName reports whether a configuration key has a credential suffix.
func SensitiveName(name string) bool { return sensitiveName.MatchString(name) }

type pluginView struct {
	boundary *Boundary
	fields   map[string]map[string]pluginapi.ConfigFieldType
	values   candidates
}

func (b *Boundary) scalarHandle(key candidate) string {
	// Include the YAML tag in the digest and omit the display suffix.
	return b.makeHandle(key.value, "\x00plugin-yaml:"+key.yamlTag+"\x00")
}

func RedactPluginConfig(c *gin.Context, id string, instance *yaml.Node) {
	if view, ok := c.Get(pluginViewKey); ok {
		view.(pluginView).redact(id, instance)
	}
}

func RedactPluginConfigTree(c *gin.Context, root *yaml.Node) {
	if view, ok := c.Get(pluginViewKey); ok {
		visitPluginConfigs(root, view.(pluginView).redact)
	}
}

func (c candidates) addPluginConfig(node *yaml.Node, fields map[string]pluginapi.ConfigFieldType) {
	walkPluginSecrets(node, fields, func(secret *yaml.Node) string {
		c.addPluginSecret(secret)
		return ""
	})
}

func (c candidates) addPluginSecret(node *yaml.Node) {
	c.add(node.Value, false)
	if tag := node.ShortTag(); tag != "!!str" {
		c[candidate{value: node.Value, yamlTag: tag}] = false
	}
}

func (v pluginView) redact(id string, instance *yaml.Node) bool {
	out := walkPluginSecrets(instance, v.fields[id], func(node *yaml.Node) string {
		v.values.addPluginSecret(node)
		if tag := node.ShortTag(); tag != "!!str" {
			return v.boundary.scalarHandle(candidate{value: node.Value, yamlTag: tag})
		}
		return v.boundary.handle(node.Value)
	})
	if out == instance {
		return false
	}
	*instance = *out
	return true
}

func visitPluginConfigs(root *yaml.Node, visit func(string, *yaml.Node) bool) bool {
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	configs := mappingValue(mappingValue(root, "plugins"), "configs")
	changed := false
	if configs != nil && configs.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(configs.Content); i += 2 {
			changed = visit(configs.Content[i].Value, configs.Content[i+1]) || changed
		}
	}
	return changed
}

func mappingValue(node *yaml.Node, name string) *yaml.Node {
	if node != nil && node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == name {
				return node.Content[i+1]
			}
		}
	}
	return nil
}

// A credential suffix on the key or an ancestor makes a leaf secret. The
// manifest has no secret flag and types only top-level fields, so an untyped
// nonempty string also defaults to secret. Non-string leaves stay public
// unless their name or an ancestor has a credential suffix.
func pluginLeafSecret(node *yaml.Node, fieldType pluginapi.ConfigFieldType, sensitive bool) bool {
	return node.ShortTag() != "!!null" && node.Value != "" &&
		(sensitive || fieldType == "" && node.ShortTag() == "!!str")
}

// The visitor returns an empty string when it only needs to collect values.
// Copy modified nodes so traversing aliases never writes into their targets.
func walkPluginSecrets(instance *yaml.Node, fields map[string]pluginapi.ConfigFieldType, visit func(*yaml.Node) string) *yaml.Node {
	aliases := make(map[*yaml.Node]bool)
	var walk func(*yaml.Node, bool, pluginapi.ConfigFieldType, bool) *yaml.Node
	walk = func(node *yaml.Node, root bool, fieldType pluginapi.ConfigFieldType, sensitive bool) *yaml.Node {
		switch node.Kind {
		case yaml.AliasNode:
			if node.Alias == nil || aliases[node.Alias] {
				return node
			}
			aliases[node.Alias] = true
			out := walk(node.Alias, root, fieldType, sensitive)
			delete(aliases, node.Alias)
			if out == node.Alias {
				return node
			}
			out.Anchor = ""
			return out
		case yaml.ScalarNode:
			if pluginLeafSecret(node, fieldType, sensitive) {
				if handle := visit(node); handle != "" {
					out := *node
					out.Tag, out.Value = "!!str", handle
					return &out
				}
			}
			return node
		}
		out := node
		replace := func(i int, child *yaml.Node) {
			if child == node.Content[i] {
				return
			}
			if out == node {
				copyNode := *node
				copyNode.Content = append([]*yaml.Node(nil), node.Content...)
				out = &copyNode
			}
			out.Content[i] = child
		}
		if node.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(node.Content); i += 2 {
				key := node.Content[i]
				if root && (key.Value == "enabled" || key.Value == "priority") {
					continue
				}
				var childType pluginapi.ConfigFieldType
				if root {
					childType = fields[key.Value]
				}
				replace(i+1, walk(node.Content[i+1], root && key.ShortTag() == "!!merge", childType, sensitive || SensitiveName(key.Value)))
			}
		} else {
			for i, child := range node.Content {
				replace(i, walk(child, root, "", sensitive))
			}
		}
		return out
	}
	return walk(instance, true, "", false)
}
