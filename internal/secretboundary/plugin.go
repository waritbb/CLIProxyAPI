package secretboundary

import (
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

const pluginScalarKey = "secretboundary.pluginScalar"

func (b *Boundary) scalarHandle(key candidate) string {
	// Use the YAML tag as part of the digest, without exposing the scalar in
	// the display suffix (a boolean or short ID would be easy to infer).
	return b.makeHandle(key.value, "\x00plugin-yaml:"+key.yamlTag+"\x00")
}

// RedactPluginScalars protects non-string leaves before a config view is
// decoded into JSON, where their original YAML tag and spelling are lost.
func RedactPluginScalars(c *gin.Context, instance *yaml.Node) {
	if fn, ok := c.Get(pluginScalarKey); ok {
		fn.(func(*yaml.Node) bool)(instance)
	}
}

func RedactPluginConfigTree(c *gin.Context, root *yaml.Node) {
	if fn, ok := c.Get(pluginScalarKey); ok {
		visitPluginConfigs(root, fn.(func(*yaml.Node) bool))
	}
}

func (b *Boundary) redactPluginScalars(instance *yaml.Node) bool {
	changed := false
	visitPluginScalars(instance, func(node *yaml.Node) {
		if node.ShortTag() != "!!str" {
			node.Value = b.scalarHandle(candidate{value: node.Value, yamlTag: node.ShortTag()})
			node.Tag = "!!str"
			changed = true
		}
	})
	return changed
}

func visitPluginConfigs(root *yaml.Node, visit func(*yaml.Node) bool) bool {
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	configs := mappingValue(mappingValue(root, "plugins"), "configs")
	changed := false
	if configs != nil && configs.Kind == yaml.MappingNode {
		for i := 1; i < len(configs.Content); i += 2 {
			changed = visit(configs.Content[i]) || changed
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

func visitPluginScalars(instance *yaml.Node, visit func(*yaml.Node)) {
	seen := map[*yaml.Node]bool{}
	var walk func(*yaml.Node)
	walk = func(node *yaml.Node) {
		if node == nil || seen[node] {
			return
		}
		seen[node] = true
		switch node.Kind {
		case yaml.AliasNode:
			walk(node.Alias)
		case yaml.ScalarNode:
			visit(node)
		case yaml.MappingNode:
			for i := 1; i < len(node.Content); i += 2 {
				walk(node.Content[i])
			}
		default:
			for _, child := range node.Content {
				walk(child)
			}
		}
	}
	if instance.Kind != yaml.MappingNode {
		walk(instance)
		return
	}
	for i := 0; i+1 < len(instance.Content); i += 2 {
		switch instance.Content[i].Value {
		case "enabled", "priority":
		default:
			walk(instance.Content[i+1])
		}
	}
}
