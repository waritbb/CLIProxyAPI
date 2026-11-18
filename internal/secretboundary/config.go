package secretboundary

import (
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

func (c candidates) addConfigField(name, value string) {
	if name != "" && name != "-" && value != "" {
		c[candidate{value: value, yamlField: name}] = false
	}
}

// addConfigYAML records the original YAML scalar forms of indexed credentials.
func (c candidates) addConfigYAML(raw []byte, fields map[string]map[string]pluginapi.ConfigField) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return err
	}
	visitPluginConfigs(&doc, func(id string, node *yaml.Node) bool {
		c.addPluginConfig(node, fields[id])
		return false
	})
	visitConfigScalars(&doc, "", func(node *yaml.Node, field string) bool {
		var value string
		if err := node.Decode(&value); err == nil && value != "" {
			if _, ok := c[candidate{value: value, yamlField: field}]; ok {
				c[scalarCandidate(node, field)] = false
			}
		}
		return false
	})
	return nil
}

func scalarCandidate(node *yaml.Node, field string) candidate {
	return candidate{value: node.Value, yamlTag: node.ShortTag(), yamlField: field}
}

func visitConfigScalars(node *yaml.Node, field string, visit func(*yaml.Node, string) bool) bool {
	if node.Kind == yaml.AliasNode && node.Alias != nil && node.Alias.Kind == yaml.ScalarNode {
		node = node.Alias
	}
	if node.Kind == yaml.ScalarNode {
		return field != "" && node.ShortTag() != "!!str" && visit(node, field)
	}
	changed := false
	if node.Kind == yaml.MappingNode {
		for i := 0; i < len(node.Content); i += 2 {
			changed = visitConfigScalars(node.Content[i+1], node.Content[i].Value, visit) || changed
		}
		return changed
	}
	for _, child := range node.Content {
		changed = visitConfigScalars(child, field, visit) || changed
	}
	return changed
}

func (idx *index) redactConfigScalar(node *yaml.Node, field string) bool {
	handle, ok := idx.byScalar[scalarCandidate(node, field)]
	if ok {
		node.Value, node.Tag = handle, "!!str"
	}
	return ok
}

// StringifyConfigSecrets keeps the exact text of credentials whose Go config
// fields are strings before generic YAML decoding can normalize their values.
func StringifyConfigSecrets(c *gin.Context, root *yaml.Node) {
	source, ok := c.Get(configSourceKey)
	if !ok {
		return
	}
	values := source.(candidates)
	visitConfigScalars(root, "", func(node *yaml.Node, field string) bool {
		var value string
		if err := node.Decode(&value); err != nil || value == "" {
			return false
		}
		if _, ok := values[candidate{value: value, yamlField: field}]; !ok {
			return false
		}
		node.Value, node.Tag = value, "!!str"
		return true
	})
}
