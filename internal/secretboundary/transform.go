package secretboundary

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/MoeForge/moego/json"
	"gopkg.in/yaml.v3"
)

type transform func(string) (string, error)

var errDuplicateKey = errors.New("duplicate key after secret translation")

func transformJSON(data []byte, convert transform) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var input any
	if err := dec.Decode(&input); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("invalid JSON document")
	}
	output, changed, err := walkJSON(input, convert)
	if err != nil {
		return nil, err
	}
	if !changed {
		return data, nil
	}
	return json.Marshal(output)
}

func walkJSON(input any, convert transform) (any, bool, error) {
	switch value := input.(type) {
	case string:
		out, err := convert(value)
		return out, out != value, err
	case []any:
		changed := false
		for i, item := range value {
			next, modified, err := walkJSON(item, convert)
			if err != nil {
				return nil, false, err
			}
			value[i] = next
			changed = changed || modified
		}
		return value, changed, nil
	case map[string]any:
		out := make(map[string]any, len(value))
		changed := false
		for key, item := range value {
			name, err := convert(key)
			if err != nil {
				return nil, false, err
			}
			if _, exists := out[name]; exists {
				return nil, false, errDuplicateKey
			}
			next, modified, err := walkJSON(item, convert)
			if err != nil {
				return nil, false, err
			}
			changed = changed || key != name || modified
			out[name] = next
		}
		return out, changed, nil
	default:
		return value, false, nil
	}
}

func transformYAML(data []byte, convert transform, comments bool) ([]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []*yaml.Node
	changed := false
	for {
		doc := new(yaml.Node)
		err := dec.Decode(doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if err := walkYAML(doc, convert, comments, &changed); err != nil {
			return nil, err
		}
		docs = append(docs, doc)
	}
	if !changed {
		return data, nil
	}
	var output bytes.Buffer
	enc := yaml.NewEncoder(&output)
	enc.SetIndent(2)
	for _, doc := range docs {
		if err := enc.Encode(doc); err != nil {
			return nil, err
		}
	}
	return output.Bytes(), enc.Close()
}

func walkYAML(node *yaml.Node, convert transform, comments bool, changed *bool) error {
	if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!str" {
		out, err := convert(node.Value)
		if err != nil {
			return err
		}
		*changed = *changed || out != node.Value
		node.Value = out
	}
	if comments {
		for _, comment := range []*string{&node.HeadComment, &node.LineComment, &node.FootComment} {
			out, err := convert(*comment)
			if err != nil {
				return err
			}
			*changed = *changed || out != *comment
			*comment = out
		}
	}
	for _, child := range node.Content {
		if err := walkYAML(child, convert, comments, changed); err != nil {
			return err
		}
	}
	return nil
}

// ValidateConfig reports the location of a reserved handle without echoing it.
func ValidateConfig(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil // The existing config parser owns syntax diagnostics.
	}
	return validateConfigNode(&doc, nil)
}

func validateConfigNode(node *yaml.Node, path []string) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if ContainsHandle([]byte(node.Value)) {
			return fmt.Errorf("config field %s: %w", strings.Join(path, "."), ErrHandleInStorage)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if ContainsHandle([]byte(key.Value)) {
				return fmt.Errorf("config mapping at %s: %w", strings.Join(path, "."), ErrHandleInStorage)
			}
			if err := validateConfigNode(node.Content[i+1], append(path, key.Value)); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			if err := validateConfigNode(child, append(path, fmt.Sprintf("[%d]", i))); err != nil {
				return err
			}
		}
	default:
		for _, child := range node.Content {
			if err := validateConfigNode(child, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func ValidateAuthFile(data []byte) error {
	if ContainsHandle(data) {
		return ErrHandleInStorage
	}
	// Handles can also arrive encoded using JSON string escapes.
	_, err := transformJSON(data, func(s string) (string, error) {
		if ContainsHandle([]byte(s)) {
			return "", ErrHandleInStorage
		}
		return s, nil
	})
	if errors.Is(err, ErrHandleInStorage) {
		return err
	}
	return nil // Auth file parsing owns validation of the JSON.
}
