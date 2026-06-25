// Package conjurapi implements the Conjur API client.
package conjurapi

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

const keychainNamespaceEnvVar = "CONJUR_KEYCHAIN_NAMESPACE"

// resolveKeychainNamespace applies keychain namespace precedence.
//
// When fromCallerConfig is true (Validate / NewClient on a hand-built Config),
// a non-empty value on Config wins over the environment. When false (LoadConfig),
// environment overrides YAML and the value already merged from conjur.conf /
// .conjurrc. LoadConfig sets keychainNamespaceResolved so Validate does not
// re-apply env over a caller-modified Config. Hand-built Configs can call
// SetKeychainNamespaceResolved(true) for the same effect after clearing namespace.
func resolveKeychainNamespace(c *Config, fromCallerConfig bool) {
	if fromCallerConfig && c.KeychainNamespace != "" {
		return
	}

	raw, ok := os.LookupEnv(keychainNamespaceEnvVar)
	if !ok {
		return
	}

	c.KeychainNamespace = raw
}

func rejectEmptyYAMLKeychainNamespace(doc *yaml.Node) error {
	mapping := yamlDocumentMapping(doc)
	if mapping == nil {
		return nil
	}

	return rejectEmptyKeychainNamespaceInMapping(mapping, nil)
}

func rejectEmptyKeychainNamespaceInMapping(mapping *yaml.Node, seen map[*yaml.Node]bool) error {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	if seen == nil {
		seen = make(map[*yaml.Node]bool)
	}
	if seen[mapping] {
		return nil
	}
	seen[mapping] = true

	for i := 0; i+1 < len(mapping.Content); i += 2 {
		key := mapping.Content[i]
		value := mapping.Content[i+1]

		if key.Value == "<<" {
			if err := rejectEmptyKeychainNamespaceInMapping(yamlMergeTarget(value), seen); err != nil {
				return err
			}
			continue
		}

		if key.Value == "keychain_namespace" && yamlKeychainNamespaceValueEmpty(value) {
			return fmt.Errorf("keychain_namespace must not be empty")
		}
	}

	return nil
}

func yamlMergeTarget(value *yaml.Node) *yaml.Node {
	if value == nil {
		return nil
	}
	if value.Kind == yaml.AliasNode {
		return yamlMergeTarget(value.Alias)
	}
	if value.Kind == yaml.MappingNode {
		return value
	}
	return nil
}

func yamlDocumentMapping(doc *yaml.Node) *yaml.Node {
	if doc == nil {
		return nil
	}

	content := doc
	if content.Kind == yaml.DocumentNode && len(content.Content) > 0 {
		content = content.Content[0]
	}

	if content.Kind != yaml.MappingNode {
		return nil
	}

	return content
}

func yamlKeychainNamespaceValueEmpty(value *yaml.Node) bool {
	if value == nil {
		return true
	}

	if value.Kind == yaml.AliasNode {
		if value.Alias == nil {
			return true
		}
		return yamlKeychainNamespaceValueEmpty(value.Alias)
	}

	switch value.Kind {
	case yaml.ScalarNode:
		return value.Tag == "!!null" || value.Value == ""
	default:
		return value.Tag == "!!null"
	}
}
