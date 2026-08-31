package secret

import (
	"bytes"
	"fmt"
	"strconv"

	yaml_v3 "gopkg.in/yaml.v3"
)

// YamlEncoder is an Encoder compatible object with additional helpers to work with yaml data: EncryptYamlData and DecryptYamlData
type YamlEncoder struct {
	Encoder Encoder

	generateFunc	func([]byte) ([]byte, error)
	extractFunc	func([]byte) ([]byte, error)
	formatAware	formatAwareEncoder
}

func NewYamlEncoder(encoder Encoder) *YamlEncoder {
	yamlEncoder := &YamlEncoder{Encoder: encoder}

	if encoder != nil {
		yamlEncoder.generateFunc = encoder.Encrypt
		yamlEncoder.extractFunc = encoder.Decrypt

		if formatAware, ok := encoder.(formatAwareEncoder); ok {
			yamlEncoder.formatAware = formatAware
		}
	} else {
		yamlEncoder.generateFunc = doNothing
		yamlEncoder.extractFunc = doNothing
	}

	return yamlEncoder
}

func (s *YamlEncoder) Encrypt(data []byte) ([]byte, error) {
	resultData, err := s.generateFunc(data)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: check encryption key and data: %w", err)
	}

	return resultData, nil
}

func (s *YamlEncoder) EncryptYamlData(data []byte) ([]byte, error) {
	generateFunc := s.generateFunc
	if s.formatAware != nil {
		generateFunc = s.formatAware.encryptYamlScalar
	}

	resultData, err := doYamlDataV2(generateFunc, s.formatAware, data, encryptYamlMode)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: check encryption key and data: %w", err)
	}

	return resultData, nil
}

func (s *YamlEncoder) Decrypt(data []byte) ([]byte, error) {
	resultData, err := s.extractFunc(data)
	if err != nil {
		if IsExtractDataError(err) {
			return nil, fmt.Errorf("decryption failed: check data `%s`: %w", string(data), err)
		}

		return nil, fmt.Errorf("decryption failed: check encryption key and data: %w", err)
	}

	return resultData, nil
}

func (s *YamlEncoder) DecryptYamlData(data []byte) ([]byte, error) {
	resultData, err := doYamlDataV2(s.extractFunc, s.formatAware, data, decryptYamlMode)
	if err != nil {
		if IsExtractDataError(err) {
			return nil, fmt.Errorf("decryption failed: check data `%s`: %w", string(data), err)
		}

		return nil, fmt.Errorf("decryption failed: check encryption key and data: %w", err)
	}

	return resultData, nil
}

func doYamlDataV2(doFunc func([]byte) ([]byte, error), formatAware formatAwareEncoder, data []byte, mode yamlProcessorMode) ([]byte, error) {
	var config yaml_v3.Node

	if err := yaml_v3.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("unable to unmarshal config data: %w", err)
	}

	resultConfig, err := doYamlValueSecretV2(doFunc, formatAware, deepCopyNode(&config), mode)
	if err != nil {
		return nil, fmt.Errorf("unable to process config secrets: %w", err)
	}

	var resultData bytes.Buffer

	yamlEncoder := yaml_v3.NewEncoder(&resultData)
	yamlEncoder.SetIndent(2)
	if err := yamlEncoder.Encode(resultConfig); err != nil {
		return nil, fmt.Errorf("unable to marshal modified config data: %w", err)
	}

	return resultData.Bytes(), nil
}

type yamlProcessorMode int

const (
	decryptYamlMode yamlProcessorMode = iota
	encryptYamlMode
)

func deepCopyNode(node *yaml_v3.Node) *yaml_v3.Node {
	if node == nil {
		return nil
	}

	copyNode := &yaml_v3.Node{
		Kind:        node.Kind,
		Style:       node.Style,
		Tag:         node.Tag,
		Value:       node.Value,
		Anchor:      node.Anchor,
		Alias:       deepCopyNode(node.Alias),
		HeadComment: node.HeadComment,
		LineComment: node.LineComment,
		FootComment: node.FootComment,
		Line:        node.Line,
		Column:      node.Column,
	}

	if len(node.Content) > 0 {
		copyNode.Content = make([]*yaml_v3.Node, len(node.Content))
		for i, child := range node.Content {
			copyNode.Content[i] = deepCopyNode(child)
		}
	}

	return copyNode
}

func doYamlValueSecretV2(doFunc func([]byte) ([]byte, error), formatAware formatAwareEncoder, node *yaml_v3.Node, mode yamlProcessorMode) (*yaml_v3.Node, error) {
	switch node.Kind {
	case yaml_v3.DocumentNode:
		for pos := 0; pos < len(node.Content); pos += 1 {
			newValueNode, err := doYamlValueSecretV2(doFunc, formatAware, deepCopyNode(node.Content[pos]), mode)
			if err != nil {
				return nil, fmt.Errorf("unable to process document key %d: %w", pos, err)
			}
			node.Content[pos] = newValueNode
		}

	case yaml_v3.MappingNode:
		for pos := 0; pos < len(node.Content); pos += 2 {
			keyNode := node.Content[pos]
			valueNode := node.Content[pos+1]
			newValueNode, err := doYamlValueSecretV2(doFunc, formatAware, deepCopyNode(valueNode), mode)
			if err != nil {
				return nil, fmt.Errorf("unable to process map key %q value=%v: %w", keyNode.Value, valueNode.Value, err)
			}
			node.Content[pos+1] = newValueNode
		}

	case yaml_v3.SequenceNode:
		for pos := 0; pos < len(node.Content); pos += 1 {
			newValueNode, err := doYamlValueSecretV2(doFunc, formatAware, deepCopyNode(node.Content[pos]), mode)
			if err != nil {
				return nil, fmt.Errorf("unable to process array key %d: %w", pos, err)
			}
			node.Content[pos] = newValueNode
		}

	case yaml_v3.AliasNode:
		newAliasNode, err := doYamlValueSecretV2(doFunc, formatAware, deepCopyNode(node.Alias), mode)
		if err != nil {
			return nil, fmt.Errorf("unable to process an alias node %q: %w", node.Value, err)
		}
		node.Alias = newAliasNode

	case yaml_v3.ScalarNode:
		switch mode {
		case decryptYamlMode:
			switch node.ShortTag() {
			case "!!null":
			// ignore

			case "!!str":
				var value string

				if err := node.Decode(&value); err != nil {
					return nil, fmt.Errorf("unable to decode string value %q: %w", node.Value, err)
				}

				if formatAware != nil {
					return node, decryptScalarWithMetadata(formatAware, node, value)
				}

				newValue, err := doFunc([]byte(value))
				if err != nil {
					return nil, err
				}

				if err := encodeScalarPreservingComments(node, string(newValue)); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("unable to decode non string value %q: expected encoded value as hex string", node.Value)
			}

		case encryptYamlMode:
			switch node.ShortTag() {
			case "!!null":
			// ignore

			default:
				plainText, err := scalarPlainText(formatAware, node)
				if err != nil {
					return nil, err
				}

				newValue, err := doFunc(plainText)
				if err != nil {
					return nil, err
				}

				// The ciphertext is always emitted as an ordinary string scalar. Carrying the
				// original tag over would make older readers reject the node, and carrying a
				// folded style over would let the emitter fold line breaks into the hex.
				if err := encodeScalarPreservingComments(node, string(newValue)); err != nil {
					return nil, err
				}
			}
		}
	}

	return node, nil
}

func scalarPlainText(formatAware formatAwareEncoder, node *yaml_v3.Node) ([]byte, error) {
	if formatAware != nil {
		return frameScalar(node.ShortTag(), node.Style, node.Value), nil
	}

	var value interface{}
	if err := node.Decode(&value); err != nil {
		return nil, fmt.Errorf("unable to decode string value %q: %w", node.Value, err)
	}

	return []byte(fmt.Sprintf("%v", value)), nil
}

func decryptScalarWithMetadata(formatAware formatAwareEncoder, node *yaml_v3.Node, value string) error {
	plainText, version, err := formatAware.decryptWithFormat([]byte(value))
	if err != nil {
		return err
	}

	if version != formatVersionAesGCMYaml {
		return encodeScalarPreservingComments(node, string(plainText))
	}

	tag, style, originalValue, err := unframeScalar(plainText)
	if err != nil {
		return err
	}

	node.Kind = yaml_v3.ScalarNode
	node.Tag = tag
	node.Style = style
	node.Value = originalValue
	node.Content = nil
	node.Alias = nil

	return nil
}

func encodeScalarPreservingComments(node *yaml_v3.Node, value string) error {
	headComment, lineComment, footComment := node.HeadComment, node.LineComment, node.FootComment

	if err := node.Encode(value); err != nil {
		return fmt.Errorf("unable to encode string value %q: %w", value, err)
	}

	node.HeadComment, node.LineComment, node.FootComment = headComment, lineComment, footComment

	return nil
}

const scalarFrameSeparator = 0

// frameScalar stores the YAML metadata of a scalar next to its raw value so that the tag
// and style survive a round trip. The value comes last and is treated as opaque bytes, so
// it may contain separators, newlines or anything else.
func frameScalar(shortTag string, style yaml_v3.Style, value string) []byte {
	var payload bytes.Buffer

	payload.WriteString(shortTag)
	payload.WriteByte(scalarFrameSeparator)
	payload.WriteString(strconv.Itoa(int(style)))
	payload.WriteByte(scalarFrameSeparator)
	payload.WriteString(value)

	return payload.Bytes()
}

func unframeScalar(payload []byte) (string, yaml_v3.Style, string, error) {
	parts := bytes.SplitN(payload, []byte{scalarFrameSeparator}, 3)
	if len(parts) != 3 {
		return "", 0, "", fmt.Errorf("malformed encrypted scalar payload: expected tag, style and value")
	}

	style, err := strconv.Atoi(string(parts[1]))
	if err != nil {
		return "", 0, "", fmt.Errorf("unable to parse scalar style %q: %w", string(parts[1]), err)
	}

	return string(parts[0]), yaml_v3.Style(style), string(parts[2]), nil
}

func doNothing(data []byte) ([]byte, error) { return data, nil }
