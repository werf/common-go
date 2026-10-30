package secret

import (
	"reflect"
	"testing"
)

func TestDecryptYamlDataWithUntypedScalars(t *testing.T) {
	encoder, err := NewAesEncoder(legacyFixtureKey)
	if err != nil {
		t.Fatal(err)
	}

	yamlEncoder := NewYamlEncoder(encoder)

	typedValues, err := yamlEncoder.EncryptYamlData([]byte("typed: 1\n"))
	if err != nil {
		t.Fatal(err)
	}

	blob, err := encoder.Encrypt([]byte("42"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		data     string
		expected []UntypedScalar
	}{
		{
			name: "legacy werf fixture",
			data: legacyFixtureSecretValues,
			expected: []UntypedScalar{
				{Path: []interface{}{"added_via_secret_values"}, Value: "added_via_secret_values"},
				{Path: []interface{}{"overridden_via_secret_values"}, Value: "overridden_via_secret_values"},
			},
		},
		{
			name: "legacy values of every type",
			data: legacyFixtureTypedSecretValues,
			expected: []UntypedScalar{
				{Path: []interface{}{"int"}, Value: "123"},
				{Path: []interface{}{"bool"}, Value: "true"},
				{Path: []interface{}{"float"}, Value: "1.5"},
				{Path: []interface{}{"str"}, Value: "123"},
				{Path: []interface{}{"word"}, Value: "hello"},
				{Path: []interface{}{"empty"}, Value: ""},
				{Path: []interface{}{"list", 0}, Value: "7"},
				{Path: []interface{}{"list", 1}, Value: "text"},
				{Path: []interface{}{"nested", "port"}, Value: "8080"},
			},
		},
		{
			name:     "current format",
			data:     string(typedValues),
			expected: []UntypedScalar{},
		},
		{
			name:     "current format mixed with a legacy value",
			data:     string(typedValues) + "legacy:\n  - 100049fb3706a4dc50af98db279edad4d2eee12ebc001536f6f07f28a99af986bcb7\n",
			expected: []UntypedScalar{{Path: []interface{}{"legacy", 0}, Value: "123"}},
		},
		{
			name:     "whole-blob value",
			data:     "blob: " + string(blob) + "\n",
			expected: []UntypedScalar{{Path: []interface{}{"blob"}, Value: "42"}},
		},
		{
			name:     "empty and null values are not encrypted",
			data:     "empty: \"\"\nnull:\n",
			expected: []UntypedScalar{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, untypedScalars, err := yamlEncoder.DecryptYamlDataWithUntypedScalars([]byte(test.data))
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(untypedScalars, test.expected) {
				t.Errorf("\n[EXPECTED]: %#v\n[GOT]: %#v", test.expected, untypedScalars)
			}

			expectedResult, err := yamlEncoder.DecryptYamlData([]byte(test.data))
			if err != nil {
				t.Fatal(err)
			}

			if string(result) != string(expectedResult) {
				t.Errorf("result differs from DecryptYamlData\n[EXPECTED]: %q\n[GOT]: %q", expectedResult, result)
			}
		})
	}
}

func TestDecryptYamlDataWithUntypedScalarsWithoutFormatAwareEncoder(t *testing.T) {
	_, untypedScalars, err := NewYamlEncoder(&EncoderMock{}).DecryptYamlDataWithUntypedScalars([]byte("v: abc\n"))
	if err != nil {
		t.Fatal(err)
	}

	if len(untypedScalars) != 0 {
		t.Errorf("expected no untyped scalars, got %#v", untypedScalars)
	}
}
