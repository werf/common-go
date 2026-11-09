package secret

import (
	"testing"
)

// Ciphertexts and key below are copied verbatim from werf's committed e2e fixtures
// (test/e2e/converge/_fixtures/complex/state0). They are the backward-compatibility
// contract for the legacy AES-CBC format and must never be regenerated.
var (
	legacyFixtureKey = []byte("bc3458408a5687e60b9417adb84e4ad0")

	legacyFixtureSecretValues = "added_via_secret_values: 10007b717b44ec49b722c5d517cf6259bd20c93ea5ef2dcfc3934bccee59613d0ac07f5f39835d30f3736fc5d3edc10335bb\n" +
		"overridden_via_secret_values: 1000ad8725d33000e7bf81a5b65851003b9ca35e999b617ccff1fe402c7a941382f4fc5c9257de633a42427958b5fb43b2e3\n"

	legacyFixtureSecretValuesExtra = "added_via_secret_values_extra: 1000dc58aec55b8ce919d24fd1a9c5435f983d9a39f1fba0971d2452ae30d03788dffd4ff2d179b426e62badec66c12e2f7d\n" +
		"overridden_via_secret_values_extra: 1000b52f32b4f9a78fb8b53e2a4d4211408b0de9c9bc83a8cda7a6be77e288f307bf90d016b476960f3c99ab51be48b318fcb4f404a4559bec045631902ec5f49728\n"

	legacyFixtureSecretFile = []byte("100052fb0fa1cc8ef1cb123be089cdb853cc153772691b8fb743d612a7b64d65614d4d8745250752564941227eb8d7161523")
)

// Produced with legacyFixtureKey by EncryptYamlData of common-go 366cad5, the last commit
// that wrote the legacy format, from:
//
//	int: 123
//	bool: true
//	float: 1.5
//	str: "123"
//	word: hello
//	empty: ""
//	list:
//	  - 7
//	  - text
//	nested:
//	  port: 8080
//
// Must never be regenerated.
const legacyFixtureTypedSecretValues = "int: 100049fb3706a4dc50af98db279edad4d2eee12ebc001536f6f07f28a99af986bcb7\n" +
	"bool: 100011c3864f8d033f8939302c526d80fa2210341e83659c67affc436690987b1d7c\n" +
	"float: 10007233c3e253d6dcba511ededbf1f48babc482c1187e432de9c06145c8a9f3611d\n" +
	"str: 1000e328b697103331fe3bbecb5149dd67b0c2222d1cd92d54d68cc91a1cc7179f8d\n" +
	"word: 1000473fdef8d8975c864ba435da451b21b99139ae294d57791677f24fcbdd097e1b\n" +
	"empty: 10002deb30270b0bbf8791981c8f64658eb2d300a551a2af75fb354934223ec90113\n" +
	"list:\n" +
	"  - 100053d4b400566e5825126073067824be7f50b0cc62264d028951e9b0fdce26dd6d\n" +
	"  - 100005053b5d681b05a389607d3df93a9fac96db2818d2664ebd53a6115630d4b5df\n" +
	"nested:\n" +
	"  port: 100073da155b059e690fa5c0dc893ceb8df5eff9c264361276e4116b4914c728a559\n"

func TestLegacyFixtureYamlDataDecrypts(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{
			name:     "secret-values.yaml",
			data:     legacyFixtureSecretValues,
			expected: "added_via_secret_values: added_via_secret_values\noverridden_via_secret_values: overridden_via_secret_values\n",
		},
		{
			name:     "secret-values-extra.yaml",
			data:     legacyFixtureSecretValuesExtra,
			expected: "added_via_secret_values_extra: added_via_secret_values_extra\noverridden_via_secret_values_extra: overridden_via_secret_values_extra\n",
		},
	}

	encoder, err := NewAesEncoder(legacyFixtureKey)
	if err != nil {
		t.Fatal(err)
	}

	yamlEncoder := NewYamlEncoder(encoder)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := yamlEncoder.DecryptYamlData([]byte(test.data))
			if err != nil {
				t.Fatal(err)
			}

			if string(result) != test.expected {
				t.Errorf("\n[EXPECTED]: %q\n[GOT]: %q", test.expected, string(result))
			}
		})
	}
}

func TestLegacyFixtureSecretFileDecrypts(t *testing.T) {
	encoder, err := NewAesEncoder(legacyFixtureKey)
	if err != nil {
		t.Fatal(err)
	}

	result, err := encoder.Decrypt(legacyFixtureSecretFile)
	if err != nil {
		t.Fatal(err)
	}

	expected := "secretConfigContent\n"
	if string(result) != expected {
		t.Errorf("\n[EXPECTED]: %q\n[GOT]: %q", expected, string(result))
	}
}
