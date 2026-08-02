package secret

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	yaml_v3 "gopkg.in/yaml.v3"
)

func scalarOf(data string) *yaml_v3.Node {
	var document yaml_v3.Node
	Expect(yaml_v3.Unmarshal([]byte(data), &document)).To(Succeed())
	return document.Content[0].Content[1]
}

var _ = Describe("YamlEncoder scalar fidelity", func() {
	var encoder *YamlEncoder

	BeforeEach(func() {
		aesEncoder, err := NewAesEncoder(AesSecretKey)
		Expect(err).NotTo(HaveOccurred())
		encoder = NewYamlEncoder(aesEncoder)
	})

	DescribeTable("tag, style and value of a scalar survive an encrypt then decrypt round trip",
		func(data string) {
			encrypted, err := encoder.EncryptYamlData([]byte(data))
			Expect(err).NotTo(HaveOccurred())

			decrypted, err := encoder.DecryptYamlData(encrypted)
			Expect(err).NotTo(HaveOccurred())

			original := scalarOf(data)
			restored := scalarOf(string(decrypted))

			Expect(restored.Value).To(Equal(original.Value), "value")
			Expect(restored.ShortTag()).To(Equal(original.ShortTag()), "tag")
			Expect(restored.Style).To(Equal(original.Style), "style")
		},
		Entry("integer", "v: 123\n"),
		Entry("negative integer", "v: -7\n"),
		Entry("boolean", "v: true\n"),
		Entry("float", "v: 64.5\n"),
		Entry("timestamp", "v: 2022-07-15\n"),
		Entry("binary", "v: !!binary R0lGODlhDAAMAIQAAP//9/X17unp5WZmZgAAAOfn515eXg==\n"),
		Entry("plain string", "v: hello\n"),
		Entry("numeric string", "v: \"123\"\n"),
		Entry("boolean-like string", "v: \"true\"\n"),
		Entry("folded block string", "v: >-\n  hello\n  world\n"),
		Entry("literal block string", "v: |\n  line1\n  line2\n"),
		Entry("empty string", "v: \"\"\n"),
		Entry("only newlines", "v: \"\\n\\n\"\n"),
		Entry("embedded separator byte", "v: \"a\\0b\\0c\"\n"),
		Entry("tabs and carriage returns", "v: \"a\\tb\\r\\nc\"\n"),
		Entry("leading whitespace", "v: \"  indented\"\n"),
		Entry("unicode with combining marks and astral characters", "v: \"паро́ль→\\U0001F510\"\n"),
		Entry("colon and hash", "v: \"a: b # c\"\n"),
		Entry("long value with double spaces", "v: \"word word word word word word word word word word word word word word word word x  y\"\n"),
	)

	It("keeps a null value untouched", func() {
		data := "v:\n"

		encrypted, err := encoder.EncryptYamlData([]byte(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encrypted)).To(Equal(data))

		decrypted, err := encoder.DecryptYamlData(encrypted)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(decrypted)).To(Equal(data))
	})

	It("emits the ciphertext as an ordinary string scalar so that older readers accept it", func() {
		encrypted, err := encoder.EncryptYamlData([]byte("v: 123\n"))
		Expect(err).NotTo(HaveOccurred())

		cipherScalar := scalarOf(string(encrypted))
		Expect(cipherScalar.ShortTag()).To(Equal("!!str"))
		Expect(cipherScalar.Style).To(Equal(yaml_v3.Style(0)))
		Expect(cipherScalar.Value).To(HavePrefix("0200"))
	})

	It("preserves comments attached to a value and to a key", func() {
		data := "# head comment on key\nv: 123 # line comment on value\n"

		encrypted, err := encoder.EncryptYamlData([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		decrypted, err := encoder.DecryptYamlData(encrypted)
		Expect(err).NotTo(HaveOccurred())

		var document yaml_v3.Node
		Expect(yaml_v3.Unmarshal(decrypted, &document)).To(Succeed())

		keyNode := document.Content[0].Content[0]
		valueNode := document.Content[0].Content[1]

		Expect(keyNode.HeadComment).To(Equal("# head comment on key"))
		Expect(valueNode.LineComment).To(Equal("# line comment on value"))
		Expect(valueNode.Value).To(Equal("123"))
		Expect(valueNode.ShortTag()).To(Equal("!!int"))
	})

	It("restores types through nested mappings, sequences and anchors", func() {
		data := "root: &anchor\n  count: 3\n  enabled: false\n  items:\n    - 1\n    - two\n    - 3.5\nalias: *anchor\n"

		encrypted, err := encoder.EncryptYamlData([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		decrypted, err := encoder.DecryptYamlData(encrypted)
		Expect(err).NotTo(HaveOccurred())

		var restored map[string]interface{}
		Expect(yaml_v3.Unmarshal(decrypted, &restored)).To(Succeed())

		root := restored["root"].(map[string]interface{})
		Expect(root["count"]).To(Equal(3))
		Expect(root["enabled"]).To(Equal(false))
		Expect(root["items"]).To(Equal([]interface{}{1, "two", 3.5}))
	})

	It("leaves values untouched and unframed without an encoder", func() {
		data := "v: 0200abcdef\n"

		decrypted, err := NewYamlEncoder(nil).DecryptYamlData([]byte(data))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(decrypted)).To(Equal(data))
	})

	It("does not frame a whole blob, so a secret file round trips unchanged", func() {
		aesEncoder, err := NewAesEncoder(AesSecretKey)
		Expect(err).NotTo(HaveOccurred())

		content := "line1\nline2\n"

		encoded, err := aesEncoder.Encrypt([]byte(content))
		Expect(err).NotTo(HaveOccurred())

		decoded, err := aesEncoder.Decrypt(encoded)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(decoded)).To(Equal(content))
		Expect(string(decoded)).NotTo(ContainSubstring(string([]byte{scalarFrameSeparator})))
	})

	It("reports an unframed payload found in a YAML value instead of corrupting it", func() {
		aesEncoder, err := NewAesEncoder(AesSecretKey)
		Expect(err).NotTo(HaveOccurred())

		blob, err := aesEncoder.Encrypt([]byte("no framing here"))
		Expect(err).NotTo(HaveOccurred())

		_, err = NewYamlEncoder(aesEncoder).DecryptYamlData([]byte("v: " + string(blob) + "\n"))
		Expect(err).To(MatchError(ContainSubstring("malformed encrypted scalar payload")))
	})

	It("still decrypts a legacy ciphertext as a plain string", func() {
		legacyEncoder, err := NewAesEncoder(legacyFixtureKey)
		Expect(err).NotTo(HaveOccurred())

		decrypted, err := NewYamlEncoder(legacyEncoder).DecryptYamlData([]byte(legacyFixtureSecretValues))
		Expect(err).NotTo(HaveOccurred())

		Expect(string(decrypted)).To(Equal("added_via_secret_values: added_via_secret_values\noverridden_via_secret_values: overridden_via_secret_values\n"))
	})
})
