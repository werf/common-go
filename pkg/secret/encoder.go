package secret

type Encoder interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(encodedData []byte) ([]byte, error)
}

// formatAwareDecrypter is implemented by encoders whose ciphertext carries a format
// version. YamlEncoder only stores and restores YAML scalar metadata when its Encoder
// implements this, so that any other Encoder keeps producing and consuming plain values.
type formatAwareDecrypter interface {
	decryptWithFormat(encodedData []byte) ([]byte, uint16, error)
}
