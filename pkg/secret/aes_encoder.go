package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	formatVersionLegacyCBC uint16 = 16
	formatVersionAesGCM    uint16 = 2

	formatVersionSize = 2
	gcmNonceSize      = 12
)

var (
	errMinimumDataLength        = errors.New("minimum required data length")
	errUnpadFailed              = errors.New("inconsistent data, unpad failed")
	errBlockSizeMultiple        = errors.New("data isn't a multiple of the block size")
	errAuthenticationFailed     = errors.New("authentication failed: data has been tampered with or the encryption key is wrong")
	errUnsupportedFormatVersion = errors.New("unsupported secret format version")
)

type AesEncoder struct {
	CipherBlock cipher.Block
}

var _ formatAwareDecrypter = (*AesEncoder)(nil)

func GenerateAesSecretKey() ([]byte, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}

	result := []byte(hex.EncodeToString(randomBytes))

	return result, nil
}

func NewAesEncoder(key []byte) (*AesEncoder, error) {
	key, err := hexToBinary(key)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	secret := &AesEncoder{c}
	return secret, nil
}

func (s *AesEncoder) Encrypt(data []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(s.CipherBlock)
	if err != nil {
		return nil, fmt.Errorf("initialize aes-gcm: %w", err)
	}

	args := make([]byte, formatVersionSize+gcmNonceSize)
	binary.LittleEndian.PutUint16(args[:formatVersionSize], formatVersionAesGCM)

	nonce := args[formatVersionSize:]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read random nonce: %w", err)
	}

	args = gcm.Seal(args, nonce, data, nil)

	result := make([]byte, hex.EncodedLen(len(args)))
	hex.Encode(result, args)

	return result, nil
}

func (s *AesEncoder) Decrypt(data []byte) ([]byte, error) {
	result, _, err := s.decryptWithFormat(data)
	return result, err
}

// Empty input is reported as the legacy format so that callers which restore YAML
// scalar metadata treat the result as an unframed plain value.
func (s *AesEncoder) decryptWithFormat(data []byte) ([]byte, uint16, error) {
	if len(data) == 0 {
		return data, formatVersionLegacyCBC, nil
	}

	dataToExtract, err := hexToBinary(data)
	if err != nil {
		return nil, 0, err
	}

	if len(dataToExtract) < formatVersionSize {
		return nil, 0, minimumDataLengthError(legacyCBCMinimumDataBinarySize())
	}

	version := binary.LittleEndian.Uint16(dataToExtract[:formatVersionSize])

	switch version {
	case formatVersionLegacyCBC:
		result, err := s.decryptLegacyCBC(dataToExtract)
		return result, version, err
	case formatVersionAesGCM:
		result, err := s.decryptAesGCM(dataToExtract)
		return result, version, err
	default:
		return nil, version, fmt.Errorf("%w: %d", errUnsupportedFormatVersion, version)
	}
}

func (s *AesEncoder) decryptLegacyCBC(dataToExtract []byte) ([]byte, error) {
	if len(dataToExtract) < legacyCBCMinimumDataBinarySize() {
		return nil, minimumDataLengthError(legacyCBCMinimumDataBinarySize())
	}

	iv := dataToExtract[formatVersionSize : formatVersionSize+aes.BlockSize]
	cipherText := dataToExtract[formatVersionSize+aes.BlockSize:]

	if len(cipherText)%aes.BlockSize != 0 {
		return nil, errBlockSizeMultiple
	}

	mode := cipher.NewCBCDecrypter(s.CipherBlock, iv)
	mode.CryptBlocks(cipherText, cipherText)

	return unpad(cipherText)
}

func (s *AesEncoder) decryptAesGCM(dataToExtract []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(s.CipherBlock)
	if err != nil {
		return nil, fmt.Errorf("initialize aes-gcm: %w", err)
	}

	minimumDataBinarySize := formatVersionSize + gcmNonceSize + gcm.Overhead()
	if len(dataToExtract) < minimumDataBinarySize {
		return nil, minimumDataLengthError(minimumDataBinarySize)
	}

	nonce := dataToExtract[formatVersionSize : formatVersionSize+gcmNonceSize]
	cipherText := dataToExtract[formatVersionSize+gcmNonceSize:]

	result, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, errAuthenticationFailed
	}

	return result, nil
}

func legacyCBCMinimumDataBinarySize() int {
	return formatVersionSize + aes.BlockSize + aes.BlockSize
}

func minimumDataLengthError(minimumDataBinarySize int) error {
	return fmt.Errorf("%w: '%v'", errMinimumDataLength, minimumDataBinarySize*2)
}

func unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errUnpadFailed
	}

	unpadding := int(data[length-1])
	if unpadding == 0 || unpadding > aes.BlockSize || unpadding > length {
		return nil, errUnpadFailed
	}

	if subtle.ConstantTimeCompare(data[length-unpadding:], bytes.Repeat([]byte{byte(unpadding)}, unpadding)) != 1 {
		return nil, errUnpadFailed
	}

	return data[:length-unpadding], nil
}

func hexToBinary(data []byte) ([]byte, error) {
	result := make([]byte, hex.DecodedLen(len(data)))
	if _, err := hex.Decode(result, data); err != nil {
		return nil, err
	}

	return result, nil
}

func IsExtractDataError(err error) bool {
	return errors.Is(err, errMinimumDataLength) ||
		errors.Is(err, hex.ErrLength) ||
		errors.Is(err, errUnsupportedFormatVersion)
}
