package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAesEncoderWritesAesGCMFormatVersion(t *testing.T) {
	s, err := NewAesEncoder(AesSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	encodedData, err := s.Encrypt([]byte("value"))
	if err != nil {
		t.Fatal(err)
	}

	if prefix := string(encodedData[:4]); prefix != "0200" {
		t.Errorf("\n[EXPECTED]: %s\n[GOT]: %s", "0200", prefix)
	}
}

// A version-2 ciphertext is shorter than the legacy minimum of 34 binary bytes, so a
// minimum-length check left ahead of the version dispatch would reject valid data.
func TestAesEncoderShortPlaintextRoundTrip(t *testing.T) {
	s, err := NewAesEncoder(AesSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, plainText := range []string{"", "a", "ab", "abc"} {
		t.Run(fmt.Sprintf("%d bytes", len(plainText)), func(t *testing.T) {
			encodedData, err := s.Encrypt([]byte(plainText))
			if err != nil {
				t.Fatal(err)
			}

			if plainText == "" && hex.DecodedLen(len(encodedData)) >= legacyCBCMinimumDataBinarySize() {
				t.Errorf("the smallest ciphertext is %d binary bytes, at or above the legacy minimum of %d, so this no longer exercises a below-minimum ciphertext", hex.DecodedLen(len(encodedData)), legacyCBCMinimumDataBinarySize())
			}

			result, err := s.Decrypt(encodedData)
			if err != nil {
				t.Fatal(err)
			}

			if string(result) != plainText {
				t.Errorf("\n[EXPECTED]: %q\n[GOT]: %q", plainText, string(result))
			}
		})
	}
}

func TestAesEncoderRejectsEveryBitFlip(t *testing.T) {
	s, err := NewAesEncoder(AesSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	encodedData, err := s.Encrypt([]byte("postgres://user:hunter2@db:5432/app"))
	if err != nil {
		t.Fatal(err)
	}

	original, err := hexToBinary(encodedData)
	if err != nil {
		t.Fatal(err)
	}

	for bytePos := 0; bytePos < len(original); bytePos++ {
		for bit := 0; bit < 8; bit++ {
			tampered := make([]byte, len(original))
			copy(tampered, original)
			tampered[bytePos] ^= 1 << bit

			tamperedHex := make([]byte, hex.EncodedLen(len(tampered)))
			hex.Encode(tamperedHex, tampered)

			// Flips inside the version prefix produce an unsupported-version error rather
			// than an authentication failure, so any error is an acceptable rejection.
			if _, err := s.Decrypt(tamperedHex); err == nil {
				t.Fatalf("tampered ciphertext accepted: byte %d bit %d", bytePos, bit)
			}
		}
	}
}

// Because no container sits on the legacy grid, rewriting the version prefix is now
// rejected for every plaintext length rather than only for most of them.
//
// The rejection must come from the size or block check, never from unpad: reaching unpad
// would mean the blob was decrypted with an unauthenticated key stream first, and whether
// that lands on valid padding is a matter of chance. Asserting only that some error came
// back would accept that outcome roughly 995 times out of 1000 and hide the regression.
func TestAesEncoderRejectsVersionDowngrade(t *testing.T) {
	s, err := NewAesEncoder(AesSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	for dataSize := 0; dataSize <= 200; dataSize++ {
		plainText := bytes.Repeat([]byte("s"), dataSize)

		encodedData, err := s.Encrypt(plainText)
		if err != nil {
			t.Fatal(err)
		}

		raw, err := hexToBinary(encodedData)
		if err != nil {
			t.Fatal(err)
		}

		binary.LittleEndian.PutUint16(raw[:formatVersionSize], formatVersionLegacyCBC)

		downgraded := make([]byte, hex.EncodedLen(len(raw)))
		hex.Encode(downgraded, raw)

		_, err = s.Decrypt(downgraded)
		if err == nil {
			t.Fatalf("a version-downgraded ciphertext of a %d-byte plaintext was accepted", dataSize)
		}

		if !errors.Is(err, errMinimumDataLength) && !errors.Is(err, errBlockSizeMultiple) {
			t.Fatalf("a version-downgraded ciphertext of a %d-byte plaintext reached the legacy key stream instead of failing on shape: %v", dataSize, err)
		}
	}
}

func TestAesEncoderRejectsNonCanonicalFiller(t *testing.T) {
	s, err := NewAesEncoder(AesSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		sealed []byte
	}{
		{name: "missing required filler", sealed: []byte("abc\x00")},
		{name: "missing required filler at the next legacy layout", sealed: append(bytes.Repeat([]byte("a"), 19), 0)},
		{name: "nonzero filler", sealed: []byte("abc\xff\x01")},
		{name: "unnecessary zero filler", sealed: []byte("abcd\x00\x01")},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := s.Decrypt(aesGCMEncoded(t, s, test.sealed))
			if !errors.Is(err, errAuthenticationFailed) {
				t.Fatalf("expected an authentication failure, got: %v", err)
			}
		})
	}
}

func aesGCMEncoded(t *testing.T, s *AesEncoder, sealed []byte) []byte {
	t.Helper()

	gcm, err := cipher.NewGCM(s.CipherBlock)
	if err != nil {
		t.Fatal(err)
	}

	raw := make([]byte, formatVersionSize+gcm.NonceSize())
	binary.LittleEndian.PutUint16(raw[:formatVersionSize], formatVersionAesGCM)

	nonce := raw[formatVersionSize:]
	for i := range nonce {
		nonce[i] = byte(i)
	}

	raw = gcm.Seal(raw, nonce, sealed, raw[:formatVersionSize])

	encoded := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(encoded, raw)

	return encoded
}

func TestAesEncoderRejectsWrongKey(t *testing.T) {
	s, err := NewAesEncoder(AesSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	other, err := NewAesEncoder([]byte("bc3458408a5687e60b9417adb84e4ad0"))
	if err != nil {
		t.Fatal(err)
	}

	encodedData, err := s.Encrypt([]byte("value"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = other.Decrypt(encodedData)
	if !errors.Is(err, errAuthenticationFailed) {
		t.Errorf("expected an authentication failure, got: %v", err)
	}

	if IsExtractDataError(err) {
		t.Error("an authentication failure must not be reported as a data error, so callers keep advising to check the encryption key")
	}
}

func TestAesEncoderRejectsUnsupportedFormatVersion(t *testing.T) {
	s, err := NewAesEncoder(AesSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	encodedData, err := s.Encrypt([]byte("value"))
	if err != nil {
		t.Fatal(err)
	}

	unsupported := append([]byte("0400"), encodedData[4:]...)

	_, err = s.Decrypt(unsupported)
	if !errors.Is(err, errUnsupportedFormatVersion) {
		t.Fatalf("expected an unsupported version error, got: %v", err)
	}

	if !strings.Contains(err.Error(), "4") {
		t.Errorf("expected the rejected version in the message, got: %v", err)
	}

	if !IsExtractDataError(err) {
		t.Error("an unsupported format version is a data error")
	}
}

func TestAesEncoderDecryptWithFormatReportsVersion(t *testing.T) {
	s, err := NewAesEncoder(legacyFixtureKey)
	if err != nil {
		t.Fatal(err)
	}

	_, version, err := s.decryptWithFormat(legacyFixtureSecretFile)
	if err != nil {
		t.Fatal(err)
	}

	if version != formatVersionLegacyCBC {
		t.Errorf("\n[EXPECTED]: %d\n[GOT]: %d", formatVersionLegacyCBC, version)
	}

	encodedData, err := s.Encrypt([]byte("value"))
	if err != nil {
		t.Fatal(err)
	}

	_, version, err = s.decryptWithFormat(encodedData)
	if err != nil {
		t.Fatal(err)
	}

	if version != formatVersionAesGCM {
		t.Errorf("\n[EXPECTED]: %d\n[GOT]: %d", formatVersionAesGCM, version)
	}
}

func TestUnpad(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expected    string
		expectError bool
	}{
		{
			name:     "valid single byte of padding",
			data:     append(bytes.Repeat([]byte("a"), aes.BlockSize-1), 0x01),
			expected: strings.Repeat("a", aes.BlockSize-1),
		},
		{
			name:     "valid full block of padding",
			data:     bytes.Repeat([]byte{byte(aes.BlockSize)}, aes.BlockSize),
			expected: "",
		},
		{
			name:        "zero padding length",
			data:        append(bytes.Repeat([]byte("a"), aes.BlockSize-1), 0x00),
			expectError: true,
		},
		{
			name:        "padding length above the block size",
			data:        append(bytes.Repeat([]byte("a"), 2*aes.BlockSize-1), byte(aes.BlockSize+1)),
			expectError: true,
		},
		{
			name:        "padding length above the data length",
			data:        append(bytes.Repeat([]byte("a"), 3), 0x08),
			expectError: true,
		},
		{
			name:        "inconsistent padding bytes",
			data:        append(bytes.Repeat([]byte("a"), aes.BlockSize-4), 0x04, 0xff, 0x04, 0x04),
			expectError: true,
		},
		{
			name:        "empty data",
			data:        []byte{},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := unpad(test.data)

			if test.expectError {
				if !errors.Is(err, errUnpadFailed) {
					t.Errorf("expected an unpad failure, got: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if string(result) != test.expected {
				t.Errorf("\n[EXPECTED]: %q\n[GOT]: %q", test.expected, string(result))
			}
		})
	}
}

func TestIsExtractDataError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "minimum data length",
			err:      minimumDataLengthError(legacyCBCMinimumDataBinarySize()),
			expected: true,
		},
		{
			name:     "odd length hex string",
			err:      fmt.Errorf("wrapped: %w", hex.ErrLength),
			expected: true,
		},
		{
			name:     "unsupported format version",
			err:      fmt.Errorf("%w: %d", errUnsupportedFormatVersion, 3),
			expected: true,
		},
		{
			name:     "authentication failure",
			err:      errAuthenticationFailed,
			expected: false,
		},
		{
			name:     "unpad failure",
			err:      errUnpadFailed,
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsExtractDataError(test.err); got != test.expected {
				t.Errorf("\n[EXPECTED]: %v\n[GOT]: %v", test.expected, got)
			}
		})
	}
}
