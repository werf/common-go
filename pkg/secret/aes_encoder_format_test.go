package secret

import (
	"bytes"
	"crypto/aes"
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

			if binarySize := hex.DecodedLen(len(encodedData)); binarySize >= legacyCBCMinimumDataBinarySize() {
				t.Errorf("ciphertext is %d binary bytes, at or above the legacy minimum of %d, so this no longer exercises a below-minimum ciphertext", binarySize, legacyCBCMinimumDataBinarySize())
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

// A version-2 container whose plaintext length is 4 modulo 16 also satisfies the legacy
// block layout, so a rewritten prefix reaches the CBC reader instead of being rejected on
// shape alone. That reader cannot authenticate, so a small fraction of attempts is
// accepted. What must hold is that such an attempt never yields the protected plaintext:
// the attacker has no key, so anything accepted is unpredictable garbage.
func TestAesEncoderDowngradeNeverRevealsPlaintext(t *testing.T) {
	s, err := NewAesEncoder(AesSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	plainText := []byte("s3cr")
	if len(plainText)%aes.BlockSize != 4 {
		t.Fatalf("this test needs a plaintext length of 4 modulo 16 to reach the legacy reader, got %d", len(plainText))
	}

	const trials = 2000
	accepted := 0

	for i := 0; i < trials; i++ {
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

		result, err := s.Decrypt(downgraded)
		if err != nil {
			continue
		}

		accepted++
		if bytes.Equal(result, plainText) {
			t.Fatal("a downgraded ciphertext revealed the protected plaintext")
		}
	}

	// The expected rate is well under 1%; this only guards against the legacy reader
	// turning permissive, not against the inherent gap itself.
	if accepted*100 > trials*5 {
		t.Errorf("legacy reader accepted %d of %d downgraded ciphertexts, far above the expected rate", accepted, trials)
	}
}

// Rewriting the version prefix of a version-2 ciphertext to the legacy one routes it to
// the CBC reader, which does not authenticate. For every plaintext length that does not
// suit the legacy block layout the rewrite is rejected outright, deterministically.
func TestAesEncoderRejectsVersionDowngrade(t *testing.T) {
	s, err := NewAesEncoder(AesSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, plainText := range []string{"a", "ab", "abc", "abcde", "value", "a longer secret value"} {
		t.Run(plainText, func(t *testing.T) {
			encodedData, err := s.Encrypt([]byte(plainText))
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

			if _, err := s.Decrypt(downgraded); err == nil {
				t.Error("a version-downgraded ciphertext was accepted")
			}
		})
	}
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

	unsupported := append([]byte("0300"), encodedData[4:]...)

	_, err = s.Decrypt(unsupported)
	if !errors.Is(err, errUnsupportedFormatVersion) {
		t.Fatalf("expected an unsupported version error, got: %v", err)
	}

	if !strings.Contains(err.Error(), "3") {
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
