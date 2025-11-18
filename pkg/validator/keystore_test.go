package validator

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePassword(t *testing.T) {
	tests := []struct {
		name       string
		iterations int
	}{
		{
			name:       "generate unique passwords",
			iterations: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			passwords := make(map[string]bool)

			for i := 0; i < tt.iterations; i++ {
				password, err := GeneratePassword()

				require.NoError(t, err, "should generate password without error")
				assert.NotEmpty(t, password, "password should not be empty")
				assert.Equal(t, 64, len(password), "password should be 64 hex characters (32 bytes)")

				// Ensure uniqueness
				assert.False(t, passwords[password], "passwords should be unique")
				passwords[password] = true
			}
		})
	}
}

func TestCreateKeystoreFileName(t *testing.T) {
	tests := []struct {
		name     string
		pubkey   string
		expected string
	}{
		{
			name:     "standard pubkey",
			pubkey:   "0x1234567890abcdef",
			expected: "keystore-0x1234567890.json",
		},
		{
			name:     "long pubkey",
			pubkey:   "0x1234567890abcdef1234567890abcdef1234567890abcdef",
			expected: "keystore-0x1234567890.json",
		},
		{
			name:     "short pubkey",
			pubkey:   "0x1234",
			expected: "keystore-0x1234.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename := CreateKeystoreFileName(tt.pubkey)
			assert.Equal(t, tt.expected, filename, "filename should match expected format")
		})
	}
}

func TestCreatePasswordFileName(t *testing.T) {
	tests := []struct {
		name     string
		pubkey   string
		expected string
	}{
		{
			name:     "standard pubkey",
			pubkey:   "0x1234567890abcdef",
			expected: "keystore-0x1234567890.txt",
		},
		{
			name:     "long pubkey",
			pubkey:   "0x1234567890abcdef1234567890abcdef1234567890abcdef",
			expected: "keystore-0x1234567890.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename := CreatePasswordFileName(tt.pubkey)
			assert.Equal(t, tt.expected, filename, "filename should match expected format")
		})
	}
}

func TestNewUUID(t *testing.T) {
	tests := []struct {
		name       string
		iterations int
	}{
		{
			name:       "generate unique UUIDs",
			iterations: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uuids := make(map[string]bool)

			for i := 0; i < tt.iterations; i++ {
				uuid := NewUUID()

				assert.NotEmpty(t, uuid, "UUID should not be empty")
				assert.Equal(t, 36, len(uuid), "UUID should be 36 characters (standard format)")

				// Check for dashes in correct positions
				assert.Equal(t, "-", string(uuid[8]), "should have dash at position 8")
				assert.Equal(t, "-", string(uuid[13]), "should have dash at position 13")
				assert.Equal(t, "-", string(uuid[18]), "should have dash at position 18")
				assert.Equal(t, "-", string(uuid[23]), "should have dash at position 23")

				// Ensure uniqueness
				assert.False(t, uuids[uuid], "UUIDs should be unique")
				uuids[uuid] = true
			}
		})
	}
}

func TestCreateEncryptedKeystore(t *testing.T) {
	// Generate a valid BLS private key for testing
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	kd, err := NewBLSKeyDerivation(mnemonic)
	require.NoError(t, err)

	validatorKey, err := kd.DeriveValidatorKey(0)
	require.NoError(t, err)
	validPrivateKey := validatorKey.Marshal()

	tests := []struct {
		name           string
		privateKey     []byte
		password       string
		validatorIndex uint64
		wantErr        bool
		errMsg         string
	}{
		{
			name:           "valid 32-byte private key",
			privateKey:     validPrivateKey,
			password:       "test-password-123",
			validatorIndex: 0,
			wantErr:        false,
		},
		{
			name:           "invalid private key length",
			privateKey:     make([]byte, 16),
			password:       "test-password-123",
			validatorIndex: 0,
			wantErr:        true,
			errMsg:         "invalid private key length",
		},
		{
			name:           "empty password",
			privateKey:     validPrivateKey,
			password:       "",
			validatorIndex: 0,
			wantErr:        true,
			errMsg:         "password cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keystore, err := CreateEncryptedKeystore(tt.privateKey, tt.password, tt.validatorIndex)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, keystore)

			// Verify keystore structure
			assert.Equal(t, uint(4), keystore.Version, "version should be 4")
			assert.NotEmpty(t, keystore.UUID, "UUID should not be empty")
			assert.NotEmpty(t, keystore.Pubkey, "public key should not be empty")
			assert.Equal(t, 96, len(keystore.Pubkey), "public key should be 48 bytes (96 hex chars)")

			// Verify path format
			expectedPath := "m/12381/3600/0/0/0"
			assert.Equal(t, expectedPath, keystore.Path, "path should follow EIP-2334 format")

			// Verify KDF parameters
			assert.Equal(t, "scrypt", keystore.Crypto.KDF.Function)
			assert.Equal(t, 32, keystore.Crypto.KDF.Params["dklen"])
			assert.Equal(t, 262144, keystore.Crypto.KDF.Params["n"])
			assert.Equal(t, 8, keystore.Crypto.KDF.Params["r"])
			assert.Equal(t, 1, keystore.Crypto.KDF.Params["p"])

			// Verify salt is present and random (64 hex chars = 32 bytes)
			salt, ok := keystore.Crypto.KDF.Params["salt"].(string)
			require.True(t, ok, "salt should be a string")
			assert.Equal(t, 64, len(salt), "salt should be 32 bytes (64 hex chars)")

			// Verify cipher parameters
			assert.Equal(t, "aes-128-ctr", keystore.Crypto.Cipher.Function)

			// Verify IV is present and random (32 hex chars = 16 bytes)
			iv, ok := keystore.Crypto.Cipher.Params["iv"].(string)
			require.True(t, ok, "IV should be a string")
			assert.Equal(t, 32, len(iv), "IV should be 16 bytes (32 hex chars)")

			// Verify ciphertext is present and encrypted (not equal to plaintext)
			assert.NotEmpty(t, keystore.Crypto.Cipher.Message, "ciphertext should not be empty")
			assert.NotEqual(t, hex.EncodeToString(tt.privateKey), keystore.Crypto.Cipher.Message,
				"ciphertext should not equal plaintext")

			// Verify checksum is present
			assert.Equal(t, "sha256", keystore.Crypto.Checksum.Function)
			assert.NotEmpty(t, keystore.Crypto.Checksum.Message, "checksum should not be empty")
			assert.Equal(t, 64, len(keystore.Crypto.Checksum.Message), "checksum should be 32 bytes (64 hex chars)")
		})
	}
}

func TestCreateEncryptedKeystore_Uniqueness(t *testing.T) {
	// Test that creating multiple keystores produces unique salts, IVs, and ciphertexts
	// Use a known valid mnemonic to generate a valid BLS private key
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	kd, err := NewBLSKeyDerivation(mnemonic)
	require.NoError(t, err)

	validatorKey, err := kd.DeriveValidatorKey(0)
	require.NoError(t, err)

	privateKey := validatorKey.Marshal()
	password := "test-password"

	keystores := make([]*Keystore, 3)
	for i := 0; i < 3; i++ {
		ks, err := CreateEncryptedKeystore(privateKey, password, uint64(i))
		require.NoError(t, err)
		keystores[i] = ks
	}

	// Verify all have different salts
	for i := 0; i < len(keystores); i++ {
		for j := i + 1; j < len(keystores); j++ {
			salti := keystores[i].Crypto.KDF.Params["salt"].(string)
			saltj := keystores[j].Crypto.KDF.Params["salt"].(string)
			assert.NotEqual(t, salti, saltj, "salts should be unique")

			ivi := keystores[i].Crypto.Cipher.Params["iv"].(string)
			ivj := keystores[j].Crypto.Cipher.Params["iv"].(string)
			assert.NotEqual(t, ivi, ivj, "IVs should be unique")

			cti := keystores[i].Crypto.Cipher.Message
			ctj := keystores[j].Crypto.Cipher.Message
			assert.NotEqual(t, cti, ctj, "ciphertexts should be different due to different IVs")
		}
	}
}

func TestCreateEncryptedKeystore_DifferentPasswords(t *testing.T) {
	// Test that different passwords produce different ciphertexts
	// Use a known valid mnemonic to generate a valid BLS private key
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	kd, err := NewBLSKeyDerivation(mnemonic)
	require.NoError(t, err)

	validatorKey, err := kd.DeriveValidatorKey(0)
	require.NoError(t, err)

	privateKey := validatorKey.Marshal()

	ks1, err := CreateEncryptedKeystore(privateKey, "password1", 0)
	require.NoError(t, err)

	ks2, err := CreateEncryptedKeystore(privateKey, "password2", 0)
	require.NoError(t, err)

	// Even with the same private key, different passwords should produce different results
	assert.NotEqual(t, ks1.Crypto.Cipher.Message, ks2.Crypto.Cipher.Message,
		"different passwords should produce different ciphertexts")
	assert.NotEqual(t, ks1.Crypto.Checksum.Message, ks2.Crypto.Checksum.Message,
		"different passwords should produce different checksums")
}
