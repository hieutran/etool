package validator

import (
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
