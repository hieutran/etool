package jwt

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "generate valid JWT secret"},
		{name: "generate unique JWT secrets"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewGenerator()
			secret, err := gen.Generate()

			require.NoError(t, err, "should generate JWT secret without error")
			assert.Equal(t, JWTSecretLength, len(secret), "secret should be correct length")

			// Generate another to ensure uniqueness
			secret2, err := gen.Generate()
			require.NoError(t, err)
			assert.NotEqual(t, secret, secret2, "secrets should be unique")
		})
	}
}

func TestGenerateToFile(t *testing.T) {
	tests := []struct {
		name        string
		setupDir    func(t *testing.T) string
		expectError bool
	}{
		{
			name: "generate to valid directory",
			setupDir: func(t *testing.T) string {
				return t.TempDir()
			},
			expectError: false,
		},
		{
			name: "generate to nested directory",
			setupDir: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nested", "path")
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputPath := filepath.Join(tt.setupDir(t), "jwt.hex")

			gen := NewGenerator()
			err := gen.GenerateToFile(outputPath)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err, "should generate JWT to file without error")

			// Check file exists
			_, err = os.Stat(outputPath)
			assert.NoError(t, err, "file should exist")

			// Read and validate file contents
			data, err := os.ReadFile(outputPath)
			require.NoError(t, err, "should read file successfully")

			content := string(data)
			assert.True(t, strings.HasPrefix(content, "0x"), "should have 0x prefix")

			hexStr := strings.TrimPrefix(content, "0x")
			decoded, err := hex.DecodeString(hexStr)
			require.NoError(t, err, "should contain valid hex")
			assert.Equal(t, JWTSecretLength, len(decoded), "decoded secret should be correct length")

			// Check file permissions
			info, err := os.Stat(outputPath)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "should have 0600 permissions")
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		secretLen   int
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid secret length",
			secretLen:   JWTSecretLength,
			expectError: false,
		},
		{
			name:        "secret too short",
			secretLen:   16,
			expectError: true,
			errorMsg:    "invalid JWT secret length",
		},
		{
			name:        "secret too long",
			secretLen:   64,
			expectError: true,
			errorMsg:    "invalid JWT secret length",
		},
		{
			name:        "empty secret",
			secretLen:   0,
			expectError: true,
			errorMsg:    "invalid JWT secret length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := make([]byte, tt.secretLen)
			err := Validate(secret)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewGenerator(t *testing.T) {
	gen := NewGenerator()
	assert.NotNil(t, gen, "generator should not be nil")
}
