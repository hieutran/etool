package nodekey

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name            string
		iterations      int
	}{
		{
			name:       "generate valid node key",
			iterations: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewGenerator()
			generatedKeys := make(map[string]bool)

			for i := 0; i < tt.iterations; i++ {
				nodeKey, err := gen.Generate()

				require.NoError(t, err, "should generate node key without error")
				assert.NotNil(t, nodeKey.PrivateKey, "private key should not be nil")
				assert.NotEmpty(t, nodeKey.NodeID, "node ID should not be empty")
				assert.NotEmpty(t, nodeKey.PublicKey, "public key should not be empty")

				// Ensure uniqueness
				assert.False(t, generatedKeys[nodeKey.NodeID], "node IDs should be unique")
				generatedKeys[nodeKey.NodeID] = true
			}
		})
	}
}

func TestGenerateToFile(t *testing.T) {
	tests := []struct {
		name     string
		setupDir func(t *testing.T) string
	}{
		{
			name: "generate to valid directory",
			setupDir: func(t *testing.T) string {
				return t.TempDir()
			},
		},
		{
			name: "generate to nested directory",
			setupDir: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nested", "path")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outputPath := filepath.Join(tt.setupDir(t), "nodekey")

			gen := NewGenerator()
			nodeKey, err := gen.GenerateToFile(outputPath)

			require.NoError(t, err, "should generate node key to file without error")
			assert.NotNil(t, nodeKey, "should return node key")

			// Check main file exists
			_, err = os.Stat(outputPath)
			assert.NoError(t, err, "nodekey file should exist")

			// Check node ID file exists
			nodeIDPath := outputPath + ".id"
			_, err = os.Stat(nodeIDPath)
			assert.NoError(t, err, "nodekey.id file should exist")

			// Read and verify node ID
			data, err := os.ReadFile(nodeIDPath)
			require.NoError(t, err, "should read node ID file successfully")
			assert.Equal(t, nodeKey.NodeID, string(data), "node ID in file should match returned value")

			// Check file permissions
			info, err := os.Stat(outputPath)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "nodekey should have 0600 permissions")
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) string
		expectError bool
	}{
		{
			name: "load valid node key",
			setup: func(t *testing.T) string {
				tmpDir := t.TempDir()
				outputPath := filepath.Join(tmpDir, "nodekey")

				gen := NewGenerator()
				_, err := gen.GenerateToFile(outputPath)
				require.NoError(t, err)

				return outputPath
			},
			expectError: false,
		},
		{
			name: "load non-existent file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent")
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup(t)
			loadedKey, err := LoadFromFile(path)

			if tt.expectError {
				assert.Error(t, err, "should return error")
				assert.Nil(t, loadedKey, "should return nil on error")
				return
			}

			require.NoError(t, err, "should load node key without error")
			assert.NotNil(t, loadedKey, "should return node key")
			assert.NotNil(t, loadedKey.PrivateKey, "private key should not be nil")
			assert.NotEmpty(t, loadedKey.NodeID, "node ID should not be empty")
			assert.NotEmpty(t, loadedKey.PublicKey, "public key should not be empty")
		})
	}
}

func TestLoadAndCompare(t *testing.T) {
	t.Run("loaded key matches original", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputPath := filepath.Join(tmpDir, "nodekey")

		// Generate and save a key
		gen := NewGenerator()
		originalKey, err := gen.GenerateToFile(outputPath)
		require.NoError(t, err)

		// Load it back
		loadedKey, err := LoadFromFile(outputPath)
		require.NoError(t, err)

		// Compare
		assert.Equal(t, originalKey.NodeID, loadedKey.NodeID, "node IDs should match")
		assert.Equal(t, originalKey.PublicKey, loadedKey.PublicKey, "public keys should match")
	})
}

func TestNewGenerator(t *testing.T) {
	gen := NewGenerator()
	assert.NotNil(t, gen, "generator should not be nil")
}
