package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

func TestNewGenerator(t *testing.T) {
	tests := []struct {
		name        string
		mnemonic    string
		expectError bool
	}{
		{
			name:        "valid mnemonic",
			mnemonic:    testMnemonic,
			expectError: false,
		},
		{
			name:        "invalid mnemonic",
			mnemonic:    "invalid mnemonic phrase",
			expectError: true,
		},
		{
			name:        "empty mnemonic",
			mnemonic:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewGenerator(tt.mnemonic)

			if tt.expectError {
				assert.Error(t, err, "should return error for invalid mnemonic")
				assert.Nil(t, gen, "generator should be nil on error")
				return
			}

			require.NoError(t, err, "should create generator without error")
			assert.NotNil(t, gen, "generator should not be nil")
			assert.Equal(t, tt.mnemonic, gen.mnemonic, "mnemonic should match")
			assert.NotEmpty(t, gen.seed, "seed should not be empty")
			assert.Equal(t, 64, len(gen.seed), "seed should be 64 bytes")
		})
	}
}

func TestGenerator_GenerateKeys(t *testing.T) {
	tests := []struct {
		name           string
		validatorIndex uint64
		checkPath      string
	}{
		{
			name:           "generate keys for validator 0",
			validatorIndex: 0,
			checkPath:      "m/12381/3600/0/0/0",
		},
		{
			name:           "generate keys for validator 1",
			validatorIndex: 1,
			checkPath:      "m/12381/3600/1/0/0",
		},
		{
			name:           "generate keys for validator 100",
			validatorIndex: 100,
			checkPath:      "m/12381/3600/100/0/0",
		},
	}

	gen, err := NewGenerator(testMnemonic)
	require.NoError(t, err, "should create generator")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := gen.GenerateKeys(tt.validatorIndex)

			require.NoError(t, err, "should generate keys without error")
			assert.NotNil(t, keys, "keys should not be nil")
			assert.Equal(t, tt.validatorIndex, keys.ValidatorIndex, "validator index should match")
			assert.NotEmpty(t, keys.PrivateKey, "private key should not be empty")
			assert.NotEmpty(t, keys.PublicKey, "public key should not be empty")
			assert.NotEmpty(t, keys.WithdrawalPrivateKey, "withdrawal private key should not be empty")
			assert.NotEmpty(t, keys.WithdrawalPublicKey, "withdrawal public key should not be empty")
			assert.NotEmpty(t, keys.Path, "path should not be empty")
			assert.Equal(t, tt.checkPath, keys.Path, "path should match expected")
		})
	}
}

func TestGenerator_GenerateKeys_Deterministic(t *testing.T) {
	t.Run("same mnemonic and index produces same keys", func(t *testing.T) {
		gen1, err := NewGenerator(testMnemonic)
		require.NoError(t, err)

		gen2, err := NewGenerator(testMnemonic)
		require.NoError(t, err)

		keys1, err := gen1.GenerateKeys(0)
		require.NoError(t, err)

		keys2, err := gen2.GenerateKeys(0)
		require.NoError(t, err)

		// Keys should be identical
		assert.Equal(t, keys1.PrivateKey, keys2.PrivateKey, "private keys should match")
		assert.Equal(t, keys1.PublicKey, keys2.PublicKey, "public keys should match")
		assert.Equal(t, keys1.WithdrawalPrivateKey, keys2.WithdrawalPrivateKey, "withdrawal private keys should match")
		assert.Equal(t, keys1.WithdrawalPublicKey, keys2.WithdrawalPublicKey, "withdrawal public keys should match")
	})
}

func TestGenerator_GenerateKeys_DifferentIndices(t *testing.T) {
	gen, err := NewGenerator(testMnemonic)
	require.NoError(t, err)

	tests := []struct {
		index1 uint64
		index2 uint64
	}{
		{index1: 0, index2: 1},
		{index1: 0, index2: 100},
		{index1: 1, index2: 2},
	}

	for _, tt := range tests {
		t.Run("compare different indices", func(t *testing.T) {
			keys1, err := gen.GenerateKeys(tt.index1)
			require.NoError(t, err)

			keys2, err := gen.GenerateKeys(tt.index2)
			require.NoError(t, err)

			// Keys should be different for different indices
			assert.NotEqual(t, keys1.PrivateKey, keys2.PrivateKey, "private keys should differ")
			assert.NotEqual(t, keys1.PublicKey, keys2.PublicKey, "public keys should differ")
			assert.NotEqual(t, keys1.Path, keys2.Path, "paths should differ")
		})
	}
}

func TestGenerator_GetMnemonic(t *testing.T) {
	gen, err := NewGenerator(testMnemonic)
	require.NoError(t, err)

	assert.Equal(t, testMnemonic, gen.GetMnemonic(), "should return correct mnemonic")
}
