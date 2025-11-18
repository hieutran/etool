package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBLSKeyDerivation(t *testing.T) {
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
			mnemonic:    "invalid mnemonic",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kd, err := NewBLSKeyDerivation(tt.mnemonic)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, kd)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, kd)
			assert.Equal(t, tt.mnemonic, kd.mnemonic)
			assert.NotEmpty(t, kd.seed)
		})
	}
}

func TestGenerateBLSValidatorKeys(t *testing.T) {
	tests := []struct {
		name           string
		validatorIndex uint64
	}{
		{
			name:           "validator 0",
			validatorIndex: 0,
		},
		{
			name:           "validator 1",
			validatorIndex: 1,
		},
		{
			name:           "validator 100",
			validatorIndex: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := GenerateBLSValidatorKeys(testMnemonic, tt.validatorIndex)

			require.NoError(t, err)
			assert.NotNil(t, keys)
			assert.Equal(t, tt.validatorIndex, keys.ValidatorIndex)
			assert.NotNil(t, keys.ValidatorPrivateKey)
			assert.NotNil(t, keys.ValidatorPublicKey)
			assert.NotNil(t, keys.WithdrawalPrivateKey)
			assert.NotNil(t, keys.WithdrawalPublicKey)
			assert.NotEmpty(t, keys.Path)

			// Check public key bytes are correct length (48 bytes compressed BLS)
			valPubBytes := keys.GetValidatorPubKeyBytes()
			assert.Equal(t, 48, len(valPubBytes), "validator public key should be 48 bytes")

			withdrawalPubBytes := keys.GetWithdrawalPubKeyBytes()
			assert.Equal(t, 48, len(withdrawalPubBytes), "withdrawal public key should be 48 bytes")
		})
	}
}

func TestBLSValidatorKeys_Deterministic(t *testing.T) {
	t.Run("same mnemonic produces same keys", func(t *testing.T) {
		keys1, err := GenerateBLSValidatorKeys(testMnemonic, 0)
		require.NoError(t, err)

		keys2, err := GenerateBLSValidatorKeys(testMnemonic, 0)
		require.NoError(t, err)

		// Public keys should be identical
		assert.Equal(t, keys1.GetValidatorPubKeyBytes(), keys2.GetValidatorPubKeyBytes())
		assert.Equal(t, keys1.GetWithdrawalPubKeyBytes(), keys2.GetWithdrawalPubKeyBytes())
	})
}

func TestBLSValidatorKeys_DifferentIndices(t *testing.T) {
	keys0, err := GenerateBLSValidatorKeys(testMnemonic, 0)
	require.NoError(t, err)

	keys1, err := GenerateBLSValidatorKeys(testMnemonic, 1)
	require.NoError(t, err)

	// Keys should be different for different indices
	assert.NotEqual(t, keys0.GetValidatorPubKeyBytes(), keys1.GetValidatorPubKeyBytes())
	assert.NotEqual(t, keys0.GetWithdrawalPubKeyBytes(), keys1.GetWithdrawalPubKeyBytes())
}

func TestBLSValidatorKeys_SignDepositData(t *testing.T) {
	keys, err := GenerateBLSValidatorKeys(testMnemonic, 0)
	require.NoError(t, err)

	depositMessageRoot := make([]byte, 32)
	for i := range depositMessageRoot {
		depositMessageRoot[i] = byte(i)
	}

	domain := make([]byte, 32)
	for i := range domain {
		domain[i] = byte(255 - i)
	}

	signature, err := keys.SignDepositData(depositMessageRoot, domain)
	require.NoError(t, err)
	assert.NotNil(t, signature)
	assert.Equal(t, 96, len(signature), "BLS signature should be 96 bytes")

	// Signing same data should produce same signature (deterministic)
	signature2, err := keys.SignDepositData(depositMessageRoot, domain)
	require.NoError(t, err)
	assert.Equal(t, signature, signature2, "signatures should be deterministic")
}
