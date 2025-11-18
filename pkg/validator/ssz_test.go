package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSZDepositMessage_HashTreeRoot(t *testing.T) {
	tests := []struct {
		name   string
		pubkey [48]byte
		amount uint64
	}{
		{
			name:   "standard deposit",
			amount: DepositAmount,
		},
		{
			name:   "partial deposit",
			amount: 16000000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pubkey [48]byte
			for i := range pubkey {
				pubkey[i] = byte(i)
			}

			var withdrawalCreds [32]byte
			for i := range withdrawalCreds {
				withdrawalCreds[i] = byte(255 - i)
			}

			msg := SSZDepositMessage{
				Pubkey:                pubkey,
				WithdrawalCredentials: withdrawalCreds,
				Amount:                tt.amount,
			}

			root, err := msg.HashTreeRoot()
			require.NoError(t, err)
			assert.Equal(t, 32, len(root), "root should be 32 bytes")

			// Should be deterministic
			root2, err := msg.HashTreeRoot()
			require.NoError(t, err)
			assert.Equal(t, root, root2, "hash tree root should be deterministic")
		})
	}
}

func TestSSZDepositData_HashTreeRoot(t *testing.T) {
	var pubkey [48]byte
	var withdrawalCreds [32]byte
	var signature [96]byte

	for i := range pubkey {
		pubkey[i] = byte(i)
	}
	for i := range withdrawalCreds {
		withdrawalCreds[i] = byte(255 - i)
	}
	for i := range signature {
		signature[i] = byte(i % 256)
	}

	data := SSZDepositData{
		Pubkey:                pubkey,
		WithdrawalCredentials: withdrawalCreds,
		Amount:                DepositAmount,
		Signature:             signature,
	}

	root, err := data.HashTreeRoot()
	require.NoError(t, err)
	assert.Equal(t, 32, len(root), "root should be 32 bytes")

	// Should be deterministic
	root2, err := data.HashTreeRoot()
	require.NoError(t, err)
	assert.Equal(t, root, root2, "hash tree root should be deterministic")
}

func TestComputeDepositDomain(t *testing.T) {
	tests := []struct {
		name        string
		forkVersion []byte
	}{
		{
			name:        "genesis fork version",
			forkVersion: []byte{0x00, 0x00, 0x00, 0x01},
		},
		{
			name:        "custom fork version",
			forkVersion: []byte{0x01, 0x00, 0x00, 0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain := ComputeDepositDomain(tt.forkVersion)

			assert.Equal(t, 32, len(domain), "domain should be 32 bytes")
			// First 4 bytes should be deposit domain type
			assert.Equal(t, byte(0x03), domain[0], "first byte should be 0x03")
			assert.Equal(t, byte(0x00), domain[1])
			assert.Equal(t, byte(0x00), domain[2])
			assert.Equal(t, byte(0x00), domain[3])
		})
	}
}

func TestComputeSigningRoot(t *testing.T) {
	tests := []struct {
		name               string
		depositMessageRoot []byte
		domain             []byte
		expectError        bool
	}{
		{
			name:               "valid inputs",
			depositMessageRoot: make([]byte, 32),
			domain:             make([]byte, 32),
			expectError:        false,
		},
		{
			name:               "invalid deposit message root length",
			depositMessageRoot: make([]byte, 16),
			domain:             make([]byte, 32),
			expectError:        true,
		},
		{
			name:               "invalid domain length",
			depositMessageRoot: make([]byte, 32),
			domain:             make([]byte, 16),
			expectError:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, err := ComputeSigningRoot(tt.depositMessageRoot, tt.domain)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, 32, len(root), "signing root should be 32 bytes")

			// Should be deterministic
			root2, err := ComputeSigningRoot(tt.depositMessageRoot, tt.domain)
			require.NoError(t, err)
			assert.Equal(t, root, root2, "signing root should be deterministic")
		})
	}
}
