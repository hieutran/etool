package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateWithdrawalCredentials(t *testing.T) {
	withdrawalPubKey := make([]byte, 48)
	for i := range withdrawalPubKey {
		withdrawalPubKey[i] = byte(i)
	}

	tests := []struct {
		name         string
		credType     WithdrawalCredentialsType
		expectedPrefix string
	}{
		{
			name:         "BLS withdrawal credentials",
			credType:     BLSWithdrawal,
			expectedPrefix: "0x00",
		},
		{
			name:         "Execution address withdrawal credentials",
			credType:     ExecutionAddressWithdrawal,
			expectedPrefix: "0x01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := GenerateWithdrawalCredentials(withdrawalPubKey, tt.credType)

			// Should start with correct prefix
			assert.Equal(t, tt.expectedPrefix, creds[:4], "should have correct prefix")

			// Should be 66 characters (0x + 64 hex chars for 32 bytes)
			assert.Equal(t, 66, len(creds), "should be correct length")

			// Should be valid hex
			assert.Regexp(t, `^0x[0-9a-f]{64}$`, creds, "should be valid hex string")
		})
	}
}

func TestComputeDepositMessageRoot(t *testing.T) {
	tests := []struct {
		name        string
		pubkeyLen   int
		amount      uint64
	}{
		{
			name:      "standard deposit",
			pubkeyLen: 48,
			amount:    DepositAmount,
		},
		{
			name:      "partial deposit",
			pubkeyLen: 48,
			amount:    16000000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubkey := make([]byte, tt.pubkeyLen)
			withdrawalCreds := "0x00" + string(make([]byte, 62))

			root := ComputeDepositMessageRoot(pubkey, withdrawalCreds, tt.amount)

			// Should start with 0x
			assert.True(t, len(root) > 2 && root[:2] == "0x", "should have 0x prefix")

			// Should be 66 characters
			assert.Equal(t, 66, len(root), "should be correct length")

			// Should be valid hex
			assert.Regexp(t, `^0x[0-9a-f]{64}$`, root, "should be valid hex string")

			// Should be deterministic
			root2 := ComputeDepositMessageRoot(pubkey, withdrawalCreds, tt.amount)
			assert.Equal(t, root, root2, "should be deterministic")
		})
	}
}

func TestComputeDepositDataRoot(t *testing.T) {
	pubkey := make([]byte, 48)
	withdrawalCreds := "0x00" + string(make([]byte, 62))
	amount := uint64(32000000000)
	signature := "0xabcdef"

	root := ComputeDepositDataRoot(pubkey, withdrawalCreds, amount, signature)

	assert.True(t, len(root) > 2 && root[:2] == "0x", "should have 0x prefix")
	assert.Equal(t, 66, len(root), "should be correct length")
	assert.Regexp(t, `^0x[0-9a-f]{64}$`, root, "should be valid hex string")
}

func TestSignDepositMessage(t *testing.T) {
	privateKey := make([]byte, 32)
	depositMessageRoot := "0x1234567890abcdef"
	forkVersion := "0x00000001"

	signature := SignDepositMessage(privateKey, depositMessageRoot, forkVersion)

	// BLS signatures are 96 bytes = 192 hex chars + 0x prefix
	assert.True(t, len(signature) > 2 && signature[:2] == "0x", "should have 0x prefix")
	assert.Regexp(t, `^0x[0-9a-f]+$`, signature, "should be valid hex string")
}

func TestNewDepositGenerator(t *testing.T) {
	tests := []struct {
		name             string
		forkVersion      string
		networkName      string
		credType         WithdrawalCredentialsType
		expectedFork     string
		expectedNetwork  string
	}{
		{
			name:            "with custom values",
			forkVersion:     "0x00000002",
			networkName:     "custom-network",
			credType:        BLSWithdrawal,
			expectedFork:    "0x00000002",
			expectedNetwork: "custom-network",
		},
		{
			name:            "with empty values (defaults)",
			forkVersion:     "",
			networkName:     "",
			credType:        ExecutionAddressWithdrawal,
			expectedFork:    GenesisForkVersion,
			expectedNetwork: "devnet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewDepositGenerator(tt.forkVersion, tt.networkName, tt.credType)

			assert.NotNil(t, gen, "generator should not be nil")
			assert.Equal(t, tt.expectedFork, gen.forkVersion, "fork version should match")
			assert.Equal(t, tt.expectedNetwork, gen.networkName, "network name should match")
			assert.Equal(t, tt.credType, gen.credType, "credential type should match")
		})
	}
}

func TestDepositGenerator_GenerateDepositData(t *testing.T) {
	tests := []struct {
		name         string
		forkVersion  string
		networkName  string
		credType     WithdrawalCredentialsType
	}{
		{
			name:        "BLS withdrawal",
			forkVersion: "0x00000001",
			networkName: "testnet",
			credType:    BLSWithdrawal,
		},
		{
			name:        "Execution address withdrawal",
			forkVersion: "0x00000001",
			networkName: "testnet",
			credType:    ExecutionAddressWithdrawal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a validator generator
			valGen, err := NewGenerator(testMnemonic)
			require.NoError(t, err)

			// Generate keys
			keys, err := valGen.GenerateKeys(0)
			require.NoError(t, err)

			// Generate deposit data
			depositGen := NewDepositGenerator(tt.forkVersion, tt.networkName, tt.credType)
			deposit, err := depositGen.GenerateDepositData(keys)

			require.NoError(t, err, "should generate deposit data without error")
			assert.NotNil(t, deposit, "deposit should not be nil")
			assert.Equal(t, DepositAmount, deposit.Amount, "amount should match")
			assert.NotEmpty(t, deposit.Pubkey, "pubkey should not be empty")
			assert.NotEmpty(t, deposit.WithdrawalCredentials, "withdrawal credentials should not be empty")
			assert.NotEmpty(t, deposit.Signature, "signature should not be empty")
			assert.NotEmpty(t, deposit.DepositMessageRoot, "deposit message root should not be empty")
			assert.NotEmpty(t, deposit.DepositDataRoot, "deposit data root should not be empty")
			assert.Equal(t, tt.networkName, deposit.NetworkName, "network name should match")
			assert.Equal(t, tt.forkVersion, deposit.ForkVersion, "fork version should match")
		})
	}
}

func TestDepositGenerator_GenerateDepositDataList(t *testing.T) {
	tests := []struct {
		name        string
		startIndex  uint64
		count       uint64
	}{
		{
			name:       "generate single deposit",
			startIndex: 0,
			count:      1,
		},
		{
			name:       "generate multiple deposits",
			startIndex: 0,
			count:      5,
		},
		{
			name:       "generate with offset",
			startIndex: 10,
			count:      3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valGen, err := NewGenerator(testMnemonic)
			require.NoError(t, err)

			depositGen := NewDepositGenerator("0x00000001", "testnet", BLSWithdrawal)
			depositList, err := depositGen.GenerateDepositDataList(valGen, tt.startIndex, tt.count)

			require.NoError(t, err, "should generate deposit list without error")
			assert.Equal(t, int(tt.count), len(depositList), "should generate correct number of deposits")

			// Verify each deposit has unique pubkey
			pubkeys := make(map[string]bool)
			for i, deposit := range depositList {
				assert.NotEmpty(t, deposit.Pubkey, "deposit %d should have pubkey", i)
				assert.False(t, pubkeys[deposit.Pubkey], "pubkeys should be unique")
				pubkeys[deposit.Pubkey] = true
				assert.Equal(t, DepositAmount, deposit.Amount, "deposit %d should have correct amount", i)
			}
		})
	}
}
