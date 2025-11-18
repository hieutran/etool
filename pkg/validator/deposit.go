package validator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// DepositAmount is the standard deposit amount in Gwei (32 ETH)
	DepositAmount = 32000000000

	// GenesisForkVersion is the default genesis fork version
	GenesisForkVersion = "0x00000001"
)

// DepositData represents a validator deposit
type DepositData struct {
	Pubkey                string `json:"pubkey"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	Amount                uint64 `json:"amount"`
	Signature             string `json:"signature"`
	DepositMessageRoot    string `json:"deposit_message_root"`
	DepositDataRoot       string `json:"deposit_data_root"`
	ForkVersion           string `json:"fork_version"`
	NetworkName           string `json:"network_name"`
	DepositCliVersion     string `json:"deposit_cli_version"`
}

// DepositDataList represents a list of deposit data
type DepositDataList []DepositData

// WithdrawalCredentialsType represents the type of withdrawal credentials
type WithdrawalCredentialsType int

const (
	// BLSWithdrawal uses BLS withdrawal credentials (0x00)
	BLSWithdrawal WithdrawalCredentialsType = iota
	// ExecutionAddressWithdrawal uses execution address withdrawal credentials (0x01)
	ExecutionAddressWithdrawal
)

// GenerateWithdrawalCredentials generates withdrawal credentials for a validator
func GenerateWithdrawalCredentials(withdrawalPubKey []byte, credType WithdrawalCredentialsType) string {
	credentials := make([]byte, 32)

	switch credType {
	case BLSWithdrawal:
		// BLS withdrawal: 0x00 + hash(withdrawal_pubkey)[1:]
		credentials[0] = 0x00
		hash := sha256.Sum256(withdrawalPubKey)
		copy(credentials[1:], hash[1:])

	case ExecutionAddressWithdrawal:
		// Execution address withdrawal: 0x01 + 11 zero bytes + execution_address
		credentials[0] = 0x01
		// For simplicity, derive execution address from pubkey hash
		hash := sha256.Sum256(withdrawalPubKey)
		copy(credentials[12:], hash[:20])

	default:
		// Default to BLS withdrawal for unknown types
		credentials[0] = 0x00
		hash := sha256.Sum256(withdrawalPubKey)
		copy(credentials[1:], hash[1:])
	}

	return "0x" + hex.EncodeToString(credentials)
}

// SaveDepositData saves deposit data to a JSON file
func SaveDepositData(depositList DepositDataList, outputPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(depositList, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal deposit data: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write deposit data: %w", err)
	}

	return nil
}
