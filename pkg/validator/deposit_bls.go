package validator

import (
	"encoding/hex"
	"fmt"
)

// BLSDepositGenerator handles deposit generation with proper BLS signatures
type BLSDepositGenerator struct {
	forkVersion []byte
	networkName string
	credType    WithdrawalCredentialsType
}

// NewBLSDepositGenerator creates a new BLS deposit generator
func NewBLSDepositGenerator(forkVersion, networkName string, credType WithdrawalCredentialsType) (*BLSDepositGenerator, error) {
	if forkVersion == "" {
		forkVersion = GenesisForkVersion
	}
	if networkName == "" {
		networkName = "devnet"
	}

	// Decode fork version
	// Validate and remove 0x prefix
	if len(forkVersion) < 2 {
		return nil, fmt.Errorf("invalid fork version: too short")
	}
	forkVersionHex := forkVersion
	if forkVersion[:2] == "0x" {
		forkVersionHex = forkVersion[2:]
	}
	forkBytes, err := hex.DecodeString(forkVersionHex)
	if err != nil {
		return nil, fmt.Errorf("invalid fork version: %w", err)
	}

	return &BLSDepositGenerator{
		forkVersion: forkBytes,
		networkName: networkName,
		credType:    credType,
	}, nil
}

// GenerateDepositData generates deposit data with proper BLS signature
func (g *BLSDepositGenerator) GenerateDepositData(keys *BLSValidatorKeys) (*DepositData, error) {
	// Get public key bytes
	pubkeyBytes := keys.GetValidatorPubKeyBytes()
	withdrawalPubKeyBytes := keys.GetWithdrawalPubKeyBytes()

	// Generate withdrawal credentials
	withdrawalCreds := GenerateWithdrawalCredentials(withdrawalPubKeyBytes, g.credType)
	withdrawalCredsBytes, err := hex.DecodeString(withdrawalCreds[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode withdrawal credentials: %w", err)
	}

	// Create deposit message
	var pubkey48 [48]byte
	copy(pubkey48[:], pubkeyBytes)

	var withdrawalCreds32 [32]byte
	copy(withdrawalCreds32[:], withdrawalCredsBytes)

	depositMessage := SSZDepositMessage{
		Pubkey:                pubkey48,
		WithdrawalCredentials: withdrawalCreds32,
		Amount:                DepositAmount,
	}

	// Compute deposit message root
	depositMessageRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute deposit message root: %w", err)
	}

	// Compute domain
	domain := ComputeDepositDomain(g.forkVersion)

	// Sign with BLS
	signatureBytes, err := keys.SignDepositData(depositMessageRoot[:], domain)
	if err != nil {
		return nil, fmt.Errorf("failed to sign deposit: %w", err)
	}

	// Create full deposit data for hash tree root
	var signature96 [96]byte
	copy(signature96[:], signatureBytes)

	depositData := SSZDepositData{
		Pubkey:                pubkey48,
		WithdrawalCredentials: withdrawalCreds32,
		Amount:                DepositAmount,
		Signature:             signature96,
	}

	// Compute deposit data root
	depositDataRoot, err := depositData.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute deposit data root: %w", err)
	}

	return &DepositData{
		Pubkey:                "0x" + hex.EncodeToString(pubkeyBytes),
		WithdrawalCredentials: withdrawalCreds,
		Amount:                DepositAmount,
		Signature:             "0x" + hex.EncodeToString(signatureBytes),
		DepositMessageRoot:    "0x" + hex.EncodeToString(depositMessageRoot[:]),
		DepositDataRoot:       "0x" + hex.EncodeToString(depositDataRoot[:]),
		ForkVersion:           "0x" + hex.EncodeToString(g.forkVersion),
		NetworkName:           g.networkName,
		DepositCliVersion:     "2.0.0",
	}, nil
}

// GenerateDepositDataList generates deposit data for multiple validators using BLS
func (g *BLSDepositGenerator) GenerateDepositDataList(mnemonic string, startIndex, count uint64) (DepositDataList, error) {
	var depositList DepositDataList

	for i := uint64(0); i < count; i++ {
		validatorIndex := startIndex + i

		// Generate BLS keys
		keys, err := GenerateBLSValidatorKeys(mnemonic, validatorIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to generate BLS keys for validator %d: %w", validatorIndex, err)
		}

		// Generate deposit data
		deposit, err := g.GenerateDepositData(keys)
		if err != nil {
			return nil, fmt.Errorf("failed to generate deposit data for validator %d: %w", validatorIndex, err)
		}

		depositList = append(depositList, *deposit)
	}

	return depositList, nil
}
