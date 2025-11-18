package validator

import (
	"crypto/rand"
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// GenerateMnemonic creates a new BIP39 mnemonic with 256 bits of entropy (24 words)
func GenerateMnemonic() (string, error) {
	entropy := make([]byte, 32) // 256 bits
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("failed to generate entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to create mnemonic: %w", err)
	}

	return mnemonic, nil
}

// ValidateMnemonic checks if a mnemonic is valid
func ValidateMnemonic(mnemonic string) error {
	if !bip39.IsMnemonicValid(mnemonic) {
		return fmt.Errorf("invalid mnemonic")
	}
	return nil
}

// MnemonicToSeed converts a mnemonic to a seed
func MnemonicToSeed(mnemonic string) ([]byte, error) {
	if err := ValidateMnemonic(mnemonic); err != nil {
		return nil, err
	}
	return bip39.NewSeed(mnemonic, ""), nil
}
