package validator

import (
	"strings"
	"testing"
)

func TestGenerateMnemonic(t *testing.T) {
	mnemonic, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("Failed to generate mnemonic: %v", err)
	}

	if mnemonic == "" {
		t.Fatal("Generated mnemonic is empty")
	}

	// Check word count (should be 24 words for 256 bits)
	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		t.Errorf("Expected 24 words, got %d", len(words))
	}

	// Validate the generated mnemonic
	if err := ValidateMnemonic(mnemonic); err != nil {
		t.Errorf("Generated mnemonic failed validation: %v", err)
	}
}

func TestValidateMnemonic(t *testing.T) {
	validMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	if err := ValidateMnemonic(validMnemonic); err != nil {
		t.Errorf("Valid mnemonic failed validation: %v", err)
	}

	invalidMnemonic := "invalid mnemonic phrase"
	if err := ValidateMnemonic(invalidMnemonic); err == nil {
		t.Error("Invalid mnemonic passed validation")
	}
}

func TestMnemonicToSeed(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	seed, err := MnemonicToSeed(mnemonic)
	if err != nil {
		t.Fatalf("Failed to convert mnemonic to seed: %v", err)
	}

	if len(seed) == 0 {
		t.Error("Seed is empty")
	}

	// BIP39 seeds should be 64 bytes
	if len(seed) != 64 {
		t.Errorf("Expected seed length 64, got %d", len(seed))
	}
}
