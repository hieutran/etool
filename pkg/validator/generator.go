package validator

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
)

const (
	// EIP-2334 path template: m/12381/3600/{validator_index}/0/0
	ValidatorPathTemplate = "m/12381/3600/%d/0/0"
	// Withdrawal path template: m/12381/3600/{validator_index}/0
	WithdrawalPathTemplate = "m/12381/3600/%d/0"
)

// Generator handles validator key generation
type Generator struct {
	mnemonic string
	seed     []byte
}

// NewGenerator creates a new validator generator
func NewGenerator(mnemonic string) (*Generator, error) {
	if err := ValidateMnemonic(mnemonic); err != nil {
		return nil, err
	}

	seed, err := MnemonicToSeed(mnemonic)
	if err != nil {
		return nil, err
	}

	return &Generator{
		mnemonic: mnemonic,
		seed:     seed,
	}, nil
}

// GenerateKeys generates validator keys for a specific index
// This is a simplified implementation - production code should use proper BLS12-381 libraries
func (g *Generator) GenerateKeys(validatorIndex uint64) (*ValidatorKeys, error) {
	// Derive validator signing key (simplified - should use proper BLS derivation)
	validatorPath := fmt.Sprintf(ValidatorPathTemplate, validatorIndex)
	validatorKey, err := g.deriveKey(validatorPath)
	if err != nil {
		return nil, fmt.Errorf("failed to derive validator key: %w", err)
	}

	// Derive withdrawal key (simplified - should use proper BLS derivation)
	withdrawalPath := fmt.Sprintf(WithdrawalPathTemplate, validatorIndex)
	withdrawalKey, err := g.deriveKey(withdrawalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to derive withdrawal key: %w", err)
	}

	// Generate public keys (simplified - should use proper BLS)
	validatorPubKey := g.derivePubKey(validatorKey)
	withdrawalPubKey := g.derivePubKey(withdrawalKey)

	return &ValidatorKeys{
		ValidatorIndex:       validatorIndex,
		PrivateKey:           validatorKey,
		PublicKey:            validatorPubKey,
		WithdrawalPrivateKey: withdrawalKey,
		WithdrawalPublicKey:  withdrawalPubKey,
		Path:                 validatorPath,
	}, nil
}

// deriveKey derives a key using HKDF (simplified version)
// Production code should use proper BLS12-381 key derivation (EIP-2333)
func (g *Generator) deriveKey(path string) ([]byte, error) {
	// Use HKDF to derive key material
	hash := sha256.New
	hkdfReader := hkdf.New(hash, g.seed, nil, []byte(path))

	// Read more bytes than needed for better entropy
	keyMaterial := make([]byte, 48)
	if _, err := hkdfReader.Read(keyMaterial); err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Take SHA256 hash to get 32 bytes and reduce likelihood of invalid keys
	// This is a workaround - proper EIP-2333 uses IKM_to_lamport_SK and mod_r
	hasher := sha256.New()
	hasher.Write(keyMaterial)
	hasher.Write([]byte(path)) // Add path for additional entropy
	key := hasher.Sum(nil)

	// Simple validation - ensure not all zeros
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		// Try again with different salt
		hasher.Reset()
		hasher.Write(keyMaterial)
		hasher.Write([]byte(path))
		hasher.Write([]byte{1}) // Add salt
		key = hasher.Sum(nil)
	}

	return key, nil
}

// derivePubKey derives a public key from a private key (simplified)
// Production code should use proper BLS12-381 operations
func (g *Generator) derivePubKey(privateKey []byte) []byte {
	// This is a placeholder - real BLS public key derivation is much more complex
	hash := sha256.Sum256(append(privateKey, []byte("pubkey")...))
	pubKey := make([]byte, 48) // BLS public keys are 48 bytes
	copy(pubKey, hash[:])
	return pubKey
}

// KeystoreWithPassword holds a keystore and its password
type KeystoreWithPassword struct {
	Keystore *Keystore
	Password string
	Pubkey   string
}

// GenerateKeystoresInMemory generates keystores for a range of validators without saving to disk
func (g *Generator) GenerateKeystoresInMemory(startIndex, count uint64, passwordFunc func() (string, error)) ([]*KeystoreWithPassword, error) {
	if passwordFunc == nil {
		passwordFunc = GeneratePassword
	}

	var keystores []*KeystoreWithPassword

	for i := uint64(0); i < count; i++ {
		validatorIndex := startIndex + i

		// Generate keys
		keys, err := g.GenerateKeys(validatorIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to generate keys for validator %d: %w", validatorIndex, err)
		}

		// Generate password
		password, err := passwordFunc()
		if err != nil {
			return nil, fmt.Errorf("failed to generate password for validator %d: %w", validatorIndex, err)
		}

		// Create encrypted keystore using proper EIP-2335 encryption
		keystore, err := CreateEncryptedKeystore(keys.PrivateKey, password, validatorIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to create encrypted keystore for validator %d: %w", validatorIndex, err)
		}

		pubkeyHex := hex.EncodeToString(keys.PublicKey)

		keystores = append(keystores, &KeystoreWithPassword{
			Keystore: keystore,
			Password: password,
			Pubkey:   pubkeyHex,
		})
	}

	return keystores, nil
}

// SaveKeystoresToDirectory saves keystores and passwords to a directory
func SaveKeystoresToDirectory(keystores []*KeystoreWithPassword, outputDir string) ([]string, error) {
	var keystorePaths []string

	for i, ks := range keystores {
		// Save keystore
		keystoreFile := filepath.Join(outputDir, CreateKeystoreFileName(ks.Pubkey))
		if err := SaveKeystore(ks.Keystore, keystoreFile); err != nil {
			return nil, fmt.Errorf("failed to save keystore %d: %w", i, err)
		}

		// Save password
		passwordFile := filepath.Join(outputDir, CreatePasswordFileName(ks.Pubkey))
		if err := SavePassword(ks.Password, passwordFile); err != nil {
			return nil, fmt.Errorf("failed to save password %d: %w", i, err)
		}

		keystorePaths = append(keystorePaths, keystoreFile)
	}

	return keystorePaths, nil
}

// GenerateKeystores generates keystores for a range of validators and saves them to disk
// This is a convenience method that combines GenerateKeystoresInMemory() and SaveKeystoresToDirectory()
func (g *Generator) GenerateKeystores(startIndex, count uint64, outputDir string, passwordFunc func() (string, error)) ([]string, error) {
	// Generate keystores in memory
	keystores, err := g.GenerateKeystoresInMemory(startIndex, count, passwordFunc)
	if err != nil {
		return nil, err
	}

	// Save to directory
	return SaveKeystoresToDirectory(keystores, outputDir)
}

// GetMnemonic returns the mnemonic used by this generator
func (g *Generator) GetMnemonic() string {
	return g.mnemonic
}

// Helper function to convert uint64 to bytes
func uint64ToBytes(value uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, value)
	return b
}
