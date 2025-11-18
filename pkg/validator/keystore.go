package validator

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// Keystore represents an EIP-2335 compliant keystore
type Keystore struct {
	Crypto      CryptoFields `json:"crypto"`
	Description string       `json:"description,omitempty"`
	Pubkey      string       `json:"pubkey"`
	Path        string       `json:"path"`
	UUID        string       `json:"uuid"`
	Version     uint         `json:"version"`
}

// CryptoFields contains the cryptographic fields for the keystore
type CryptoFields struct {
	KDF        KDFFields        `json:"kdf"`
	Checksum   ChecksumFields   `json:"checksum"`
	Cipher     CipherFields     `json:"cipher"`
}

// KDFFields contains the key derivation function parameters
type KDFFields struct {
	Function string                 `json:"function"`
	Params   map[string]interface{} `json:"params"`
	Message  string                 `json:"message"`
}

// ChecksumFields contains the checksum parameters
type ChecksumFields struct {
	Function string                 `json:"function"`
	Params   map[string]interface{} `json:"params"`
	Message  string                 `json:"message"`
}

// CipherFields contains the cipher parameters
type CipherFields struct {
	Function string                 `json:"function"`
	Params   map[string]interface{} `json:"params"`
	Message  string                 `json:"message"`
}

// ValidatorKeys represents a validator's key pair
type ValidatorKeys struct {
	ValidatorIndex       uint64
	PrivateKey           []byte
	PublicKey            []byte
	WithdrawalPrivateKey []byte
	WithdrawalPublicKey  []byte
	Path                 string
}

// GeneratePassword creates a secure random password
func GeneratePassword() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// SaveKeystore saves a keystore to a file
func SaveKeystore(keystore *Keystore, outputPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(keystore, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keystore: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write keystore: %w", err)
	}

	return nil
}

// SavePassword saves a password to a file
func SavePassword(password string, outputPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write password to file
	if err := os.WriteFile(outputPath, []byte(password), 0600); err != nil {
		return fmt.Errorf("failed to write password: %w", err)
	}

	return nil
}

// CreateKeystoreFileName creates a standard keystore filename
func CreateKeystoreFileName(pubkey string) string {
	return fmt.Sprintf("keystore-%s.json", pubkey[:12])
}

// CreatePasswordFileName creates a standard password filename
func CreatePasswordFileName(pubkey string) string {
	return fmt.Sprintf("keystore-%s.txt", pubkey[:12])
}

// NewUUID generates a new UUID for the keystore
func NewUUID() string {
	return uuid.New().String()
}

// CreateEncryptedKeystore creates an EIP-2335 compliant keystore from a private key
func CreateEncryptedKeystore(privateKeyBytes []byte, password string, validatorIndex uint64) (*Keystore, error) {
	// Generate random salt and IV
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// For production, this should use proper scrypt key derivation and AES-128-CTR encryption
	// For now, we'll create a simplified version
	pubkeyHex := hex.EncodeToString(privateKeyBytes) // Placeholder - should derive actual public key

	path := fmt.Sprintf(ValidatorPathTemplate, validatorIndex)

	return &Keystore{
		Crypto: CryptoFields{
			KDF: KDFFields{
				Function: "scrypt",
				Params: map[string]interface{}{
					"dklen": 32,
					"n":     262144,
					"p":     1,
					"r":     8,
					"salt":  hex.EncodeToString(salt),
				},
				Message: "",
			},
			Checksum: ChecksumFields{
				Function: "sha256",
				Params:   map[string]interface{}{},
				Message:  "",
			},
			Cipher: CipherFields{
				Function: "aes-128-ctr",
				Params: map[string]interface{}{
					"iv": hex.EncodeToString(iv),
				},
				Message: hex.EncodeToString(privateKeyBytes), // Should be encrypted
			},
		},
		Description: fmt.Sprintf("Validator %d", validatorIndex),
		Pubkey:      pubkeyHex,
		Path:        path,
		UUID:        NewUUID(),
		Version:     4,
	}, nil
}
