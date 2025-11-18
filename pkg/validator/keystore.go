package validator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	"golang.org/x/crypto/scrypt"
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
	KDF      KDFFields      `json:"kdf"`
	Checksum ChecksumFields `json:"checksum"`
	Cipher   CipherFields   `json:"cipher"`
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
	end := 12
	if len(pubkey) < end {
		end = len(pubkey)
	}
	prefix := pubkey[:end]
	return fmt.Sprintf("keystore-%s.json", prefix)
}

// CreatePasswordFileName creates a standard password filename
func CreatePasswordFileName(pubkey string) string {
	end := 12
	if len(pubkey) < end {
		end = len(pubkey)
	}
	prefix := pubkey[:end]
	return fmt.Sprintf("keystore-%s.txt", prefix)
}

// NewUUID generates a new UUID for the keystore
func NewUUID() string {
	return uuid.New().String()
}

// CreateEncryptedKeystore creates an EIP-2335 compliant keystore from a private key
// This function implements proper encryption following the EIP-2335 specification:
// - Derives BLS public key from private key
// - Uses scrypt KDF with provided password to derive encryption key
// - Encrypts private key with AES-128-CTR
// - Computes SHA-256 checksum for integrity verification
func CreateEncryptedKeystore(privateKeyBytes []byte, password string, validatorIndex uint64) (*Keystore, error) {
	// Validate inputs
	if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privateKeyBytes))
	}
	if password == "" {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Derive the BLS public key from the private key
	pubkey, err := derivePublicKeyFromPrivate(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}
	pubkeyHex := hex.EncodeToString(pubkey)

	// Generate random salt for scrypt KDF (32 bytes as per EIP-2335)
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate random IV for AES-128-CTR (16 bytes)
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Derive decryption key using scrypt
	// Parameters from EIP-2335: N=262144, r=8, p=1, dklen=32
	decryptionKey, err := scrypt.Key([]byte(password), salt, 262144, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key with scrypt: %w", err)
	}

	// Use first 16 bytes for AES-128-CTR encryption
	aesKey := decryptionKey[:16]

	// Encrypt the private key using AES-128-CTR
	ciphertext, err := encryptAES128CTR(privateKeyBytes, aesKey, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Compute checksum: SHA-256 hash of decryptionKey[16:32] + ciphertext
	checksum := computeChecksum(decryptionKey[16:32], ciphertext)

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
				Message: "", // Empty as per EIP-2335
			},
			Checksum: ChecksumFields{
				Function: "sha256",
				Params:   map[string]interface{}{},
				Message:  hex.EncodeToString(checksum),
			},
			Cipher: CipherFields{
				Function: "aes-128-ctr",
				Params: map[string]interface{}{
					"iv": hex.EncodeToString(iv),
				},
				Message: hex.EncodeToString(ciphertext),
			},
		},
		Description: fmt.Sprintf("Validator %d", validatorIndex),
		Pubkey:      pubkeyHex,
		Path:        path,
		UUID:        NewUUID(),
		Version:     4,
	}, nil
}

// derivePublicKeyFromPrivate derives a BLS public key from a private key
// This uses the go-eth2-types library for proper BLS12-381 operations
func derivePublicKeyFromPrivate(privateKeyBytes []byte) ([]byte, error) {
	// Initialize BLS (idempotent, safe to call multiple times)
	if err := e2types.InitBLS(); err != nil {
		return nil, fmt.Errorf("failed to initialize BLS: %w", err)
	}

	// Create BLS private key from bytes
	privKey, err := e2types.BLSPrivateKeyFromBytes(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create BLS private key: %w", err)
	}

	// Get public key
	pubKey, ok := privKey.PublicKey().(*e2types.BLSPublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert BLS public key type")
	}

	// Return marshaled public key (48 bytes compressed)
	return pubKey.Marshal(), nil
}

// encryptAES128CTR encrypts data using AES-128 in CTR mode
func encryptAES128CTR(plaintext, key, iv []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("invalid key length: expected 16 bytes, got %d", len(key))
	}
	if len(iv) != 16 {
		return nil, fmt.Errorf("invalid IV length: expected 16 bytes, got %d", len(iv))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create CTR stream
	stream := cipher.NewCTR(block, iv)

	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, nil
}

// computeChecksum computes the EIP-2335 checksum
// Checksum is SHA-256(decryptionKey[16:32] || ciphertext)
func computeChecksum(decryptionKeySuffix, ciphertext []byte) []byte {
	hasher := sha256.New()
	hasher.Write(decryptionKeySuffix)
	hasher.Write(ciphertext)
	return hasher.Sum(nil)
}
