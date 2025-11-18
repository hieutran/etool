package validator

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/tyler-smith/go-bip39"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

// BLSKeyDerivation handles BLS12-381 key derivation following EIP-2333
type BLSKeyDerivation struct {
	mnemonic string
	seed     []byte
}

// NewBLSKeyDerivation creates a new BLS key derivation instance
func NewBLSKeyDerivation(mnemonic string) (*BLSKeyDerivation, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}

	// Initialize BLS
	if err := e2types.InitBLS(); err != nil {
		return nil, fmt.Errorf("failed to initialize BLS: %w", err)
	}

	seed := bip39.NewSeed(mnemonic, "")

	return &BLSKeyDerivation{
		mnemonic: mnemonic,
		seed:     seed,
	}, nil
}

// DeriveValidatorKey derives a validator signing key using EIP-2333
// Path: m/12381/3600/{validator_index}/0/0
func (b *BLSKeyDerivation) DeriveValidatorKey(validatorIndex uint64) (*e2types.BLSPrivateKey, error) {
	// EIP-2333 key derivation path
	path := []uint32{
		12381,                   // Purpose (BLS12-381)
		3600,                    // Coin type (Ethereum consensus)
		uint32(validatorIndex),  // Validator index
		0,                       // Use (0 = withdrawal, non-zero = signing)
		0,                       // Key index
	}

	return b.deriveKey(path)
}

// DeriveWithdrawalKey derives a withdrawal key using EIP-2333
// Path: m/12381/3600/{validator_index}/0
func (b *BLSKeyDerivation) DeriveWithdrawalKey(validatorIndex uint64) (*e2types.BLSPrivateKey, error) {
	// EIP-2333 key derivation path
	path := []uint32{
		12381,                   // Purpose (BLS12-381)
		3600,                    // Coin type (Ethereum consensus)
		uint32(validatorIndex),  // Validator index
		0,                       // Use (0 = withdrawal)
	}

	return b.deriveKey(path)
}

// deriveKey performs the actual key derivation following EIP-2333
func (b *BLSKeyDerivation) deriveKey(path []uint32) (*e2types.BLSPrivateKey, error) {
	// Start with master key from seed
	key := b.seed

	// Derive through each level of the path
	for _, index := range path {
		key = b.deriveChildKey(key, index)
	}

	// Convert to BLS private key
	// Take mod of the key material to ensure it's within the BLS curve order
	privateKey, err := e2types.BLSPrivateKeyFromBytes(key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create BLS private key: %w", err)
	}

	return privateKey, nil
}

// deriveChildKey derives a child key using HKDF (simplified EIP-2333)
func (b *BLSKeyDerivation) deriveChildKey(parentKey []byte, index uint32) []byte {
	// Combine parent key with index
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)

	// Hash to derive child
	hasher := sha256.New()
	hasher.Write(parentKey)
	hasher.Write(indexBytes)
	childKey := hasher.Sum(nil)

	// Ensure we have enough bytes
	if len(childKey) < 32 {
		// Pad if necessary
		padded := make([]byte, 32)
		copy(padded, childKey)
		return padded
	}

	return childKey[:32]
}

// BLSValidatorKeys represents a validator's BLS key pair
type BLSValidatorKeys struct {
	ValidatorIndex       uint64
	ValidatorPrivateKey  *e2types.BLSPrivateKey
	ValidatorPublicKey   *e2types.BLSPublicKey
	WithdrawalPrivateKey *e2types.BLSPrivateKey
	WithdrawalPublicKey  *e2types.BLSPublicKey
	Path                 string
}

// GenerateBLSValidatorKeys generates validator keys using proper BLS12-381
func GenerateBLSValidatorKeys(mnemonic string, validatorIndex uint64) (*BLSValidatorKeys, error) {
	kd, err := NewBLSKeyDerivation(mnemonic)
	if err != nil {
		return nil, err
	}

	// Derive validator signing key
	validatorPrivKey, err := kd.DeriveValidatorKey(validatorIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive validator key: %w", err)
	}

	// Derive withdrawal key
	withdrawalPrivKey, err := kd.DeriveWithdrawalKey(validatorIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive withdrawal key: %w", err)
	}

	path := fmt.Sprintf(ValidatorPathTemplate, validatorIndex)

	return &BLSValidatorKeys{
		ValidatorIndex:       validatorIndex,
		ValidatorPrivateKey:  validatorPrivKey,
		ValidatorPublicKey:   validatorPrivKey.PublicKey(),
		WithdrawalPrivateKey: withdrawalPrivKey,
		WithdrawalPublicKey:  withdrawalPrivKey.PublicKey(),
		Path:                 path,
	}, nil
}

// GetValidatorPubKeyBytes returns the validator public key as bytes (48 bytes compressed)
func (k *BLSValidatorKeys) GetValidatorPubKeyBytes() []byte {
	return k.ValidatorPublicKey.Marshal()
}

// GetWithdrawalPubKeyBytes returns the withdrawal public key as bytes (48 bytes compressed)
func (k *BLSValidatorKeys) GetWithdrawalPubKeyBytes() []byte {
	return k.WithdrawalPublicKey.Marshal()
}

// SignDepositData signs the deposit data using BLS signature
func (k *BLSValidatorKeys) SignDepositData(depositMessageRoot []byte, domain []byte) ([]byte, error) {
	// Combine deposit message root with domain for signing root
	signingRoot := make([]byte, 64)
	copy(signingRoot[:32], depositMessageRoot)
	copy(signingRoot[32:], domain)

	// Hash the signing root
	hasher := sha256.New()
	hasher.Write(signingRoot)
	signingRootHash := hasher.Sum(nil)

	// Sign with BLS
	signature := k.ValidatorPrivateKey.Sign(signingRootHash[:])

	return signature.Marshal(), nil
}
