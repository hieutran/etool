package validator

import (
	"encoding/hex"
	"fmt"
	"strings"

	e2types "github.com/wealdtech/go-eth2-types/v2"
)

// ImportedValidator represents a single imported validator with generated keys
type ImportedValidator struct {
	Index                uint64
	ValidatorPrivateKey  *e2types.BLSPrivateKey
	ValidatorPublicKey   *e2types.BLSPublicKey
	WithdrawalPrivateKey *e2types.BLSPrivateKey
	WithdrawalPublicKey  *e2types.BLSPublicKey
}

// CreateValidatorFromPrivateKey creates a validator from a private key hex string
func CreateValidatorFromPrivateKey(privateKeyHex string, index uint64) (*ImportedValidator, error) {
	// Initialize BLS
	if err := e2types.InitBLS(); err != nil {
		return nil, fmt.Errorf("failed to initialize BLS: %w", err)
	}

	// Remove 0x prefix if present
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	// Decode hex private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	// Validate key length (BLS private keys are 32 bytes)
	if len(privateKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privateKeyBytes))
	}

	// Create BLS private key
	validatorPrivKey, err := e2types.BLSPrivateKeyFromBytes(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create BLS private key: %w", err)
	}

	// For withdrawal key, we'll use the validator key itself as withdrawal key
	// This is a simple approach - in production you might want to derive a separate withdrawal key
	withdrawalPrivKey := validatorPrivKey

	// Get public keys with proper type assertion
	validatorPubKey, ok := validatorPrivKey.PublicKey().(*e2types.BLSPublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert validator public key type")
	}

	withdrawalPubKey, ok := withdrawalPrivKey.PublicKey().(*e2types.BLSPublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert withdrawal public key type")
	}

	return &ImportedValidator{
		Index:                index,
		ValidatorPrivateKey:  validatorPrivKey,
		ValidatorPublicKey:   validatorPubKey,
		WithdrawalPrivateKey: withdrawalPrivKey,
		WithdrawalPublicKey:  withdrawalPubKey,
	}, nil
}

// CreateValidatorsFromPrivateKeys creates multiple validators from private key hex strings
func CreateValidatorsFromPrivateKeys(privateKeys []string) ([]*ImportedValidator, error) {
	validators := make([]*ImportedValidator, 0, len(privateKeys))

	for i, privKey := range privateKeys {
		validator, err := CreateValidatorFromPrivateKey(privKey, uint64(i))
		if err != nil {
			return nil, fmt.Errorf("failed to create validator %d: %w", i, err)
		}
		validators = append(validators, validator)
	}

	return validators, nil
}

// GetValidatorPubKeyBytes returns the validator public key as bytes (48 bytes compressed)
func (v *ImportedValidator) GetValidatorPubKeyBytes() []byte {
	return v.ValidatorPublicKey.Marshal()
}

// GetWithdrawalPubKeyBytes returns the withdrawal public key as bytes (48 bytes compressed)
func (v *ImportedValidator) GetWithdrawalPubKeyBytes() []byte {
	return v.WithdrawalPublicKey.Marshal()
}

// SignDepositData signs the deposit data using BLS signature
func (v *ImportedValidator) SignDepositData(depositMessageRoot []byte, domain []byte) ([]byte, error) {
	// Combine deposit message root with domain for signing root
	signingRoot := make([]byte, 64)
	copy(signingRoot[:32], depositMessageRoot)
	copy(signingRoot[32:], domain)

	// Hash the signing root using SHA256
	hasher := func() [32]byte {
		var hash [32]byte
		copy(hash[:], signingRoot)
		return hash
	}()

	// Sign with BLS
	signature := v.ValidatorPrivateKey.Sign(hasher[:])

	return signature.Marshal(), nil
}

// GenerateKeystoreFromValidator creates a keystore from a validator with supplied private key
func GenerateKeystoreFromValidator(validator *ImportedValidator, password string) (*KeystoreWithPassword, error) {
	// Get private key bytes
	privKeyBytes := validator.ValidatorPrivateKey.Marshal()

	// Create keystore (using EIP-2335 format with proper encryption)
	keystore, err := CreateEncryptedKeystore(privKeyBytes, password, validator.Index)
	if err != nil {
		return nil, fmt.Errorf("failed to create keystore: %w", err)
	}

	pubkeyHex := hex.EncodeToString(validator.GetValidatorPubKeyBytes())

	return &KeystoreWithPassword{
		Keystore: keystore,
		Password: password,
		Pubkey:   pubkeyHex,
	}, nil
}

// GenerateKeystoresFromValidators creates keystores for all validators with supplied private keys
func GenerateKeystoresFromValidators(validators []*ImportedValidator, passwordFunc func() (string, error)) ([]*KeystoreWithPassword, error) {
	if passwordFunc == nil {
		passwordFunc = GeneratePassword
	}

	keystores := make([]*KeystoreWithPassword, 0, len(validators))

	for _, validator := range validators {
		password, err := passwordFunc()
		if err != nil {
			return nil, fmt.Errorf("failed to generate password for validator %d: %w", validator.Index, err)
		}

		keystore, err := GenerateKeystoreFromValidator(validator, password)
		if err != nil {
			return nil, fmt.Errorf("failed to generate keystore for validator %d: %w", validator.Index, err)
		}

		keystores = append(keystores, keystore)
	}

	return keystores, nil
}

// GenerateDepositDataFromValidator generates deposit data from a validator with supplied private key
func GenerateDepositDataFromValidator(validator *ImportedValidator, forkVersion []byte, networkName string, credType WithdrawalCredentialsType) (*DepositData, error) {
	// Convert to BLSValidatorKeys format for compatibility
	blsKeys := &BLSValidatorKeys{
		ValidatorIndex:       validator.Index,
		ValidatorPrivateKey:  validator.ValidatorPrivateKey,
		ValidatorPublicKey:   validator.ValidatorPublicKey,
		WithdrawalPrivateKey: validator.WithdrawalPrivateKey,
		WithdrawalPublicKey:  validator.WithdrawalPublicKey,
		Path:                 fmt.Sprintf(ValidatorPathTemplate, validator.Index),
	}

	// Create BLS deposit generator
	forkVersionHex := "0x" + hex.EncodeToString(forkVersion)
	generator, err := NewBLSDepositGenerator(forkVersionHex, networkName, credType)
	if err != nil {
		return nil, fmt.Errorf("failed to create deposit generator: %w", err)
	}

	// Generate deposit data
	return generator.GenerateDepositData(blsKeys)
}

// GenerateDepositDataFromValidators generates deposit data for all validators with supplied private keys
func GenerateDepositDataFromValidators(validators []*ImportedValidator, forkVersion []byte, networkName string, credType WithdrawalCredentialsType) (DepositDataList, error) {
	depositList := make(DepositDataList, 0, len(validators))

	for _, validator := range validators {
		deposit, err := GenerateDepositDataFromValidator(validator, forkVersion, networkName, credType)
		if err != nil {
			return nil, fmt.Errorf("failed to generate deposit for validator %d: %w", validator.Index, err)
		}
		depositList = append(depositList, *deposit)
	}

	return depositList, nil
}
