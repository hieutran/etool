package validator

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// SSZDepositMessage represents the deposit message for SSZ encoding
type SSZDepositMessage struct {
	Pubkey                [48]byte
	WithdrawalCredentials [32]byte
	Amount                uint64
}

// SSZDepositData represents the full deposit data for SSZ encoding
type SSZDepositData struct {
	Pubkey                [48]byte
	WithdrawalCredentials [32]byte
	Amount                uint64
	Signature             [96]byte
}

// HashTreeRoot computes the hash tree root of the deposit message (simplified SSZ)
func (d *SSZDepositMessage) HashTreeRoot() ([32]byte, error) {
	// This is a simplified implementation
	// Production should use fastssz or Prysm's SSZ library for proper Merkleization

	// Chunk 1: Pubkey (48 bytes, needs padding to 64 bytes for two 32-byte chunks)
	chunk1 := make([]byte, 32)
	copy(chunk1, d.Pubkey[:32])

	chunk2 := make([]byte, 32)
	copy(chunk2, d.Pubkey[32:48])

	// Hash pubkey chunks
	hasher := sha256.New()
	hasher.Write(chunk1)
	hasher.Write(chunk2)
	pubkeyRoot := hasher.Sum(nil)

	// Chunk 3: Withdrawal credentials (32 bytes)
	withdrawalRoot := d.WithdrawalCredentials

	// Chunk 4: Amount (8 bytes, little-endian)
	amountBytes := make([]byte, 32)
	binary.LittleEndian.PutUint64(amountBytes, d.Amount)

	// Combine all chunks
	hasher.Reset()
	hasher.Write(pubkeyRoot)
	hasher.Write(withdrawalRoot[:])
	hasher.Write(amountBytes)

	var root [32]byte
	copy(root[:], hasher.Sum(nil))
	return root, nil
}

// HashTreeRoot computes the hash tree root of the full deposit data (simplified SSZ)
func (d *SSZDepositData) HashTreeRoot() ([32]byte, error) {
	// This is a simplified implementation
	// Production should use fastssz or Prysm's SSZ library

	// First compute deposit message root
	depositMsg := SSZDepositMessage{
		Pubkey:                d.Pubkey,
		WithdrawalCredentials: d.WithdrawalCredentials,
		Amount:                d.Amount,
	}
	depositMsgRoot, err := depositMsg.HashTreeRoot()
	if err != nil {
		return [32]byte{}, err
	}

	// Signature chunks (96 bytes = 3 chunks of 32 bytes)
	sigChunk1 := make([]byte, 32)
	copy(sigChunk1, d.Signature[:32])

	sigChunk2 := make([]byte, 32)
	copy(sigChunk2, d.Signature[32:64])

	sigChunk3 := make([]byte, 32)
	copy(sigChunk3, d.Signature[64:96])

	// Hash signature chunks
	hasher := sha256.New()
	hasher.Write(sigChunk1)
	hasher.Write(sigChunk2)
	hasher.Write(sigChunk3)
	signatureRoot := hasher.Sum(nil)

	// Combine deposit message root and signature root
	hasher.Reset()
	hasher.Write(depositMsgRoot[:])
	hasher.Write(signatureRoot)

	var root [32]byte
	copy(root[:], hasher.Sum(nil))
	return root, nil
}

// ComputeDepositDomain computes the domain for deposit signing
func ComputeDepositDomain(forkVersion []byte) []byte {
	// Domain type for deposits
	depositDomainType := []byte{0x03, 0x00, 0x00, 0x00}

	// Genesis fork version (typically 4 bytes)
	if len(forkVersion) < 4 {
		forkVersion = append(forkVersion, make([]byte, 4-len(forkVersion))...)
	}

	// Compute fork data root
	hasher := sha256.New()
	hasher.Write(forkVersion[:4])
	hasher.Write(make([]byte, 28)) // Genesis validators root (zeros for genesis)
	forkDataRoot := hasher.Sum(nil)

	// Combine domain type and fork data root
	domain := make([]byte, 32)
	copy(domain[:4], depositDomainType)
	copy(domain[4:], forkDataRoot[:28])

	return domain
}

// ComputeSigningRoot computes the signing root for a deposit
func ComputeSigningRoot(depositMessageRoot, domain []byte) ([32]byte, error) {
	if len(depositMessageRoot) != 32 {
		return [32]byte{}, fmt.Errorf("deposit message root must be 32 bytes")
	}
	if len(domain) != 32 {
		return [32]byte{}, fmt.Errorf("domain must be 32 bytes")
	}

	// Create signing root: hash(deposit_message_root + domain)
	hasher := sha256.New()
	hasher.Write(depositMessageRoot)
	hasher.Write(domain)

	var signingRoot [32]byte
	copy(signingRoot[:], hasher.Sum(nil))
	return signingRoot, nil
}
