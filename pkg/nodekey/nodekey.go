package nodekey

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Generator handles node key generation
type Generator struct{}

// NewGenerator creates a new node key generator
func NewGenerator() *Generator {
	return &Generator{}
}

// NodeKey represents an Ethereum node's private key and derived information
type NodeKey struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  string
	NodeID     string
	EnodeURL   string
}

// Generate creates a new node key
func (g *Generator) Generate() (*NodeKey, error) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Get public key
	publicKey := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	// Get node ID (public key hash)
	nodeID := enode.PubkeyToIDV4(&privateKey.PublicKey).String()

	return &NodeKey{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		NodeID:     nodeID,
	}, nil
}

// SaveToFile writes a node key to a file
func SaveToFile(nodeKey *NodeKey, outputPath string) error {
	// Validate nodeKey is not nil
	if nodeKey == nil {
		return fmt.Errorf("nodeKey cannot be nil")
	}

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Convert private key to hex
	privateKeyBytes := crypto.FromECDSA(nodeKey.PrivateKey)
	hexKey := hex.EncodeToString(privateKeyBytes)

	// Write private key to file
	if err := os.WriteFile(outputPath, []byte(hexKey), 0600); err != nil {
		return fmt.Errorf("failed to write node key: %w", err)
	}

	// Write node ID to separate file
	nodeIDPath := outputPath + ".id"
	if err := os.WriteFile(nodeIDPath, []byte(nodeKey.NodeID), 0644); err != nil {
		return fmt.Errorf("failed to write node ID: %w", err)
	}

	return nil
}

// GenerateToFile creates a node key and writes it to a file
// This is a convenience method that combines Generate() and SaveToFile()
func (g *Generator) GenerateToFile(outputPath string) (*NodeKey, error) {
	nodeKey, err := g.Generate()
	if err != nil {
		return nil, err
	}
	if err := SaveToFile(nodeKey, outputPath); err != nil {
		return nil, err
	}
	return nodeKey, nil
}

// LoadFromFile loads a node key from a file
func LoadFromFile(path string) (*NodeKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read node key: %w", err)
	}

	// Trim whitespace to handle trailing newlines/spaces
	privateKeyHex := strings.TrimSpace(string(data))

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode node key: %w", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey := crypto.PubkeyToAddress(privateKey.PublicKey).Hex()
	nodeID := enode.PubkeyToIDV4(&privateKey.PublicKey).String()

	return &NodeKey{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		NodeID:     nodeID,
	}, nil
}
