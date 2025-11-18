package jwt

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// JWTSecretLength is the required length for JWT secrets (32 bytes)
const JWTSecretLength = 32

// Generator handles JWT secret generation
type Generator struct{}

// NewGenerator creates a new JWT generator
func NewGenerator() *Generator {
	return &Generator{}
}

// Generate creates a new JWT secret
func (g *Generator) Generate() ([]byte, error) {
	secret := make([]byte, JWTSecretLength)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return secret, nil
}

// SaveToFile writes a JWT secret to a file
func SaveToFile(secret []byte, outputPath string) error {
	if err := Validate(secret); err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write as hex string with 0x prefix
	hexSecret := "0x" + hex.EncodeToString(secret)
	if err := os.WriteFile(outputPath, []byte(hexSecret), 0600); err != nil {
		return fmt.Errorf("failed to write JWT secret: %w", err)
	}

	return nil
}

// GenerateToFile creates a JWT secret and writes it to a file
// This is a convenience method that combines Generate() and SaveToFile()
func (g *Generator) GenerateToFile(outputPath string) error {
	secret, err := g.Generate()
	if err != nil {
		return err
	}
	return SaveToFile(secret, outputPath)
}

// Validate checks if a JWT secret is valid
func Validate(secret []byte) error {
	if len(secret) != JWTSecretLength {
		return fmt.Errorf("invalid JWT secret length: expected %d, got %d", JWTSecretLength, len(secret))
	}
	return nil
}
