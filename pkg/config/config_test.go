package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultNetworkConfig(t *testing.T) {
	config := DefaultNetworkConfig()

	if config.PresetBase == "" {
		t.Error("PresetBase should not be empty")
	}

	if config.MinGenesisActiveValidatorCount == 0 {
		t.Error("MinGenesisActiveValidatorCount should not be 0")
	}

	if config.SecondsPerSlot == 0 {
		t.Error("SecondsPerSlot should not be 0")
	}

	if config.DepositContractAddress == "" {
		t.Error("DepositContractAddress should not be empty")
	}
}

func TestGenerator_SetChainID(t *testing.T) {
	gen := NewGenerator(nil)
	chainID := uint64(99999)

	gen.SetChainID(chainID)

	if gen.config.DepositChainID != chainID {
		t.Errorf("DepositChainID mismatch: expected %d, got %d", chainID, gen.config.DepositChainID)
	}

	if gen.config.DepositNetworkID != chainID {
		t.Errorf("DepositNetworkID mismatch: expected %d, got %d", chainID, gen.config.DepositNetworkID)
	}
}

func TestGenerator_SetValidatorCount(t *testing.T) {
	gen := NewGenerator(nil)
	count := uint64(128)

	gen.SetValidatorCount(count)

	if gen.config.MinGenesisActiveValidatorCount != count {
		t.Errorf("ValidatorCount mismatch: expected %d, got %d", count, gen.config.MinGenesisActiveValidatorCount)
	}
}

func TestGenerator_GenerateToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "config.yaml")

	gen := NewGenerator(nil)
	err := gen.GenerateToFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to generate config to file: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Config file was not created")
	}

	// Read and parse YAML
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var parsedConfig NetworkConfig
	if err := yaml.Unmarshal(data, &parsedConfig); err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	// Verify some fields
	if parsedConfig.PresetBase == "" {
		t.Error("PresetBase is empty in generated file")
	}
}
