package genesis

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestDefaultExecutionConfig(t *testing.T) {
	config := DefaultExecutionConfig()

	if config.ChainID == 0 {
		t.Error("ChainID should not be 0")
	}

	if config.ChainName == "" {
		t.Error("ChainName should not be empty")
	}

	if config.GasLimit == 0 {
		t.Error("GasLimit should not be 0")
	}
}

func TestExecutionGenerator_AddPrefundedAccount(t *testing.T) {
	gen := NewExecutionGenerator(nil)

	address := common.HexToAddress("0x123463a4B065722E99115D6c222f267d9cABb524")
	balance := big.NewInt(1000000000000000000) // 1 ETH

	gen.AddPrefundedAccount(address, balance)

	if len(gen.config.Alloc) != 1 {
		t.Errorf("Expected 1 prefunded account, got %d", len(gen.config.Alloc))
	}

	account, exists := gen.config.Alloc[address]
	if !exists {
		t.Error("Prefunded account not found")
	}

	if account.Balance.Cmp(balance) != 0 {
		t.Errorf("Balance mismatch: expected %s, got %s", balance.String(), account.Balance.String())
	}
}

func TestExecutionGenerator_Generate(t *testing.T) {
	config := DefaultExecutionConfig()
	config.ChainID = 12345

	gen := NewExecutionGenerator(config)
	genesis, err := gen.Generate()
	if err != nil {
		t.Fatalf("Failed to generate genesis: %v", err)
	}

	if genesis.Config.ChainID.Uint64() != 12345 {
		t.Errorf("ChainID mismatch: expected 12345, got %d", genesis.Config.ChainID.Uint64())
	}

	if genesis.GasLimit != config.GasLimit {
		t.Errorf("GasLimit mismatch: expected %d, got %d", config.GasLimit, genesis.GasLimit)
	}
}

func TestExecutionGenerator_GenerateToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "genesis.json")

	gen := NewExecutionGenerator(nil)
	err := gen.GenerateToFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to generate genesis to file: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Genesis file was not created")
	}

	// Check file is not empty
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read genesis file: %v", err)
	}

	if len(data) == 0 {
		t.Error("Genesis file is empty")
	}
}

func TestDefaultConsensusConfig(t *testing.T) {
	config := DefaultConsensusConfig()

	if config.ChainID == 0 {
		t.Error("ChainID should not be 0")
	}

	if config.NetworkName == "" {
		t.Error("NetworkName should not be empty")
	}

	if config.ValidatorCount == 0 {
		t.Error("ValidatorCount should not be 0")
	}
}
