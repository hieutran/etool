package genesis

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/params"
)

// ExecutionConfig contains configuration for execution layer genesis
type ExecutionConfig struct {
	ChainID            uint64
	ChainName          string
	Timestamp          uint64
	ExtraData          string
	GasLimit           uint64
	Difficulty         uint64
	MixHash            common.Hash
	Coinbase           common.Address
	Alloc              core.GenesisAlloc
	ShanghaiTime       *uint64
	CancunTime         *uint64
	PragueTime         *uint64
	TerminalTotalDifficulty *big.Int
}

// DefaultExecutionConfig returns a default execution layer configuration
func DefaultExecutionConfig() *ExecutionConfig {
	// Default to Shanghai + Cancun enabled at genesis
	shanghaiTime := uint64(0)
	cancunTime := uint64(0)

	return &ExecutionConfig{
		ChainID:            32382,
		ChainName:          "eth-devnet",
		Timestamp:          uint64(time.Now().Unix()),
		ExtraData:          "0x",
		GasLimit:           30000000,
		Difficulty:         0,
		MixHash:            common.Hash{},
		Coinbase:           common.Address{},
		Alloc:              make(core.GenesisAlloc),
		ShanghaiTime:       &shanghaiTime,
		CancunTime:         &cancunTime,
		TerminalTotalDifficulty: big.NewInt(0),
	}
}

// ExecutionGenerator handles execution layer genesis generation
type ExecutionGenerator struct {
	config *ExecutionConfig
}

// NewExecutionGenerator creates a new execution layer genesis generator
func NewExecutionGenerator(config *ExecutionConfig) *ExecutionGenerator {
	if config == nil {
		config = DefaultExecutionConfig()
	}
	return &ExecutionGenerator{config: config}
}

// AddPrefundedAccount adds a prefunded account to the genesis
func (g *ExecutionGenerator) AddPrefundedAccount(address common.Address, balance *big.Int) {
	if g.config.Alloc == nil {
		g.config.Alloc = make(core.GenesisAlloc)
	}
	g.config.Alloc[address] = core.GenesisAccount{
		Balance: balance,
	}
}

// AddPrefundedAccountWithCode adds a prefunded account with code to the genesis
func (g *ExecutionGenerator) AddPrefundedAccountWithCode(address common.Address, balance *big.Int, code []byte) {
	if g.config.Alloc == nil {
		g.config.Alloc = make(core.GenesisAlloc)
	}
	g.config.Alloc[address] = core.GenesisAccount{
		Balance: balance,
		Code:    code,
	}
}

// Generate creates the execution layer genesis
func (g *ExecutionGenerator) Generate() (*core.Genesis, error) {
	// Create chain config
	chainConfig := &params.ChainConfig{
		ChainID:             big.NewInt(int64(g.config.ChainID)),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		MergeNetsplitBlock:  big.NewInt(0),
		ShanghaiTime:        g.config.ShanghaiTime,
		CancunTime:          g.config.CancunTime,
		PragueTime:          g.config.PragueTime,
		TerminalTotalDifficulty: g.config.TerminalTotalDifficulty,
	}

	genesis := &core.Genesis{
		Config:     chainConfig,
		Nonce:      0,
		Timestamp:  g.config.Timestamp,
		ExtraData:  []byte(g.config.ExtraData),
		GasLimit:   g.config.GasLimit,
		Difficulty: big.NewInt(int64(g.config.Difficulty)),
		MixHash:    g.config.MixHash,
		Coinbase:   g.config.Coinbase,
		Alloc:      g.config.Alloc,
	}

	return genesis, nil
}

// SaveToFile writes a genesis to a file
func SaveToFile(genesis *core.Genesis, outputPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal genesis: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write genesis.json: %w", err)
	}

	return nil
}

// GenerateToFile creates genesis.json and writes it to a file
// This is a convenience method that combines Generate() and SaveToFile()
func (g *ExecutionGenerator) GenerateToFile(outputPath string) error {
	genesis, err := g.Generate()
	if err != nil {
		return err
	}
	return SaveToFile(genesis, outputPath)
}
