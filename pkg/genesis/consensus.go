package genesis

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ConsensusConfig contains configuration for consensus layer genesis
type ConsensusConfig struct {
	GenesisTime           uint64
	GenesisValidatorRoot  string
	GenesisForkVersion    string
	ChainID               uint64
	NetworkName           string
	PresetBase            string // "mainnet" or "minimal"
	ValidatorCount        uint64
	Eth1BlockHash         string
	Eth1Timestamp         uint64
	DepositContractAddress string
}

// DefaultConsensusConfig returns a default consensus layer configuration
func DefaultConsensusConfig() *ConsensusConfig {
	return &ConsensusConfig{
		GenesisTime:            uint64(time.Now().Unix()),
		GenesisValidatorRoot:   "0x0000000000000000000000000000000000000000000000000000000000000000",
		GenesisForkVersion:     "0x00000001",
		ChainID:                32382,
		NetworkName:            "eth-devnet",
		PresetBase:             "mainnet",
		ValidatorCount:         64,
		Eth1BlockHash:          "0x0000000000000000000000000000000000000000000000000000000000000000",
		Eth1Timestamp:          uint64(time.Now().Unix()),
		DepositContractAddress: "0x4242424242424242424242424242424242424242",
	}
}

// ConsensusGenerator handles consensus layer genesis generation
type ConsensusGenerator struct {
	config *ConsensusConfig
}

// NewConsensusGenerator creates a new consensus layer genesis generator
func NewConsensusGenerator(config *ConsensusConfig) *ConsensusGenerator {
	if config == nil {
		config = DefaultConsensusConfig()
	}
	return &ConsensusGenerator{config: config}
}
