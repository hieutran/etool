package genesis

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ssz "github.com/ferranbt/fastssz"
	"github.com/hieutran/etool/pkg/validator"
)

// BeaconState represents the Ethereum consensus layer state at genesis
// This is a simplified implementation focusing on Deneb/Capella features
type BeaconState struct {
	// Versioning
	GenesisTime           uint64   `ssz-size:"8"`
	GenesisValidatorsRoot [32]byte `ssz-size:"32"`
	Slot                  uint64   `ssz-size:"8"`
	Fork                  *Fork    `ssz-size:"16"`

	// History
	LatestBlockHeader *BeaconBlockHeader `ssz-size:"112"`
	BlockRoots        [][32]byte         `ssz-size:"8192,32"` // SLOTS_PER_HISTORICAL_ROOT
	StateRoots        [][32]byte         `ssz-size:"8192,32"` // SLOTS_PER_HISTORICAL_ROOT
	HistoricalRoots   [][32]byte         `ssz-size:"?,32" ssz-max:"16777216"`

	// Eth1
	Eth1Data         *Eth1Data   `ssz-size:"72"`
	Eth1DataVotes    []*Eth1Data `ssz-size:"?,72" ssz-max:"2048"`
	Eth1DepositIndex uint64      `ssz-size:"8"`

	// Registry
	Validators []*Validator `ssz-size:"?,121" ssz-max:"1099511627776"`
	Balances   []uint64     `ssz-size:"?,8" ssz-max:"1099511627776"`

	// Randomness
	RandaoMixes [][32]byte `ssz-size:"65536,32"` // EPOCHS_PER_HISTORICAL_VECTOR

	// Slashings
	Slashings []uint64 `ssz-size:"8192,8"` // EPOCHS_PER_SLASHINGS_VECTOR

	// Participation (Altair+)
	PreviousEpochParticipation []byte `ssz-size:"?,1" ssz-max:"1099511627776"`
	CurrentEpochParticipation  []byte `ssz-size:"?,1" ssz-max:"1099511627776"`

	// Finality
	JustificationBits           [1]byte     `ssz-size:"1"`
	PreviousJustifiedCheckpoint *Checkpoint `ssz-size:"40"`
	CurrentJustifiedCheckpoint  *Checkpoint `ssz-size:"40"`
	FinalizedCheckpoint         *Checkpoint `ssz-size:"40"`

	// Inactivity (Altair+)
	InactivityScores []uint64 `ssz-size:"?,8" ssz-max:"1099511627776"`

	// Sync (Altair+)
	CurrentSyncCommittee *SyncCommittee `ssz-size:"24624"`
	NextSyncCommittee    *SyncCommittee `ssz-size:"24624"`

	// Execution (Bellatrix+)
	LatestExecutionPayloadHeader *ExecutionPayloadHeader `ssz-size:"584"`

	// Withdrawals (Capella+)
	NextWithdrawalIndex          uint64               `ssz-size:"8"`
	NextWithdrawalValidatorIndex uint64               `ssz-size:"8"`
	HistoricalSummaries          []*HistoricalSummary `ssz-size:"?,64" ssz-max:"16777216"`
}

// Fork represents a consensus fork
type Fork struct {
	PreviousVersion [4]byte `ssz-size:"4"`
	CurrentVersion  [4]byte `ssz-size:"4"`
	Epoch           uint64  `ssz-size:"8"`
}

// BeaconBlockHeader represents a beacon block header
type BeaconBlockHeader struct {
	Slot          uint64   `ssz-size:"8"`
	ProposerIndex uint64   `ssz-size:"8"`
	ParentRoot    [32]byte `ssz-size:"32"`
	StateRoot     [32]byte `ssz-size:"32"`
	BodyRoot      [32]byte `ssz-size:"32"`
}

// Eth1Data represents Eth1 data
type Eth1Data struct {
	DepositRoot  [32]byte `ssz-size:"32"`
	DepositCount uint64   `ssz-size:"8"`
	BlockHash    [32]byte `ssz-size:"32"`
}

// Validator represents a consensus layer validator
type Validator struct {
	Pubkey                     [48]byte `ssz-size:"48"`
	WithdrawalCredentials      [32]byte `ssz-size:"32"`
	EffectiveBalance           uint64   `ssz-size:"8"`
	Slashed                    bool     `ssz-size:"1"`
	ActivationEligibilityEpoch uint64   `ssz-size:"8"`
	ActivationEpoch            uint64   `ssz-size:"8"`
	ExitEpoch                  uint64   `ssz-size:"8"`
	WithdrawableEpoch          uint64   `ssz-size:"8"`
}

// HashTreeRoot computes the hash tree root of a Validator
func (v *Validator) HashTreeRoot() ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	// Field (0) 'Pubkey'
	hh.PutBytes(v.Pubkey[:])

	// Field (1) 'WithdrawalCredentials'
	hh.PutBytes(v.WithdrawalCredentials[:])

	// Field (2) 'EffectiveBalance'
	hh.PutUint64(v.EffectiveBalance)

	// Field (3) 'Slashed'
	hh.PutBool(v.Slashed)

	// Field (4) 'ActivationEligibilityEpoch'
	hh.PutUint64(v.ActivationEligibilityEpoch)

	// Field (5) 'ActivationEpoch'
	hh.PutUint64(v.ActivationEpoch)

	// Field (6) 'ExitEpoch'
	hh.PutUint64(v.ExitEpoch)

	// Field (7) 'WithdrawableEpoch'
	hh.PutUint64(v.WithdrawableEpoch)

	hh.Merkleize(0)
	return hh.HashRoot()
}

// Checkpoint represents a justified/finalized checkpoint
type Checkpoint struct {
	Epoch uint64   `ssz-size:"8"`
	Root  [32]byte `ssz-size:"32"`
}

// SyncCommittee represents a sync committee (Altair+)
type SyncCommittee struct {
	Pubkeys         [][48]byte `ssz-size:"512,48"`
	AggregatePubkey [48]byte   `ssz-size:"48"`
}

// ExecutionPayloadHeader represents execution payload header (Bellatrix+)
type ExecutionPayloadHeader struct {
	ParentHash       [32]byte  `ssz-size:"32"`
	FeeRecipient     [20]byte  `ssz-size:"20"`
	StateRoot        [32]byte  `ssz-size:"32"`
	ReceiptsRoot     [32]byte  `ssz-size:"32"`
	LogsBloom        [256]byte `ssz-size:"256"`
	PrevRandao       [32]byte  `ssz-size:"32"`
	BlockNumber      uint64    `ssz-size:"8"`
	GasLimit         uint64    `ssz-size:"8"`
	GasUsed          uint64    `ssz-size:"8"`
	Timestamp        uint64    `ssz-size:"8"`
	ExtraData        []byte    `ssz-size:"?,1" ssz-max:"32"`
	BaseFeePerGas    [32]byte  `ssz-size:"32"`
	BlockHash        [32]byte  `ssz-size:"32"`
	TransactionsRoot [32]byte  `ssz-size:"32"`
	WithdrawalsRoot  [32]byte  `ssz-size:"32"` // Capella+
	BlobGasUsed      uint64    `ssz-size:"8"`  // Deneb+
	ExcessBlobGas    uint64    `ssz-size:"8"`  // Deneb+
}

// HistoricalSummary represents historical summary (Capella+)
type HistoricalSummary struct {
	BlockSummaryRoot [32]byte `ssz-size:"32"`
	StateSummaryRoot [32]byte `ssz-size:"32"`
}

// Constants for genesis state
const (
	FAR_FUTURE_EPOCH             = uint64(^uint64(0))
	GENESIS_EPOCH                = uint64(0)
	GENESIS_SLOT                 = uint64(0)
	SLOTS_PER_HISTORICAL_ROOT    = 8192
	EPOCHS_PER_HISTORICAL_VECTOR = 65536
	EPOCHS_PER_SLASHINGS_VECTOR  = 8192
	SYNC_COMMITTEE_SIZE          = 512
	MAX_EFFECTIVE_BALANCE        = uint64(32000000000) // 32 ETH in Gwei
	EFFECTIVE_BALANCE_INCREMENT  = uint64(1000000000)  // 1 ETH in Gwei
)

// NewGenesisBeaconState creates a new genesis beacon state from deposits
func NewGenesisBeaconState(
	genesisTime uint64,
	eth1BlockHash [32]byte,
	deposits []validator.DepositData,
	forkVersion [4]byte,
	executionPayloadHash [32]byte,
) (*BeaconState, error) {

	// Initialize empty state
	state := &BeaconState{
		GenesisTime: genesisTime,
		Slot:        GENESIS_SLOT,
		Fork: &Fork{
			PreviousVersion: forkVersion,
			CurrentVersion:  forkVersion,
			Epoch:           GENESIS_EPOCH,
		},
		LatestBlockHeader: &BeaconBlockHeader{
			BodyRoot: [32]byte{}, // Will be set later
		},
		BlockRoots:      make([][32]byte, SLOTS_PER_HISTORICAL_ROOT),
		StateRoots:      make([][32]byte, SLOTS_PER_HISTORICAL_ROOT),
		HistoricalRoots: [][32]byte{},
		Eth1Data: &Eth1Data{
			DepositRoot:  [32]byte{},
			DepositCount: uint64(len(deposits)),
			BlockHash:    eth1BlockHash,
		},
		Eth1DataVotes:                []*Eth1Data{},
		Eth1DepositIndex:             uint64(len(deposits)),
		Validators:                   []*Validator{},
		Balances:                     []uint64{},
		RandaoMixes:                  make([][32]byte, EPOCHS_PER_HISTORICAL_VECTOR),
		Slashings:                    make([]uint64, EPOCHS_PER_SLASHINGS_VECTOR),
		PreviousEpochParticipation:   []byte{},
		CurrentEpochParticipation:    []byte{},
		JustificationBits:            [1]byte{0},
		PreviousJustifiedCheckpoint:  &Checkpoint{Epoch: GENESIS_EPOCH, Root: [32]byte{}},
		CurrentJustifiedCheckpoint:   &Checkpoint{Epoch: GENESIS_EPOCH, Root: [32]byte{}},
		FinalizedCheckpoint:          &Checkpoint{Epoch: GENESIS_EPOCH, Root: [32]byte{}},
		InactivityScores:             []uint64{},
		CurrentSyncCommittee:         newEmptySyncCommittee(),
		NextSyncCommittee:            newEmptySyncCommittee(),
		LatestExecutionPayloadHeader: newGenesisExecutionPayloadHeader(executionPayloadHash, genesisTime),
		NextWithdrawalIndex:          0,
		NextWithdrawalValidatorIndex: 0,
		HistoricalSummaries:          []*HistoricalSummary{},
	}

	// Initialize RANDAO mixes with eth1 block hash
	for i := range state.RandaoMixes {
		state.RandaoMixes[i] = eth1BlockHash
	}

	// Process deposits to create validators
	for _, deposit := range deposits {
		if err := processDeposit(state, &deposit); err != nil {
			return nil, fmt.Errorf("failed to process deposit: %w", err)
		}
	}

	// Compute genesis validators root
	validatorsRoot, err := computeValidatorsRoot(state.Validators)
	if err != nil {
		return nil, fmt.Errorf("failed to compute validators root: %w", err)
	}
	state.GenesisValidatorsRoot = validatorsRoot

	return state, nil
}

// processDeposit processes a single deposit and adds validator to state
func processDeposit(state *BeaconState, deposit *validator.DepositData) error {
	// Parse pubkey and withdrawal credentials
	var pubkey [48]byte
	var withdrawalCreds [32]byte

	pubkeyBytes, err := hexToBytes(deposit.Pubkey)
	if err != nil || len(pubkeyBytes) != 48 {
		return fmt.Errorf("invalid pubkey: %s", deposit.Pubkey)
	}
	copy(pubkey[:], pubkeyBytes)

	credsBytes, err := hexToBytes(deposit.WithdrawalCredentials)
	if err != nil || len(credsBytes) != 32 {
		return fmt.Errorf("invalid withdrawal credentials: %s", deposit.WithdrawalCredentials)
	}
	copy(withdrawalCreds[:], credsBytes)

	// Create new validator
	val := &Validator{
		Pubkey:                     pubkey,
		WithdrawalCredentials:      withdrawalCreds,
		EffectiveBalance:           MAX_EFFECTIVE_BALANCE,
		Slashed:                    false,
		ActivationEligibilityEpoch: GENESIS_EPOCH,
		ActivationEpoch:            GENESIS_EPOCH,
		ExitEpoch:                  FAR_FUTURE_EPOCH,
		WithdrawableEpoch:          FAR_FUTURE_EPOCH,
	}

	// Add validator to state
	state.Validators = append(state.Validators, val)
	state.Balances = append(state.Balances, deposit.Amount)
	state.PreviousEpochParticipation = append(state.PreviousEpochParticipation, 0)
	state.CurrentEpochParticipation = append(state.CurrentEpochParticipation, 0)
	state.InactivityScores = append(state.InactivityScores, 0)

	return nil
}

// computeValidatorsRoot computes the hash tree root of validators
func computeValidatorsRoot(validators []*Validator) ([32]byte, error) {
	if len(validators) == 0 {
		return [32]byte{}, nil
	}

	// Use fastssz to compute merkle root - simplified for v1.0.0
	// Since Validator doesn't have HashTreeRootWith in v1.0.0, we'll compute it differently
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)

	// For each validator, we need to hash their fields
	for _, v := range validators {
		// Hash validator fields manually since HashTreeRootWith is not available
		root, err := v.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		hh.Append(root[:])
	}

	root, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, err
	}

	return root, nil
}

// newEmptySyncCommittee creates an empty sync committee
func newEmptySyncCommittee() *SyncCommittee {
	sc := &SyncCommittee{
		Pubkeys:         make([][48]byte, SYNC_COMMITTEE_SIZE),
		AggregatePubkey: [48]byte{},
	}
	return sc
}

// newGenesisExecutionPayloadHeader creates a genesis execution payload header
func newGenesisExecutionPayloadHeader(blockHash [32]byte, timestamp uint64) *ExecutionPayloadHeader {
	return &ExecutionPayloadHeader{
		ParentHash:       [32]byte{},
		FeeRecipient:     [20]byte{},
		StateRoot:        [32]byte{},
		ReceiptsRoot:     [32]byte{},
		LogsBloom:        [256]byte{},
		PrevRandao:       [32]byte{},
		BlockNumber:      0,
		GasLimit:         30000000,
		GasUsed:          0,
		Timestamp:        timestamp,
		ExtraData:        []byte{},
		BaseFeePerGas:    uint256To32Bytes(1000000000), // 1 Gwei
		BlockHash:        blockHash,
		TransactionsRoot: emptyTransactionsRoot(),
		WithdrawalsRoot:  emptyWithdrawalsRoot(),
		BlobGasUsed:      0,
		ExcessBlobGas:    0,
	}
}

// Helper functions

func hexToBytes(s string) ([]byte, error) {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}

	if len(s)%2 != 0 {
		s = "0" + s
	}

	result := make([]byte, len(s)/2)
	for i := 0; i < len(result); i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				b |= c - 'A' + 10
			default:
				return nil, fmt.Errorf("invalid hex character: %c", c)
			}
		}
		result[i] = b
	}
	return result, nil
}

func uint256To32Bytes(val uint64) [32]byte {
	var result [32]byte
	binary.LittleEndian.PutUint64(result[0:8], val)
	return result
}

func emptyTransactionsRoot() [32]byte {
	// SSZ hash tree root of empty transactions list
	// This is a known constant for empty list
	hash := sha256.Sum256([]byte{})
	return hash
}

func emptyWithdrawalsRoot() [32]byte {
	// SSZ hash tree root of empty withdrawals list
	hash := sha256.Sum256([]byte{})
	return hash
}

// SaveGenesisSSZToFile saves genesis beacon state to file in SSZ format using fastssz
func SaveGenesisSSZToFile(state *BeaconState, outputPath string) error {
	// Encode to SSZ using fastssz (implementation in ssz_ssz.go)
	data, err := state.MarshalSSZ()
	if err != nil {
		return fmt.Errorf("failed to encode beacon state: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write genesis.ssz: %w", err)
	}

	return nil
}

// GenerateGenesisSSZ is a convenience function to generate genesis.ssz from deposit data
func GenerateGenesisSSZ(
	chainID uint64,
	networkName string,
	deposits []validator.DepositData,
	eth1BlockHash string,
	genesisTime uint64,
) (*BeaconState, error) {

	// Default genesis time to now if not specified
	if genesisTime == 0 {
		genesisTime = uint64(time.Now().Unix())
	}

	// Parse eth1 block hash
	var eth1Hash [32]byte
	if eth1BlockHash != "" {
		hashBytes, err := hexToBytes(eth1BlockHash)
		if err != nil || len(hashBytes) != 32 {
			return nil, fmt.Errorf("invalid eth1 block hash: %s", eth1BlockHash)
		}
		copy(eth1Hash[:], hashBytes)
	}

	// Fork version (default Deneb for genesis)
	forkVersion := [4]byte{0x04, 0x00, 0x00, 0x01}

	// Execution payload hash (use eth1 block hash)
	executionHash := eth1Hash

	// Generate beacon state
	state, err := NewGenesisBeaconState(
		genesisTime,
		eth1Hash,
		deposits,
		forkVersion,
		executionHash,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create genesis state: %w", err)
	}

	return state, nil
}
