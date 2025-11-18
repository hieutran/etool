package genesis

import (
	"fmt"

	ssz "github.com/ferranbt/fastssz"
)

// Implement HashTreeRoot methods using fastssz properly

// HashTreeRoot implements ssz.HashRoot for BeaconState
func (s *BeaconState) HashTreeRoot() ([32]byte, error) {
	hh := ssz.DefaultHasherPool.Get()
	defer ssz.DefaultHasherPool.Put(hh)
	if err := s.HashTreeRootWith(hh); err != nil {
		return [32]byte{}, err
	}
	return hh.HashRoot()
}

// HashTreeRootWith implements ssz.HashRoot for BeaconState
func (s *BeaconState) HashTreeRootWith(hh *ssz.Hasher) error {
	indx := hh.Index()

	// Field (0) 'GenesisTime'
	hh.PutUint64(s.GenesisTime)

	// Field (1) 'GenesisValidatorsRoot'
	hh.PutBytes(s.GenesisValidatorsRoot[:])

	// Field (2) 'Slot'
	hh.PutUint64(s.Slot)

	// Field (3) 'Fork'
	if s.Fork == nil {
		s.Fork = &Fork{}
	}
	if err := s.Fork.HashTreeRootWith(hh); err != nil {
		return err
	}

	// Field (4) 'LatestBlockHeader'
	if s.LatestBlockHeader == nil {
		s.LatestBlockHeader = &BeaconBlockHeader{}
	}
	if err := s.LatestBlockHeader.HashTreeRootWith(hh); err != nil {
		return err
	}

	// Field (5) 'BlockRoots'
	{
		subIndx := hh.Index()
		for _, i := range s.BlockRoots {
			hh.Append(i[:])
		}
		hh.Merkleize(subIndx)
	}

	// Field (6) 'StateRoots'
	{
		subIndx := hh.Index()
		for _, i := range s.StateRoots {
			hh.Append(i[:])
		}
		hh.Merkleize(subIndx)
	}

	// Field (7) 'HistoricalRoots'
	{
		subIndx := hh.Index()
		num := uint64(len(s.HistoricalRoots))
		for _, i := range s.HistoricalRoots {
			hh.Append(i[:])
		}
		hh.MerkleizeWithMixin(subIndx, num, 16777216)
	}

	// Field (8) 'Eth1Data'
	if s.Eth1Data == nil {
		s.Eth1Data = &Eth1Data{}
	}
	if err := s.Eth1Data.HashTreeRootWith(hh); err != nil {
		return err
	}

	// Field (9) 'Eth1DataVotes'
	{
		subIndx := hh.Index()
		num := uint64(len(s.Eth1DataVotes))
		for _, elem := range s.Eth1DataVotes {
			if err := elem.HashTreeRootWith(hh); err != nil {
				return err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 2048)
	}

	// Field (10) 'Eth1DepositIndex'
	hh.PutUint64(s.Eth1DepositIndex)

	// Field (11) 'Validators'
	{
		subIndx := hh.Index()
		num := uint64(len(s.Validators))
		for _, elem := range s.Validators {
			// Call HashTreeRoot directly and append the result
			root, err := elem.HashTreeRoot()
			if err != nil {
				return err
			}
			hh.Append(root[:])
		}
		hh.MerkleizeWithMixin(subIndx, num, 1099511627776)
	}

	// Field (12) 'Balances'
	{
		subIndx := hh.Index()
		num := uint64(len(s.Balances))
		for _, elem := range s.Balances {
			hh.AppendUint64(elem)
		}
		hh.MerkleizeWithMixin(subIndx, num, 1099511627776)
	}

	// Field (13) 'RandaoMixes'
	{
		subIndx := hh.Index()
		for _, i := range s.RandaoMixes {
			hh.Append(i[:])
		}
		hh.Merkleize(subIndx)
	}

	// Field (14) 'Slashings'
	{
		subIndx := hh.Index()
		for _, i := range s.Slashings {
			hh.AppendUint64(i)
		}
		hh.Merkleize(subIndx)
	}

	// Field (15) 'PreviousEpochParticipation'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(s.PreviousEpochParticipation))
		if byteLen > 1099511627776 {
			return fmt.Errorf("PreviousEpochParticipation exceeds max length")
		}
		hh.PutBytes(s.PreviousEpochParticipation)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (1099511627776+31)/32)
	}

	// Field (16) 'CurrentEpochParticipation'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(s.CurrentEpochParticipation))
		if byteLen > 1099511627776 {
			return fmt.Errorf("CurrentEpochParticipation exceeds max length")
		}
		hh.PutBytes(s.CurrentEpochParticipation)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (1099511627776+31)/32)
	}

	// Field (17) 'JustificationBits'
	hh.PutBytes(s.JustificationBits[:])

	// Field (18) 'PreviousJustifiedCheckpoint'
	if s.PreviousJustifiedCheckpoint == nil {
		s.PreviousJustifiedCheckpoint = &Checkpoint{}
	}
	if err := s.PreviousJustifiedCheckpoint.HashTreeRootWith(hh); err != nil {
		return err
	}

	// Field (19) 'CurrentJustifiedCheckpoint'
	if s.CurrentJustifiedCheckpoint == nil {
		s.CurrentJustifiedCheckpoint = &Checkpoint{}
	}
	if err := s.CurrentJustifiedCheckpoint.HashTreeRootWith(hh); err != nil {
		return err
	}

	// Field (20) 'FinalizedCheckpoint'
	if s.FinalizedCheckpoint == nil {
		s.FinalizedCheckpoint = &Checkpoint{}
	}
	if err := s.FinalizedCheckpoint.HashTreeRootWith(hh); err != nil {
		return err
	}

	// Field (21) 'InactivityScores'
	{
		subIndx := hh.Index()
		num := uint64(len(s.InactivityScores))
		for _, elem := range s.InactivityScores {
			hh.AppendUint64(elem)
		}
		hh.MerkleizeWithMixin(subIndx, num, 1099511627776)
	}

	// Field (22) 'CurrentSyncCommittee'
	if s.CurrentSyncCommittee == nil {
		s.CurrentSyncCommittee = newEmptySyncCommittee()
	}
	if err := s.CurrentSyncCommittee.HashTreeRootWith(hh); err != nil {
		return err
	}

	// Field (23) 'NextSyncCommittee'
	if s.NextSyncCommittee == nil {
		s.NextSyncCommittee = newEmptySyncCommittee()
	}
	if err := s.NextSyncCommittee.HashTreeRootWith(hh); err != nil {
		return err
	}

	// Field (24) 'LatestExecutionPayloadHeader'
	if s.LatestExecutionPayloadHeader == nil {
		s.LatestExecutionPayloadHeader = &ExecutionPayloadHeader{}
	}
	if err := s.LatestExecutionPayloadHeader.HashTreeRootWith(hh); err != nil {
		return err
	}

	// Field (25) 'NextWithdrawalIndex'
	hh.PutUint64(s.NextWithdrawalIndex)

	// Field (26) 'NextWithdrawalValidatorIndex'
	hh.PutUint64(s.NextWithdrawalValidatorIndex)

	// Field (27) 'HistoricalSummaries'
	{
		subIndx := hh.Index()
		num := uint64(len(s.HistoricalSummaries))
		for _, elem := range s.HistoricalSummaries {
			if err := elem.HashTreeRootWith(hh); err != nil {
				return err
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 16777216)
	}

	hh.Merkleize(indx)
	return nil
}

// HashTreeRootWith for Fork
func (f *Fork) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()
	hh.PutBytes(f.PreviousVersion[:])
	hh.PutBytes(f.CurrentVersion[:])
	hh.PutUint64(f.Epoch)
	hh.Merkleize(indx)
	return nil
}

// HashTreeRootWith for BeaconBlockHeader
func (b *BeaconBlockHeader) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()
	hh.PutUint64(b.Slot)
	hh.PutUint64(b.ProposerIndex)
	hh.PutBytes(b.ParentRoot[:])
	hh.PutBytes(b.StateRoot[:])
	hh.PutBytes(b.BodyRoot[:])
	hh.Merkleize(indx)
	return nil
}

// HashTreeRootWith for Eth1Data
func (e *Eth1Data) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()
	hh.PutBytes(e.DepositRoot[:])
	hh.PutUint64(e.DepositCount)
	hh.PutBytes(e.BlockHash[:])
	hh.Merkleize(indx)
	return nil
}

// HashTreeRootWith for Checkpoint
func (c *Checkpoint) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()
	hh.PutUint64(c.Epoch)
	hh.PutBytes(c.Root[:])
	hh.Merkleize(indx)
	return nil
}

// HashTreeRootWith for SyncCommittee
func (s *SyncCommittee) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	// Field (0) 'Pubkeys'
	{
		subIndx := hh.Index()
		for i := 0; i < SYNC_COMMITTEE_SIZE; i++ {
			hh.PutBytes(s.Pubkeys[i][:])
		}
		hh.Merkleize(subIndx)
	}

	// Field (1) 'AggregatePubkey'
	hh.PutBytes(s.AggregatePubkey[:])

	hh.Merkleize(indx)
	return nil
}

// HashTreeRootWith for ExecutionPayloadHeader
func (e *ExecutionPayloadHeader) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()

	hh.PutBytes(e.ParentHash[:])
	hh.PutBytes(e.FeeRecipient[:])
	hh.PutBytes(e.StateRoot[:])
	hh.PutBytes(e.ReceiptsRoot[:])
	hh.PutBytes(e.LogsBloom[:])
	hh.PutBytes(e.PrevRandao[:])
	hh.PutUint64(e.BlockNumber)
	hh.PutUint64(e.GasLimit)
	hh.PutUint64(e.GasUsed)
	hh.PutUint64(e.Timestamp)

	// ExtraData - variable length
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(e.ExtraData))
		if byteLen > 32 {
			return fmt.Errorf("ExtraData exceeds max length")
		}
		hh.PutBytes(e.ExtraData)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (32+31)/32)
	}

	hh.PutBytes(e.BaseFeePerGas[:])
	hh.PutBytes(e.BlockHash[:])
	hh.PutBytes(e.TransactionsRoot[:])
	hh.PutBytes(e.WithdrawalsRoot[:])
	hh.PutUint64(e.BlobGasUsed)
	hh.PutUint64(e.ExcessBlobGas)

	hh.Merkleize(indx)
	return nil
}

// HashTreeRootWith for HistoricalSummary
func (h *HistoricalSummary) HashTreeRootWith(hh ssz.HashWalker) error {
	indx := hh.Index()
	hh.PutBytes(h.BlockSummaryRoot[:])
	hh.PutBytes(h.StateSummaryRoot[:])
	hh.Merkleize(indx)
	return nil
}

// MarshalSSZ encodes BeaconState using fastssz
func (s *BeaconState) MarshalSSZ() ([]byte, error) {
	buf := make([]byte, s.SizeSSZ())
	return s.MarshalSSZTo(buf[:0])
}

// MarshalSSZTo encodes BeaconState to a pre-allocated buffer
func (s *BeaconState) MarshalSSZTo(buf []byte) ([]byte, error) {
	// This is a simplified implementation - in production, use fastssz code generator
	// For now, we mainly need HashTreeRoot which is already implemented
	return buf, fmt.Errorf("MarshalSSZTo not fully implemented - use fastssz code generator")
}

// SizeSSZ returns the size of the SSZ encoding
func (s *BeaconState) SizeSSZ() int {
	// Return approximate size - this would be precise with fastssz code generator
	size := 0
	size += 8  // GenesisTime
	size += 32 // GenesisValidatorsRoot
	size += 8  // Slot
	// ... more fields
	// For now return a large enough buffer
	return 2_000_000 // 2MB should be enough for most beacon states
}
