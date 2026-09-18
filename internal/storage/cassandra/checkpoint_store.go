package cassandra

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/SirojWongpitakroj/hmf-audit/internal/checkpoint"
	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

// CheckpointStore adapts Cassandra checkpoint rows to the checkpoint domain.
type CheckpointStore struct {
	repo          *CheckpointRepo
	locatorTreeID string
}

var _ checkpoint.Repository = (*CheckpointStore)(nil)

func NewCheckpointStore(session *gocql.Session, locatorTreeID string) (*CheckpointStore, error) {
	if session == nil {
		return nil, fmt.Errorf("new checkpoint store: Cassandra session is nil")
	}
	if locatorTreeID == "" {
		return nil, fmt.Errorf("new checkpoint store: locator tree ID is required")
	}
	return &CheckpointStore{repo: NewCheckpointRepo(session), locatorTreeID: locatorTreeID}, nil
}

func (store *CheckpointStore) LatestCheckpoint(ctx context.Context,
	systemID string) (checkpoint.Checkpoint, error) {

	row, err := store.repo.GetLatestCheckpoint(ctx, systemID)
	if err != nil {
		return checkpoint.Checkpoint{}, checkpointStoreError(err)
	}
	return checkpointFromRow(row, store.locatorTreeID)
}

func (store *CheckpointStore) CurrentFinalized(ctx context.Context,
	systemID string) (checkpoint.Checkpoint, error) {

	state, err := store.repo.GetFinalityState(ctx, systemID)
	if err != nil {
		return checkpoint.Checkpoint{}, checkpointStoreError(err)
	}
	row, err := store.repo.GetCheckpoint(ctx, systemID, state.CheckpointSequence)
	if err != nil {
		return checkpoint.Checkpoint{}, checkpointStoreError(err)
	}
	if row.BlockchainTxHash == nil || row.BlockchainBlockHeight == nil ||
		row.AnchoredAt == nil || row.FinalizedAt == nil ||
		row.CheckpointID != state.FinalizedCheckpointID ||
		state.LocatorTreeID != store.locatorTreeID ||
		!bytes.Equal(row.LocatorRoot, state.LocatorRoot) ||
		!bytes.Equal(row.GlobalHMFRoot, state.GlobalHMFRoot) ||
		!bytes.Equal(row.StateCommitment, state.StateCommitment) ||
		*row.BlockchainTxHash != state.BlockchainTxHash ||
		*row.BlockchainBlockHeight != state.BlockchainBlockHeight ||
		!row.AnchoredAt.Equal(state.AnchoredAt) ||
		!row.FinalizedAt.Equal(state.FinalizedAt) {
		return checkpoint.Checkpoint{}, fmt.Errorf("current checkpoint: finality state conflicts with checkpoint history")
	}
	return checkpointFromRow(row, state.LocatorTreeID)
}

func (store *CheckpointStore) SavePending(ctx context.Context,
	value checkpoint.Checkpoint) (checkpoint.Checkpoint, error) {

	if value.Status != checkpoint.StatusPending || value.Anchor != nil || value.FinalizedAt != nil {
		return checkpoint.Checkpoint{}, fmt.Errorf("save pending checkpoint: value is not pending")
	}
	if value.LocatorTreeID != store.locatorTreeID {
		return checkpoint.Checkpoint{}, fmt.Errorf("save pending checkpoint: locator tree ID does not match store configuration")
	}
	checkpointID := gocql.UUIDFromTime(value.CreatedAt)
	if value.ID != "" {
		parsed, err := gocql.ParseUUID(value.ID)
		if err != nil {
			return checkpoint.Checkpoint{}, fmt.Errorf("save pending checkpoint: parse ID: %w", err)
		}
		checkpointID = parsed
	}
	row := CheckpointRoot{
		SystemID:           value.SystemID,
		CheckpointID:       checkpointID,
		CheckpointSequence: value.Sequence,
		LocatorRoot:        checkpointBytes(value.LocatorRoot),
		GlobalHMFRoot:      checkpointBytes(value.GlobalHMFRoot),
		StateCommitment:    checkpointBytes(value.StateCommitment),
		CreatedAt:          value.CreatedAt,
	}
	if err := store.repo.UpsertCheckpoint(ctx, row); err != nil {
		return checkpoint.Checkpoint{}, err
	}
	value.ID = checkpointID.String()
	return value, nil
}

func (store *CheckpointStore) PublishFinalized(ctx context.Context,
	value checkpoint.Checkpoint) error {

	if value.Status != checkpoint.StatusFinalized || value.Anchor == nil || value.FinalizedAt == nil {
		return fmt.Errorf("publish finalized checkpoint: finality metadata is incomplete")
	}
	if value.LocatorTreeID != store.locatorTreeID {
		return fmt.Errorf("publish finalized checkpoint: locator tree ID does not match store configuration")
	}
	checkpointID, err := gocql.ParseUUID(value.ID)
	if err != nil {
		return fmt.Errorf("publish finalized checkpoint: parse ID: %w", err)
	}
	transactionHash := value.Anchor.TransactionHash
	blockHeight := value.Anchor.BlockHeight
	anchoredAt := value.Anchor.AnchoredAt
	row := CheckpointRoot{
		SystemID:              value.SystemID,
		CheckpointID:          checkpointID,
		CheckpointSequence:    value.Sequence,
		LocatorRoot:           checkpointBytes(value.LocatorRoot),
		GlobalHMFRoot:         checkpointBytes(value.GlobalHMFRoot),
		StateCommitment:       checkpointBytes(value.StateCommitment),
		BlockchainTxHash:      &transactionHash,
		BlockchainBlockHeight: &blockHeight,
		AnchoredAt:            &anchoredAt,
		FinalizedAt:           value.FinalizedAt,
		CreatedAt:             value.CreatedAt,
	}
	if err := store.repo.UpsertCheckpoint(ctx, row); err != nil {
		return err
	}
	return store.repo.UpsertFinalityState(ctx, FinalityState{
		SystemID:              value.SystemID,
		FinalizedCheckpointID: checkpointID,
		CheckpointSequence:    value.Sequence,
		LocatorTreeID:         value.LocatorTreeID,
		LocatorRoot:           checkpointBytes(value.LocatorRoot),
		GlobalHMFRoot:         checkpointBytes(value.GlobalHMFRoot),
		StateCommitment:       checkpointBytes(value.StateCommitment),
		BlockchainTxHash:      transactionHash,
		BlockchainBlockHeight: blockHeight,
		AnchoredAt:            anchoredAt,
		FinalizedAt:           *value.FinalizedAt,
		UpdatedAt:             *value.FinalizedAt,
	})
}

func checkpointFromRow(row CheckpointRoot, locatorTreeID string) (checkpoint.Checkpoint, error) {
	locatorRoot, err := checkpointHash(row.LocatorRoot)
	if err != nil {
		return checkpoint.Checkpoint{}, fmt.Errorf("decode locator root: %w", err)
	}
	globalRoot, err := checkpointHash(row.GlobalHMFRoot)
	if err != nil {
		return checkpoint.Checkpoint{}, fmt.Errorf("decode global HMF root: %w", err)
	}
	commitment, err := checkpointHash(row.StateCommitment)
	if err != nil {
		return checkpoint.Checkpoint{}, fmt.Errorf("decode state commitment: %w", err)
	}
	result := checkpoint.Checkpoint{
		ID:              row.CheckpointID.String(),
		SystemID:        row.SystemID,
		Sequence:        row.CheckpointSequence,
		LocatorTreeID:   locatorTreeID,
		LocatorRoot:     locatorRoot,
		GlobalHMFRoot:   globalRoot,
		StateCommitment: commitment,
		Status:          checkpoint.StatusPending,
		CreatedAt:       row.CreatedAt,
	}
	anchorFields := 0
	if row.BlockchainTxHash != nil {
		anchorFields++
	}
	if row.BlockchainBlockHeight != nil {
		anchorFields++
	}
	if row.AnchoredAt != nil {
		anchorFields++
	}
	if row.FinalizedAt != nil {
		anchorFields++
	}
	if anchorFields != 0 && anchorFields != 4 {
		return checkpoint.Checkpoint{}, fmt.Errorf("decode checkpoint: partial finality metadata")
	}
	if anchorFields == 4 {
		result.Status = checkpoint.StatusFinalized
		result.Anchor = &checkpoint.AnchorReceipt{
			TransactionHash: *row.BlockchainTxHash,
			BlockHeight:     *row.BlockchainBlockHeight,
			AnchoredAt:      *row.AnchoredAt,
		}
		result.FinalizedAt = row.FinalizedAt
	}
	return result, nil
}

func checkpointHash(value []byte) ([32]byte, error) {
	if len(value) != 32 {
		return [32]byte{}, fmt.Errorf("hash has %d bytes, want 32", len(value))
	}
	var result [32]byte
	copy(result[:], value)
	return result, nil
}

func checkpointBytes(value [32]byte) []byte {
	return append([]byte(nil), value[:]...)
}

func checkpointStoreError(err error) error {
	if errors.Is(err, gocql.ErrNotFound) {
		return checkpoint.ErrNotFound
	}
	return err
}
