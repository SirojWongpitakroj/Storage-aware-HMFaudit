package cassandra

import (
	"context"
	"fmt"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

type CheckpointRoot struct {
	SystemID              string
	CheckpointID          gocql.UUID
	CheckpointSequence    int64
	LocatorRoot           []byte
	GlobalHMFRoot         []byte
	StateCommitment       []byte
	BlockchainTxHash      *string
	BlockchainBlockHeight *int64
	AnchoredAt            *time.Time
	FinalizedAt           *time.Time
	CreatedAt             time.Time
}

type FinalityState struct {
	SystemID              string
	FinalizedCheckpointID gocql.UUID
	CheckpointSequence    int64
	LocatorTreeID         string
	LocatorRoot           []byte
	GlobalHMFRoot         []byte
	StateCommitment       []byte
	BlockchainTxHash      string
	BlockchainBlockHeight int64
	AnchoredAt            time.Time
	FinalizedAt           time.Time
	UpdatedAt             time.Time
}

type CheckpointRepo struct {
	session *gocql.Session
}

func NewCheckpointRepo(session *gocql.Session) *CheckpointRepo {
	return &CheckpointRepo{
		session: session,
	}
}

func (r *CheckpointRepo) UpsertCheckpoint(ctx context.Context,
	checkpoint CheckpointRoot) error {

	query := `
		INSERT INTO checkpoint_roots (
			system_id,
			checkpoint_id,
			checkpoint_sequence,
			locator_root,
			global_hmf_root,
			state_commitment,
			blockchain_tx_hash,
			blockchain_block_height,
			anchored_at,
			finalized_at,
			created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	err := r.session.Query(
		query,
		checkpoint.SystemID,
		checkpoint.CheckpointID,
		checkpoint.CheckpointSequence,
		checkpoint.LocatorRoot,
		checkpoint.GlobalHMFRoot,
		checkpoint.StateCommitment,
		checkpoint.BlockchainTxHash,
		checkpoint.BlockchainBlockHeight,
		checkpoint.AnchoredAt,
		checkpoint.FinalizedAt,
		checkpoint.CreatedAt,
	).ExecContext(ctx)

	if err != nil {
		return fmt.Errorf("upsert checkpoint %s: %w", checkpoint.CheckpointID, err)
	}

	return nil
}

func (r *CheckpointRepo) GetCheckpoint(ctx context.Context, systemID string,
	checkpointSequence int64) (CheckpointRoot, error) {

	checkpoint := CheckpointRoot{}

	query := `
		SELECT
			system_id,
			checkpoint_id,
			checkpoint_sequence,
			locator_root,
			global_hmf_root,
			state_commitment,
			blockchain_tx_hash,
			blockchain_block_height,
			anchored_at,
			finalized_at,
			created_at
		FROM checkpoint_roots
		WHERE system_id = ?
		AND checkpoint_sequence = ?;
	`

	err := r.session.Query(
		query,
		systemID,
		checkpointSequence,
	).ScanContext(
		ctx,
		&checkpoint.SystemID,
		&checkpoint.CheckpointID,
		&checkpoint.CheckpointSequence,
		&checkpoint.LocatorRoot,
		&checkpoint.GlobalHMFRoot,
		&checkpoint.StateCommitment,
		&checkpoint.BlockchainTxHash,
		&checkpoint.BlockchainBlockHeight,
		&checkpoint.AnchoredAt,
		&checkpoint.FinalizedAt,
		&checkpoint.CreatedAt,
	)

	if err != nil {
		return CheckpointRoot{}, fmt.Errorf("get checkpoint %d: %w", checkpointSequence, err)
	}

	return checkpoint, nil
}

func (r *CheckpointRepo) GetLatestCheckpoint(ctx context.Context,
	systemID string) (CheckpointRoot, error) {

	checkpoint := CheckpointRoot{}

	query := `
		SELECT
			system_id,
			checkpoint_id,
			checkpoint_sequence,
			locator_root,
			global_hmf_root,
			state_commitment,
			blockchain_tx_hash,
			blockchain_block_height,
			anchored_at,
			finalized_at,
			created_at
		FROM checkpoint_roots
		WHERE system_id = ?
		LIMIT 1;
	`

	err := r.session.Query(
		query,
		systemID,
	).ScanContext(
		ctx,
		&checkpoint.SystemID,
		&checkpoint.CheckpointID,
		&checkpoint.CheckpointSequence,
		&checkpoint.LocatorRoot,
		&checkpoint.GlobalHMFRoot,
		&checkpoint.StateCommitment,
		&checkpoint.BlockchainTxHash,
		&checkpoint.BlockchainBlockHeight,
		&checkpoint.AnchoredAt,
		&checkpoint.FinalizedAt,
		&checkpoint.CreatedAt,
	)

	if err != nil {
		return CheckpointRoot{}, fmt.Errorf("get latest checkpoint: %w", err)
	}

	return checkpoint, nil
}

func (r *CheckpointRepo) UpsertFinalityState(ctx context.Context,
	state FinalityState) error {

	query := `
		INSERT INTO finality_state (
			system_id,
			finalized_checkpoint_id,
			checkpoint_sequence,
			locator_tree_id,
			locator_root,
			global_hmf_root,
			state_commitment,
			blockchain_tx_hash,
			blockchain_block_height,
			anchored_at,
			finalized_at,
			updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	err := r.session.Query(
		query,
		state.SystemID,
		state.FinalizedCheckpointID,
		state.CheckpointSequence,
		state.LocatorTreeID,
		state.LocatorRoot,
		state.GlobalHMFRoot,
		state.StateCommitment,
		state.BlockchainTxHash,
		state.BlockchainBlockHeight,
		state.AnchoredAt,
		state.FinalizedAt,
		state.UpdatedAt,
	).ExecContext(ctx)

	if err != nil {
		return fmt.Errorf("upsert finality state %s: %w", state.SystemID, err)
	}

	return nil
}

func (r *CheckpointRepo) GetFinalityState(ctx context.Context,
	systemID string) (FinalityState, error) {

	state := FinalityState{}

	query := `
		SELECT
			system_id,
			finalized_checkpoint_id,
			checkpoint_sequence,
			locator_tree_id,
			locator_root,
			global_hmf_root,
			state_commitment,
			blockchain_tx_hash,
			blockchain_block_height,
			anchored_at,
			finalized_at,
			updated_at
		FROM finality_state
		WHERE system_id = ?;
	`

	err := r.session.Query(
		query,
		systemID,
	).ScanContext(
		ctx,
		&state.SystemID,
		&state.FinalizedCheckpointID,
		&state.CheckpointSequence,
		&state.LocatorTreeID,
		&state.LocatorRoot,
		&state.GlobalHMFRoot,
		&state.StateCommitment,
		&state.BlockchainTxHash,
		&state.BlockchainBlockHeight,
		&state.AnchoredAt,
		&state.FinalizedAt,
		&state.UpdatedAt,
	)

	if err != nil {
		return FinalityState{}, fmt.Errorf("get finality state %s: %w", systemID, err)
	}

	return state, nil
}
