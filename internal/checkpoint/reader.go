package checkpoint

import (
	"context"
	"fmt"
)

// Reader exposes the current finalized checkpoint without requiring the
// checkpoint-creation dependencies used by Service.
type Reader struct {
	systemID string
	repo     Repository
}

func NewReader(systemID string, repository Repository) (*Reader, error) {
	if systemID == "" {
		return nil, fmt.Errorf("new checkpoint reader: system ID is required")
	}
	if repository == nil {
		return nil, fmt.Errorf("new checkpoint reader: repository is nil")
	}
	return &Reader{systemID: systemID, repo: repository}, nil
}

func (reader *Reader) Current(ctx context.Context) (Checkpoint, error) {
	return readCurrent(ctx, reader.repo, reader.systemID)
}

func readCurrent(ctx context.Context, repository Repository,
	systemID string) (Checkpoint, error) {

	value, err := repository.CurrentFinalized(ctx, systemID)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("current checkpoint: %w", err)
	}
	if err := validateStoredCheckpoint(value, systemID); err != nil {
		return Checkpoint{}, err
	}
	if value.Status != StatusFinalized || value.Anchor == nil || value.FinalizedAt == nil {
		return Checkpoint{}, fmt.Errorf("current checkpoint: repository returned a non-finalized checkpoint")
	}
	return value, nil
}
