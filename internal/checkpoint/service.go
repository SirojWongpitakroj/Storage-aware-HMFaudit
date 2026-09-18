package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"
)

type Service struct {
	systemID string
	source   StateSource
	anchor   Anchor
	repo     Repository
	clock    func() time.Time
	lock     chan struct{}
}

func NewService(systemID string, source StateSource, anchor Anchor,
	repository Repository) (*Service, error) {

	if systemID == "" {
		return nil, fmt.Errorf("new checkpoint service: system ID is required")
	}
	if source == nil {
		return nil, fmt.Errorf("new checkpoint service: state source is nil")
	}
	if anchor == nil {
		return nil, fmt.Errorf("new checkpoint service: anchor is nil")
	}
	if repository == nil {
		return nil, fmt.Errorf("new checkpoint service: repository is nil")
	}
	return &Service{
		systemID: systemID,
		source:   source,
		anchor:   anchor,
		repo:     repository,
		clock:    time.Now,
		lock:     make(chan struct{}, 1),
	}, nil
}

// Finalize captures one coordinated state or resumes the latest pending
// checkpoint, anchors its commitment, then publishes it as current.
func (service *Service) Finalize(ctx context.Context) (Checkpoint, error) {
	if err := service.acquire(ctx); err != nil {
		return Checkpoint{}, err
	}
	defer service.release()

	latest, err := service.repo.LatestCheckpoint(ctx, service.systemID)
	switch {
	case err == nil:
		if err := validateStoredCheckpoint(latest, service.systemID); err != nil {
			return Checkpoint{}, err
		}
		if latest.Status == StatusPending {
			return service.anchorAndPublish(ctx, latest)
		}
		if latest.Status != StatusFinalized {
			return Checkpoint{}, fmt.Errorf("finalize checkpoint: unsupported latest status %q", latest.Status)
		}
		current, currentErr := service.repo.CurrentFinalized(ctx, service.systemID)
		if currentErr == nil {
			if err := validateStoredCheckpoint(current, service.systemID); err != nil {
				return Checkpoint{}, err
			}
			if current.Status != StatusFinalized {
				return Checkpoint{}, fmt.Errorf("finalize checkpoint: current checkpoint is not finalized")
			}
			if current.Sequence > latest.Sequence {
				return Checkpoint{}, fmt.Errorf("finalize checkpoint: current sequence exceeds latest history")
			}
			if current.Sequence == latest.Sequence && current.StateCommitment != latest.StateCommitment {
				return Checkpoint{}, fmt.Errorf("finalize checkpoint: current state conflicts with latest history")
			}
		}
		if currentErr != nil && !errors.Is(currentErr, ErrNotFound) {
			return Checkpoint{}, fmt.Errorf("finalize checkpoint: load current finality: %w", currentErr)
		}
		if errors.Is(currentErr, ErrNotFound) || current.Sequence < latest.Sequence {
			if err := service.repo.PublishFinalized(ctx, latest); err != nil {
				return Checkpoint{}, fmt.Errorf("finalize checkpoint: recover finality publication: %w", err)
			}
			return latest, nil
		}
		if latest.Sequence == math.MaxInt64 {
			return Checkpoint{}, fmt.Errorf("finalize checkpoint: sequence exhausted")
		}
	case errors.Is(err, ErrNotFound):
		latest.Sequence = 0
	case err != nil:
		return Checkpoint{}, fmt.Errorf("finalize checkpoint: load latest: %w", err)
	}

	snapshot, err := service.source.Snapshot(ctx)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("finalize checkpoint: snapshot coordinated roots: %w", err)
	}
	if snapshot.LocatorTreeID == "" {
		return Checkpoint{}, fmt.Errorf("finalize checkpoint: locator tree ID is required")
	}
	sequence := latest.Sequence + 1
	commitment, err := StateCommitment(sequence, snapshot.LocatorRoot, snapshot.GlobalHMFRoot)
	if err != nil {
		return Checkpoint{}, err
	}
	createdAt := service.clock().UTC()
	pending := Checkpoint{
		SystemID:        service.systemID,
		Sequence:        sequence,
		LocatorTreeID:   snapshot.LocatorTreeID,
		LocatorRoot:     snapshot.LocatorRoot,
		GlobalHMFRoot:   snapshot.GlobalHMFRoot,
		StateCommitment: commitment,
		Status:          StatusPending,
		CreatedAt:       createdAt,
	}
	stored, err := service.repo.SavePending(ctx, pending)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("finalize checkpoint: persist pending checkpoint: %w", err)
	}
	if err := validateStoredCheckpoint(stored, service.systemID); err != nil {
		return Checkpoint{}, fmt.Errorf("finalize checkpoint: repository returned invalid pending checkpoint: %w", err)
	}
	if stored.Status != StatusPending || stored.Sequence != pending.Sequence ||
		stored.LocatorTreeID != pending.LocatorTreeID || stored.LocatorRoot != pending.LocatorRoot ||
		stored.GlobalHMFRoot != pending.GlobalHMFRoot || stored.StateCommitment != pending.StateCommitment {
		return Checkpoint{}, fmt.Errorf("finalize checkpoint: repository changed pending checkpoint contents")
	}
	return service.anchorAndPublish(ctx, stored)
}

// Current returns only the published checkpoint trusted by readers. A pending
// checkpoint never replaces the current finalized checkpoint.
func (service *Service) Current(ctx context.Context) (Checkpoint, error) {
	return readCurrent(ctx, service.repo, service.systemID)
}

func (service *Service) anchorAndPublish(ctx context.Context,
	pending Checkpoint) (Checkpoint, error) {

	receipt, err := service.anchor.Commit(ctx, pending.StateCommitment)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("finalize checkpoint: anchor commitment: %w", err)
	}
	if err := validateReceipt(receipt); err != nil {
		return Checkpoint{}, err
	}
	finalizedAt := service.clock().UTC()
	result := pending
	result.Status = StatusFinalized
	result.Anchor = &receipt
	result.FinalizedAt = &finalizedAt
	if err := service.repo.PublishFinalized(ctx, result); err != nil {
		return Checkpoint{}, fmt.Errorf("finalize checkpoint: publish finalized checkpoint: %w", err)
	}
	return result, nil
}

func (service *Service) acquire(ctx context.Context) error {
	select {
	case service.lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (service *Service) release() {
	<-service.lock
}

func validateStoredCheckpoint(value Checkpoint, systemID string) error {
	if value.SystemID != systemID {
		return fmt.Errorf("%w: system ID %q does not match %q", ErrInvalidCheckpoint, value.SystemID, systemID)
	}
	if value.ID == "" || value.Sequence <= 0 || value.LocatorTreeID == "" || value.CreatedAt.IsZero() {
		return fmt.Errorf("%w: required checkpoint metadata is missing", ErrInvalidCheckpoint)
	}
	if err := VerifyStateCommitment(value); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCheckpoint, err)
	}
	switch value.Status {
	case StatusPending:
		if value.Anchor != nil || value.FinalizedAt != nil {
			return fmt.Errorf("%w: pending checkpoint contains finality metadata", ErrInvalidCheckpoint)
		}
	case StatusFinalized:
		if value.Anchor == nil || value.FinalizedAt == nil {
			return fmt.Errorf("%w: finalized checkpoint lacks finality metadata", ErrInvalidCheckpoint)
		}
		if err := validateReceipt(*value.Anchor); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidCheckpoint, err)
		}
	default:
		return fmt.Errorf("%w: unsupported status %q", ErrInvalidCheckpoint, value.Status)
	}
	return nil
}

func validateReceipt(receipt AnchorReceipt) error {
	if receipt.TransactionHash == "" {
		return fmt.Errorf("finalize checkpoint: anchor returned an empty transaction hash")
	}
	if receipt.BlockHeight < 0 {
		return fmt.Errorf("finalize checkpoint: anchor returned a negative block height")
	}
	if receipt.AnchoredAt.IsZero() {
		return fmt.Errorf("finalize checkpoint: anchor returned an empty timestamp")
	}
	return nil
}
