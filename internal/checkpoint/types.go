// Package checkpoint turns coordinated ALL and HMF roots into finalized,
// externally anchored checkpoints.
package checkpoint

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound          = errors.New("checkpoint not found")
	ErrInvalidCheckpoint = errors.New("invalid checkpoint")
)

type Status string

const (
	StatusPending   Status = "PENDING"
	StatusFinalized Status = "FINALIZED"
)

// RootSnapshot must contain roots captured at one coordinated finalization
// boundary. Implementations must not read the ALL and HMF roots independently.
type RootSnapshot struct {
	LocatorTreeID string
	LocatorRoot   [32]byte
	GlobalHMFRoot [32]byte
}

type AnchorReceipt struct {
	TransactionHash string
	BlockHeight     int64
	AnchoredAt      time.Time
}

type Checkpoint struct {
	ID              string
	SystemID        string
	Sequence        int64
	LocatorTreeID   string
	LocatorRoot     [32]byte
	GlobalHMFRoot   [32]byte
	StateCommitment [32]byte
	Status          Status
	Anchor          *AnchorReceipt
	CreatedAt       time.Time
	FinalizedAt     *time.Time
}

// StateSource atomically snapshots the coordinated working roots.
type StateSource interface {
	Snapshot(ctx context.Context) (RootSnapshot, error)
}

// Anchor submits a commitment and returns only after the mock or external
// anchor considers it committed. Commit must be idempotent per commitment.
type Anchor interface {
	Commit(ctx context.Context, commitment [32]byte) (AnchorReceipt, error)
}

// Repository stores pending work and publishes a finalized checkpoint as the
// current trusted state. Latest must include a pending checkpoint so a failed
// anchor operation can be resumed without allocating another sequence.
type Repository interface {
	LatestCheckpoint(ctx context.Context, systemID string) (Checkpoint, error)
	CurrentFinalized(ctx context.Context, systemID string) (Checkpoint, error)
	SavePending(ctx context.Context, value Checkpoint) (Checkpoint, error)
	PublishFinalized(ctx context.Context, value Checkpoint) error
}
