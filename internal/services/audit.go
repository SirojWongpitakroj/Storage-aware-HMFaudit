package services

import (
	"context"
	"errors"
	"fmt"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
	"github.com/SirojWongpitakroj/hmf-audit/internal/checkpoint"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
)

var ErrCheckpointChanged = errors.New("audit checkpoint changed")

type CheckpointReader interface {
	Current(ctx context.Context) (checkpoint.Checkpoint, error)
}

type LocatorResolver interface {
	ResolveLocatorQuery(ctx context.Context, treeID string, trustedRoot [32]byte,
		query locator.LocatorQuery) (locator.LocatorRangeResult, error)
}

type HMFProofService interface {
	BuildAndVerify(ctx context.Context, addresses []hpp.PhysicalAddress,
		trustedRoot [32]byte) (hpp.VerificationResult, error)
}

type LocalizationService interface {
	Localize(ctx context.Context, request localization.Request) (localization.Result, error)
}

type AuditService struct {
	checkpoints CheckpointReader
	locator     LocatorResolver
	hmfProof    HMFProofService
	localizer   LocalizationService
}

type LocatorAuditResult struct {
	Checkpoint checkpoint.Checkpoint
	Range      locator.LocatorRangeResult
}

type HMFAuditResult struct {
	Checkpoint checkpoint.Checkpoint
	HMF        hpp.VerificationResult
}

type LocalizationAuditResult struct {
	Checkpoint   checkpoint.Checkpoint
	Localization localization.Result
}

func NewAuditService(checkpoints CheckpointReader, locatorResolver LocatorResolver,
	hmfProof HMFProofService, localizers ...LocalizationService) (*AuditService, error) {

	if checkpoints == nil {
		return nil, fmt.Errorf("new audit service: checkpoint reader is nil")
	}
	if locatorResolver == nil {
		return nil, fmt.Errorf("new audit service: locator resolver is nil")
	}
	if hmfProof == nil {
		return nil, fmt.Errorf("new audit service: HMF proof service is nil")
	}
	var localizer LocalizationService
	if len(localizers) > 1 {
		return nil, fmt.Errorf("new audit service: at most one localization service is allowed")
	}
	if len(localizers) == 1 {
		if localizers[0] == nil {
			return nil, fmt.Errorf("new audit service: localization service is nil")
		}
		localizer = localizers[0]
	}
	return &AuditService{
		checkpoints: checkpoints, locator: locatorResolver, hmfProof: hmfProof, localizer: localizer,
	}, nil
}

// LocalizeTamper authenticates the Cassandra reference proof against the same
// finalized checkpoint used by the failed auditor computation.
func (service *AuditService) LocalizeTamper(ctx context.Context, checkpointSequence int64,
	auditorRoot [32]byte, failedProof hpp.HMFProof, addresses []hpp.PhysicalAddress,
	k int32) (LocalizationAuditResult, error) {

	if service.localizer == nil {
		return LocalizationAuditResult{}, fmt.Errorf("localize audit tamper: localization is unavailable")
	}
	if checkpointSequence <= 0 {
		return LocalizationAuditResult{}, fmt.Errorf("localize audit tamper: checkpoint sequence must be positive")
	}
	trusted, err := service.checkpoints.Current(ctx)
	if err != nil {
		return LocalizationAuditResult{}, fmt.Errorf("localize audit tamper: %w", err)
	}
	if trusted.Sequence != checkpointSequence {
		return LocalizationAuditResult{}, fmt.Errorf("%w: requested sequence %d, current sequence %d",
			ErrCheckpointChanged, checkpointSequence, trusted.Sequence)
	}
	result, err := service.localizer.Localize(ctx, localization.Request{
		Addresses: addresses, AuditorGlobalRoot: auditorRoot, FailedProof: failedProof,
		AnchoredGlobalRoot: trusted.GlobalHMFRoot, K: k,
	})
	if err != nil {
		return LocalizationAuditResult{}, fmt.Errorf("localize audit tamper: %w", err)
	}
	if err := service.ensureStillCurrent(ctx, trusted); err != nil {
		return LocalizationAuditResult{}, err
	}
	return LocalizationAuditResult{Checkpoint: trusted, Localization: result}, nil
}

func (service *AuditService) CurrentCheckpoint(ctx context.Context) (checkpoint.Checkpoint, error) {
	return service.checkpoints.Current(ctx)
}

// ResolveLocator returns the ALL range proof bound to the current finalized
// locator root. The auditor must verify this proof before submitting addresses.
func (service *AuditService) ResolveLocator(ctx context.Context,
	query locator.LocatorQuery) (LocatorAuditResult, error) {

	trusted, err := service.checkpoints.Current(ctx)
	if err != nil {
		return LocatorAuditResult{}, fmt.Errorf("resolve audit locator: %w", err)
	}
	result, err := service.locator.ResolveLocatorQuery(
		ctx, trusted.LocatorTreeID, trusted.LocatorRoot, query,
	)
	if err != nil {
		return LocatorAuditResult{}, fmt.Errorf("resolve audit locator: %w", err)
	}
	if err := service.ensureStillCurrent(ctx, trusted); err != nil {
		return LocatorAuditResult{}, err
	}
	return LocatorAuditResult{Checkpoint: trusted, Range: result}, nil
}

// BuildHMFProof accepts only addresses that the auditor has authenticated with
// the ALL proof. It pins the request to checkpointSequence and verifies R_G'
// before returning the self-contained HMF proof.
func (service *AuditService) BuildHMFProof(ctx context.Context, checkpointSequence int64,
	addresses []hpp.PhysicalAddress) (HMFAuditResult, error) {

	if checkpointSequence <= 0 {
		return HMFAuditResult{}, fmt.Errorf("build audit HMF proof: checkpoint sequence must be positive")
	}
	trusted, err := service.checkpoints.Current(ctx)
	if err != nil {
		return HMFAuditResult{}, fmt.Errorf("build audit HMF proof: %w", err)
	}
	if trusted.Sequence != checkpointSequence {
		return HMFAuditResult{}, fmt.Errorf("%w: requested sequence %d, current sequence %d",
			ErrCheckpointChanged, checkpointSequence, trusted.Sequence)
	}
	result, err := service.hmfProof.BuildAndVerify(ctx, addresses, trusted.GlobalHMFRoot)
	if err != nil {
		return HMFAuditResult{}, fmt.Errorf("build audit HMF proof: %w", err)
	}
	if err := service.ensureStillCurrent(ctx, trusted); err != nil {
		return HMFAuditResult{}, err
	}
	return HMFAuditResult{Checkpoint: trusted, HMF: result}, nil
}

func (service *AuditService) ensureStillCurrent(ctx context.Context,
	started checkpoint.Checkpoint) error {

	current, err := service.checkpoints.Current(ctx)
	if err != nil {
		return fmt.Errorf("confirm audit checkpoint: %w", err)
	}
	if current.Sequence != started.Sequence || current.StateCommitment != started.StateCommitment {
		return fmt.Errorf("%w: started at sequence %d, current sequence %d",
			ErrCheckpointChanged, started.Sequence, current.Sequence)
	}
	return nil
}
