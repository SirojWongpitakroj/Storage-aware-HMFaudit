package services

import (
	"context"
	"errors"
	"testing"
	"time"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
	"github.com/SirojWongpitakroj/hmf-audit/internal/checkpoint"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
)

func TestAuditServicePinsBothProofStagesToCheckpoint(t *testing.T) {
	trusted := finalizedCheckpoint(7)
	checkpoints := &sequenceCheckpointReader{values: []checkpoint.Checkpoint{trusted, trusted, trusted, trusted}}
	locatorReader := &recordingLocatorResolver{}
	hmfReader := &recordingHMFService{result: hpp.VerificationResult{
		CalculatedGlobalRoot: trusted.GlobalHMFRoot,
	}}
	localizer := &recordingLocalizationService{result: localization.Result{
		CalculatedReferenceRoot: trusted.GlobalHMFRoot,
	}}
	service, err := NewAuditService(checkpoints, locatorReader, hmfReader, localizer)
	if err != nil {
		t.Fatalf("new audit service: %v", err)
	}
	query := locator.LocatorQuery{
		TenantID: "tenant", ServiceID: "service", LogType: "audit", RegionID: "R0",
		StartTime: time.Now().Add(-time.Hour), EndTime: time.Now(),
	}
	locatorResult, err := service.ResolveLocator(context.Background(), query)
	if err != nil {
		t.Fatalf("resolve locator: %v", err)
	}
	if locatorResult.Checkpoint.Sequence != trusted.Sequence ||
		locatorReader.treeID != trusted.LocatorTreeID || locatorReader.root != trusted.LocatorRoot {
		t.Fatal("locator proof was not pinned to the trusted locator checkpoint")
	}
	addresses := []hpp.PhysicalAddress{{RegionID: "R0", ShardID: 1, SegmentID: 2, LeafID: 3}}
	hmfResult, err := service.BuildHMFProof(context.Background(), trusted.Sequence, addresses)
	if err != nil {
		t.Fatalf("build HMF proof: %v", err)
	}
	if hmfResult.Checkpoint.Sequence != trusted.Sequence || hmfReader.root != trusted.GlobalHMFRoot {
		t.Fatal("HMF proof was not pinned to the trusted global checkpoint")
	}
	if len(hmfReader.addresses) != 1 || hmfReader.addresses[0] != addresses[0] {
		t.Fatalf("HMF addresses = %+v, want %+v", hmfReader.addresses, addresses)
	}
	failedRoot := testHash("failed")
	localized, err := service.LocalizeTamper(context.Background(), trusted.Sequence,
		failedRoot, hpp.HMFProof{}, addresses, localization.DefaultJumpLevels)
	if err != nil {
		t.Fatalf("localize tamper: %v", err)
	}
	if localized.Checkpoint.Sequence != trusted.Sequence || localizer.request.K != localization.DefaultJumpLevels ||
		localizer.request.AuditorGlobalRoot != failedRoot ||
		localizer.request.AnchoredGlobalRoot != trusted.GlobalHMFRoot {
		t.Fatal("localization was not pinned to the trusted global checkpoint")
	}
}

func TestAuditServiceRejectsStaleOrChangingCheckpoint(t *testing.T) {
	trusted := finalizedCheckpoint(7)
	t.Run("stale HMF request", func(t *testing.T) {
		hmfReader := &recordingHMFService{}
		service, err := NewAuditService(
			&sequenceCheckpointReader{values: []checkpoint.Checkpoint{trusted}},
			&recordingLocatorResolver{}, hmfReader,
		)
		if err != nil {
			t.Fatalf("new audit service: %v", err)
		}
		_, err = service.BuildHMFProof(context.Background(), 6,
			[]hpp.PhysicalAddress{{RegionID: "R0"}})
		if !errors.Is(err, ErrCheckpointChanged) {
			t.Fatalf("build error = %v, want %v", err, ErrCheckpointChanged)
		}
		if hmfReader.calls != 0 {
			t.Fatal("HMF proof builder ran for a stale checkpoint")
		}
	})

	t.Run("checkpoint changes during locator read", func(t *testing.T) {
		newer := finalizedCheckpoint(8)
		service, err := NewAuditService(
			&sequenceCheckpointReader{values: []checkpoint.Checkpoint{trusted, newer}},
			&recordingLocatorResolver{}, &recordingHMFService{},
		)
		if err != nil {
			t.Fatalf("new audit service: %v", err)
		}
		_, err = service.ResolveLocator(context.Background(), locator.LocatorQuery{})
		if !errors.Is(err, ErrCheckpointChanged) {
			t.Fatalf("resolve error = %v, want %v", err, ErrCheckpointChanged)
		}
	})
}

type sequenceCheckpointReader struct {
	values []checkpoint.Checkpoint
	index  int
}

func (reader *sequenceCheckpointReader) Current(context.Context) (checkpoint.Checkpoint, error) {
	if len(reader.values) == 0 {
		return checkpoint.Checkpoint{}, errors.New("no checkpoint")
	}
	index := reader.index
	if index >= len(reader.values) {
		index = len(reader.values) - 1
	}
	reader.index++
	return reader.values[index], nil
}

type recordingLocatorResolver struct {
	treeID string
	root   [32]byte
}

func (reader *recordingLocatorResolver) ResolveLocatorQuery(_ context.Context, treeID string,
	root [32]byte, _ locator.LocatorQuery) (locator.LocatorRangeResult, error) {
	reader.treeID = treeID
	reader.root = root
	return locator.LocatorRangeResult{}, nil
}

type recordingHMFService struct {
	addresses []hpp.PhysicalAddress
	root      [32]byte
	result    hpp.VerificationResult
	calls     int
}

type recordingLocalizationService struct {
	request localization.Request
	result  localization.Result
	err     error
}

func (service *recordingLocalizationService) Localize(_ context.Context,
	request localization.Request) (localization.Result, error) {
	service.request = request
	return service.result, service.err
}

func (service *recordingHMFService) BuildAndVerify(_ context.Context,
	addresses []hpp.PhysicalAddress, root [32]byte) (hpp.VerificationResult, error) {
	service.calls++
	service.addresses = append([]hpp.PhysicalAddress(nil), addresses...)
	service.root = root
	return service.result, nil
}

func finalizedCheckpoint(sequence int64) checkpoint.Checkpoint {
	locatorRoot := testHash("locator")
	globalRoot := testHash("global")
	commitment, _ := checkpoint.StateCommitment(sequence, locatorRoot, globalRoot)
	now := time.Now().UTC()
	return checkpoint.Checkpoint{
		ID: "checkpoint", SystemID: "test", Sequence: sequence,
		LocatorTreeID: "ALL", LocatorRoot: locatorRoot, GlobalHMFRoot: globalRoot,
		StateCommitment: commitment, Status: checkpoint.StatusFinalized,
		Anchor:    &checkpoint.AnchorReceipt{TransactionHash: "0x1", BlockHeight: 1, AnchoredAt: now},
		CreatedAt: now, FinalizedAt: &now,
	}
}

func testHash(value string) [32]byte {
	var result [32]byte
	copy(result[:], []byte(value))
	return result
}
