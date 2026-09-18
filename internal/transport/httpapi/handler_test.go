package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
	"github.com/SirojWongpitakroj/hmf-audit/internal/checkpoint"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/services"
)

func TestHandlerServesLocatorAndHMFProofs(t *testing.T) {
	trusted := httpCheckpoint()
	service := &fakeAuditService{
		checkpoint: trusted,
		locator: services.LocatorAuditResult{
			Checkpoint: trusted,
			Range: locator.LocatorRangeResult{Proof: locator.LocatorRangeProof{
				ReconstructedRoot: trusted.LocatorRoot,
			}},
		},
		hmf: services.HMFAuditResult{
			Checkpoint: trusted,
			HMF:        hpp.VerificationResult{CalculatedGlobalRoot: trusted.GlobalHMFRoot},
		},
	}
	handler, err := NewHandler(service, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	locatorBody := `{
		"tenant_id":"tenant","service_id":"service","log_type":"audit","region_id":"R0",
		"start_time":"2026-01-01T00:00:00Z","end_time":"2026-01-02T00:00:00Z"
	}`
	locatorRecorder := httptest.NewRecorder()
	handler.ServeHTTP(locatorRecorder, httptest.NewRequest(
		http.MethodPost, "/v1/audits/locator-proof", strings.NewReader(locatorBody),
	))
	if locatorRecorder.Code != http.StatusOK {
		t.Fatalf("locator status = %d, body=%s", locatorRecorder.Code, locatorRecorder.Body.String())
	}
	if !strings.Contains(locatorRecorder.Body.String(), hashHex(trusted.LocatorRoot)) {
		t.Fatalf("locator response omitted hexadecimal root: %s", locatorRecorder.Body.String())
	}

	hmfBody := `{
		"checkpoint_sequence":4,
		"addresses":[{"region_id":"R0","shard_id":1,"segment_id":2,"leaf_id":3}]
	}`
	hmfRecorder := httptest.NewRecorder()
	handler.ServeHTTP(hmfRecorder, httptest.NewRequest(
		http.MethodPost, "/v1/audits/hmf-proof", strings.NewReader(hmfBody),
	))
	if hmfRecorder.Code != http.StatusOK {
		t.Fatalf("HMF status = %d, body=%s", hmfRecorder.Code, hmfRecorder.Body.String())
	}
	if service.hmfSequence != 4 || len(service.hmfAddresses) != 1 {
		t.Fatalf("HMF request = sequence %d addresses %+v", service.hmfSequence, service.hmfAddresses)
	}
	if !strings.Contains(hmfRecorder.Body.String(), hashHex(trusted.GlobalHMFRoot)) {
		t.Fatalf("HMF response omitted hexadecimal root: %s", hmfRecorder.Body.String())
	}

	localizeBody, err := json.Marshal(localizationRequest{
		CheckpointSequence: 4, AuditorGlobalRoot: hashHex([32]byte{9}), K: 15,
		Addresses:   []physicalAddress{{RegionID: "R0", ShardID: 1, SegmentID: 2, LeafID: 3}},
		FailedProof: hmfProof{},
	})
	if err != nil {
		t.Fatalf("marshal localization request: %v", err)
	}
	localizeRecorder := httptest.NewRecorder()
	handler.ServeHTTP(localizeRecorder, httptest.NewRequest(
		http.MethodPost, "/v1/audits/localize", bytes.NewReader(localizeBody),
	))
	if localizeRecorder.Code != http.StatusOK {
		t.Fatalf("localization status = %d, body=%s", localizeRecorder.Code, localizeRecorder.Body.String())
	}
	if service.localizationK != 15 || service.localizationSequence != 4 {
		t.Fatalf("localization request = sequence %d k %d", service.localizationSequence, service.localizationK)
	}
}

func TestHandlerRejectsInvalidRequestsAndReportsDependencyState(t *testing.T) {
	trusted := httpCheckpoint()
	service := &fakeAuditService{checkpoint: trusted, hmfErr: services.ErrCheckpointChanged}
	handler, err := NewHandler(service, func(context.Context) error { return errors.New("Cassandra unavailable") })
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status = %d, want %d", ready.Code, http.StatusServiceUnavailable)
	}

	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, httptest.NewRequest(http.MethodPost,
		"/v1/audits/hmf-proof", bytes.NewBufferString(`{"unknown":true}`)))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid request status = %d, want %d", invalid.Code, http.StatusBadRequest)
	}

	stale := httptest.NewRecorder()
	handler.ServeHTTP(stale, httptest.NewRequest(http.MethodPost,
		"/v1/audits/hmf-proof", bytes.NewBufferString(`{
			"checkpoint_sequence":3,
			"addresses":[{"region_id":"R0","shard_id":0,"segment_id":0,"leaf_id":0}]
		}`)))
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale request status = %d, body=%s", stale.Code, stale.Body.String())
	}

	service.checkpointErr = checkpoint.ErrNotFound
	current := httptest.NewRecorder()
	handler.ServeHTTP(current, httptest.NewRequest(http.MethodGet, "/v1/checkpoints/current", nil))
	if current.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing checkpoint status = %d, body=%s", current.Code, current.Body.String())
	}
}

type fakeAuditService struct {
	checkpoint           checkpoint.Checkpoint
	checkpointErr        error
	locator              services.LocatorAuditResult
	locatorErr           error
	hmf                  services.HMFAuditResult
	hmfErr               error
	hmfSequence          int64
	hmfAddresses         []hpp.PhysicalAddress
	localizationSequence int64
	localizationK        int32
}

func (service *fakeAuditService) LocalizeTamper(_ context.Context, sequence int64, _ [32]byte,
	_ hpp.HMFProof, _ []hpp.PhysicalAddress, k int32) (services.LocalizationAuditResult, error) {
	service.localizationSequence = sequence
	service.localizationK = k
	return services.LocalizationAuditResult{Checkpoint: service.checkpoint}, nil
}

func (service *fakeAuditService) CurrentCheckpoint(context.Context) (checkpoint.Checkpoint, error) {
	return service.checkpoint, service.checkpointErr
}

func (service *fakeAuditService) ResolveLocator(context.Context,
	locator.LocatorQuery) (services.LocatorAuditResult, error) {
	return service.locator, service.locatorErr
}

func (service *fakeAuditService) BuildHMFProof(_ context.Context, sequence int64,
	addresses []hpp.PhysicalAddress) (services.HMFAuditResult, error) {
	service.hmfSequence = sequence
	service.hmfAddresses = append([]hpp.PhysicalAddress(nil), addresses...)
	return service.hmf, service.hmfErr
}

func httpCheckpoint() checkpoint.Checkpoint {
	locatorRoot := [32]byte{1, 2, 3}
	globalRoot := [32]byte{4, 5, 6}
	commitment, _ := checkpoint.StateCommitment(4, locatorRoot, globalRoot)
	now := time.Now().UTC()
	return checkpoint.Checkpoint{
		ID: "checkpoint", SystemID: "test", Sequence: 4, LocatorTreeID: "ALL",
		LocatorRoot: locatorRoot, GlobalHMFRoot: globalRoot, StateCommitment: commitment,
		Status:    checkpoint.StatusFinalized,
		Anchor:    &checkpoint.AnchorReceipt{TransactionHash: "0x1", BlockHeight: 1, AnchoredAt: now},
		CreatedAt: now, FinalizedAt: &now,
	}
}
