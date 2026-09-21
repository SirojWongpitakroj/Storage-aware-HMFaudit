package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
	"github.com/SirojWongpitakroj/hmf-audit/internal/checkpoint"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
	"github.com/SirojWongpitakroj/hmf-audit/internal/services"
)

const maxRequestBytes int64 = 1 << 20

type AuditService interface {
	CurrentCheckpoint(ctx context.Context) (checkpoint.Checkpoint, error)
	ResolveLocator(ctx context.Context, query locator.LocatorQuery) (services.LocatorAuditResult, error)
	BuildHMFProof(ctx context.Context, checkpointSequence int64,
		addresses []hpp.PhysicalAddress) (services.HMFAuditResult, error)
	LocalizeTamper(ctx context.Context, checkpointSequence int64, auditorRoot [32]byte,
		failedProof hpp.HMFProof, addresses []hpp.PhysicalAddress,
		k int32) (services.LocalizationAuditResult, error)
}

type ReadinessCheck func(ctx context.Context) error

type Handler struct {
	service AuditService
	ready   ReadinessCheck
}

func NewHandler(service AuditService, ready ReadinessCheck) (http.Handler, error) {
	if service == nil {
		return nil, fmt.Errorf("new audit HTTP handler: service is nil")
	}
	if ready == nil {
		return nil, fmt.Errorf("new audit HTTP handler: readiness check is nil")
	}
	handler := &Handler{service: service, ready: ready}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handler.health)
	mux.HandleFunc("/readyz", handler.readiness)
	mux.HandleFunc("/v1/checkpoints/current", handler.currentCheckpoint)
	mux.HandleFunc("/v1/audits/locator-proof", handler.locatorProof)
	mux.HandleFunc("/v1/audits/hmf-proof", handler.hmfProof)
	mux.HandleFunc("/v1/audits/localize", handler.localize)
	return mux, nil
}

type locatorProofRequest struct {
	TenantID  string    `json:"tenant_id"`
	ServiceID string    `json:"service_id"`
	LogType   string    `json:"log_type"`
	RegionID  string    `json:"region_id"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

type hmfProofRequest struct {
	CheckpointSequence int64             `json:"checkpoint_sequence"`
	Addresses          []physicalAddress `json:"addresses"`
}

type localizationRequest struct {
	CheckpointSequence int64             `json:"checkpoint_sequence"`
	AuditorGlobalRoot  string            `json:"auditor_global_root"`
	K                  int32             `json:"k"`
	Addresses          []physicalAddress `json:"addresses"`
	FailedProof        hmfProof          `json:"failed_proof"`
}

type physicalAddress struct {
	RegionID  string `json:"region_id"`
	ShardID   int64  `json:"shard_id"`
	SegmentID int64  `json:"segment_id"`
	LeafID    int64  `json:"leaf_id"`
}

type checkpointResponse struct {
	ID              string                    `json:"id"`
	SystemID        string                    `json:"system_id"`
	Sequence        int64                     `json:"sequence"`
	LocatorTreeID   string                    `json:"locator_tree_id"`
	LocatorRoot     string                    `json:"locator_root"`
	GlobalHMFRoot   string                    `json:"global_hmf_root"`
	StateCommitment string                    `json:"state_commitment"`
	Status          checkpoint.Status         `json:"status"`
	Anchor          *checkpoint.AnchorReceipt `json:"anchor,omitempty"`
	CreatedAt       time.Time                 `json:"created_at"`
	FinalizedAt     *time.Time                `json:"finalized_at,omitempty"`
}

type locatorProofResponse struct {
	Checkpoint checkpointResponse    `json:"checkpoint"`
	Result     locatorResultResponse `json:"result"`
}

type locatorResultResponse struct {
	Entries     []locator.LocatorEntry `json:"entries"`
	Predecessor *locator.LocatorEntry  `json:"predecessor,omitempty"`
	Successor   *locator.LocatorEntry  `json:"successor,omitempty"`
	Proof       locatorRangeProof      `json:"proof"`
}

type locatorRangeProof struct {
	Leaves            []locatorLeafProof `json:"leaves"`
	ReconstructedRoot string             `json:"reconstructed_root"`
}

type locatorLeafProof struct {
	PageID     int64                      `json:"page_id"`
	NextPageID *int64                     `json:"next_page_id,omitempty"`
	Keys       []locator.LocatorKey       `json:"keys"`
	Values     []*locator.LocatorValue    `json:"values"`
	Path       []locatorProofStepResponse `json:"path"`
}

type locatorProofStepResponse struct {
	PageID      int64                `json:"page_id"`
	Keys        []locator.LocatorKey `json:"keys"`
	ChildIndex  int                  `json:"child_index"`
	ChildHashes []string             `json:"child_hashes"`
}

type hmfProofResponse struct {
	Checkpoint           checkpointResponse `json:"checkpoint"`
	CalculatedGlobalRoot string             `json:"calculated_global_root"`
	Proof                hmfProof           `json:"proof"`
}

type localizationResponse struct {
	Checkpoint              checkpointResponse        `json:"checkpoint"`
	CalculatedReferenceRoot string                    `json:"calculated_reference_root"`
	Proof                   localizationProofResponse `json:"proof"`
}

type localizationProofResponse struct {
	AnchoredGlobalRoot  string                        `json:"anchored_global_root"`
	AuditorGlobalRoot   string                        `json:"auditor_global_root"`
	ReferenceGlobalRoot string                        `json:"reference_global_root"`
	K                   int32                         `json:"k"`
	Addresses           []hpp.PhysicalAddress         `json:"addresses"`
	FailedProof         hmfProof                      `json:"failed_proof"`
	ReferenceProof      hmfProof                      `json:"reference_proof"`
	BadShards           []hpp.TreeRef                 `json:"bad_shards"`
	Rounds              []localizationRoundResponse   `json:"rounds"`
	Suspects            []localizationSuspectResponse `json:"suspects"`
}

type localizationRoundResponse struct {
	Tree        hpp.TreeRef                      `json:"tree"`
	FromLevel   int32                            `json:"from_level"`
	TargetLevel int32                            `json:"target_level"`
	Comparisons []localizationComparisonResponse `json:"comparisons"`
}

type localizationComparisonResponse struct {
	Ref           hpp.NodeRef `json:"ref"`
	AuditorHash   string      `json:"auditor_hash"`
	ReferenceHash string      `json:"reference_hash"`
	Match         bool        `json:"match"`
}

type localizationSuspectResponse struct {
	Ref            hpp.NodeRef                 `json:"ref"`
	Address        *hpp.PhysicalAddress        `json:"address,omitempty"`
	AuditorHash    string                      `json:"auditor_hash"`
	ReferenceHash  string                      `json:"reference_hash"`
	Classification localization.Classification `json:"classification"`
}

type hmfProof struct {
	Plan   hpp.ProofPlan     `json:"plan"`
	Leaves []hmfLeafResponse `json:"leaves"`
	Nodes  []hmfNodeResponse `json:"nodes"`
}

type hmfLeafResponse struct {
	Address hpp.PhysicalAddress `json:"address"`
	Hash    string              `json:"hash"`
}

type hmfNodeResponse struct {
	Ref  hpp.NodeRef `json:"ref"`
	Hash string      `json:"hash"`
}

func (handler *Handler) health(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (handler *Handler) readiness(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if err := handler.ready(request.Context()); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "not_ready", "service dependencies are unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (handler *Handler) currentCheckpoint(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	value, err := handler.service.CurrentCheckpoint(request.Context())
	if err != nil {
		handleServiceError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, checkpointView(value))
}

func (handler *Handler) locatorProof(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	var input locatorProofRequest
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	query := locator.LocatorQuery{
		TenantID: input.TenantID, ServiceID: input.ServiceID, LogType: input.LogType,
		RegionID: input.RegionID, StartTime: input.StartTime, EndTime: input.EndTime,
	}
	if _, _, err := query.Bounds(); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := handler.service.ResolveLocator(request.Context(), query)
	if err != nil {
		handleServiceError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, locatorProofResponse{
		Checkpoint: checkpointView(result.Checkpoint), Result: locatorResultView(result.Range),
	})
}

func (handler *Handler) hmfProof(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	var input hmfProofRequest
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.CheckpointSequence <= 0 || len(input.Addresses) == 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request",
			"checkpoint_sequence must be positive and addresses must not be empty")
		return
	}
	addresses := make([]hpp.PhysicalAddress, 0, len(input.Addresses))
	for _, address := range input.Addresses {
		if address.RegionID == "" || address.ShardID < 0 || address.SegmentID < 0 || address.LeafID < 0 {
			writeError(writer, http.StatusBadRequest, "invalid_request",
				"every address requires a region_id and nonnegative shard_id, segment_id, and leaf_id")
			return
		}
		addresses = append(addresses, hpp.PhysicalAddress{
			RegionID: address.RegionID, ShardID: address.ShardID,
			SegmentID: address.SegmentID, LeafID: address.LeafID,
		})
	}
	result, err := handler.service.BuildHMFProof(request.Context(), input.CheckpointSequence, addresses)
	if err != nil {
		handleServiceError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, hmfProofResponse{
		Checkpoint:           checkpointView(result.Checkpoint),
		CalculatedGlobalRoot: hashHex(result.HMF.CalculatedGlobalRoot),
		Proof:                hmfProofView(result.HMF.Proof),
	})
}

func (handler *Handler) localize(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	var input localizationRequest
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if input.CheckpointSequence <= 0 ||
		(input.K != 0 && input.K != localization.DefaultJumpLevels) || len(input.Addresses) == 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request", fmt.Sprintf(
			"checkpoint_sequence must be positive, k must be %d or omitted, and addresses must not be empty",
			localization.DefaultJumpLevels))
		return
	}
	if input.K == 0 {
		input.K = localization.DefaultJumpLevels
	}
	auditorRoot, err := parseHash(input.AuditorGlobalRoot)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "auditor_global_root must be a 32-byte hex hash")
		return
	}
	addresses, err := addressValues(input.Addresses)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	failedProof, err := hmfProofValue(input.FailedProof)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := handler.service.LocalizeTamper(request.Context(), input.CheckpointSequence,
		auditorRoot, failedProof, addresses, input.K)
	if err != nil {
		handleServiceError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, localizationResponse{
		Checkpoint:              checkpointView(result.Checkpoint),
		CalculatedReferenceRoot: hashHex(result.Localization.CalculatedReferenceRoot),
		Proof:                   localizationProofView(result.Localization.Proof),
	})
}

func checkpointView(value checkpoint.Checkpoint) checkpointResponse {
	return checkpointResponse{
		ID: value.ID, SystemID: value.SystemID, Sequence: value.Sequence,
		LocatorTreeID: value.LocatorTreeID, LocatorRoot: hashHex(value.LocatorRoot),
		GlobalHMFRoot: hashHex(value.GlobalHMFRoot), StateCommitment: hashHex(value.StateCommitment),
		Status: value.Status, Anchor: value.Anchor, CreatedAt: value.CreatedAt, FinalizedAt: value.FinalizedAt,
	}
}

func locatorResultView(value locator.LocatorRangeResult) locatorResultResponse {
	proof := locatorRangeProof{ReconstructedRoot: hashHex(value.Proof.ReconstructedRoot)}
	for _, leaf := range value.Proof.Leaves {
		converted := locatorLeafProof{
			PageID: leaf.PageID, NextPageID: leaf.NextPageID,
			Keys: leaf.Keys, Values: leaf.Values,
		}
		for _, step := range leaf.Path {
			path := locatorProofStepResponse{
				PageID: step.PageID, Keys: step.Keys, ChildIndex: step.ChildIndex,
			}
			for _, hash := range step.ChildHashes {
				path.ChildHashes = append(path.ChildHashes, hashHex(hash))
			}
			converted.Path = append(converted.Path, path)
		}
		proof.Leaves = append(proof.Leaves, converted)
	}
	return locatorResultResponse{
		Entries: value.Entries, Predecessor: value.Predecessor,
		Successor: value.Successor, Proof: proof,
	}
}

func hmfProofView(value hpp.HMFProof) hmfProof {
	result := hmfProof{Plan: value.Plan}
	for _, leaf := range value.Leaves {
		result.Leaves = append(result.Leaves, hmfLeafResponse{Address: leaf.Address, Hash: hashHex(leaf.Hash)})
	}
	for _, node := range value.Nodes {
		result.Nodes = append(result.Nodes, hmfNodeResponse{Ref: node.Ref, Hash: hashHex(node.Hash)})
	}
	return result
}

func hmfProofValue(value hmfProof) (hpp.HMFProof, error) {
	result := hpp.HMFProof{Plan: value.Plan}
	for _, leaf := range value.Leaves {
		hash, err := parseHash(leaf.Hash)
		if err != nil {
			return hpp.HMFProof{}, fmt.Errorf("failed_proof leaf hash: %w", err)
		}
		result.Leaves = append(result.Leaves, hpp.RequestedLeaf{Address: leaf.Address, Hash: hash})
	}
	for _, node := range value.Nodes {
		hash, err := parseHash(node.Hash)
		if err != nil {
			return hpp.HMFProof{}, fmt.Errorf("failed_proof node hash: %w", err)
		}
		result.Nodes = append(result.Nodes, hpp.ProofNode{Ref: node.Ref, Hash: hash})
	}
	return result, nil
}

func localizationProofView(value localization.Proof) localizationProofResponse {
	result := localizationProofResponse{
		AnchoredGlobalRoot:  hashHex(value.AnchoredGlobalRoot),
		AuditorGlobalRoot:   hashHex(value.AuditorGlobalRoot),
		ReferenceGlobalRoot: hashHex(value.ReferenceGlobalRoot), K: value.K,
		Addresses: value.Addresses, FailedProof: hmfProofView(value.FailedProof),
		ReferenceProof: hmfProofView(value.ReferenceProof), BadShards: value.BadShards,
	}
	for _, round := range value.Rounds {
		converted := localizationRoundResponse{Tree: round.Tree, FromLevel: round.FromLevel,
			TargetLevel: round.TargetLevel}
		for _, comparison := range round.Comparisons {
			converted.Comparisons = append(converted.Comparisons, localizationComparisonResponse{
				Ref: comparison.Ref, AuditorHash: hashHex(comparison.AuditorHash),
				ReferenceHash: hashHex(comparison.ReferenceHash), Match: comparison.Match,
			})
		}
		result.Rounds = append(result.Rounds, converted)
	}
	for _, suspect := range value.Suspects {
		result.Suspects = append(result.Suspects, localizationSuspectResponse{
			Ref: suspect.Ref, Address: suspect.Address, AuditorHash: hashHex(suspect.AuditorHash),
			ReferenceHash: hashHex(suspect.ReferenceHash), Classification: suspect.Classification,
		})
	}
	return result
}

func addressValues(values []physicalAddress) ([]hpp.PhysicalAddress, error) {
	result := make([]hpp.PhysicalAddress, 0, len(values))
	for _, address := range values {
		if address.RegionID == "" || address.ShardID < 0 || address.SegmentID < 0 || address.LeafID < 0 {
			return nil, fmt.Errorf("every address requires a region_id and nonnegative indexes")
		}
		result = append(result, hpp.PhysicalAddress{RegionID: address.RegionID, ShardID: address.ShardID,
			SegmentID: address.SegmentID, LeafID: address.LeafID})
	}
	return result, nil
}

func parseHash(value string) ([32]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, fmt.Errorf("expected 64 hexadecimal characters")
	}
	var result [32]byte
	copy(result[:], decoded)
	return result, nil
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("request body must contain one JSON object")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func handleServiceError(writer http.ResponseWriter, err error) {
	if errors.Is(err, services.ErrCheckpointChanged) {
		writeError(writer, http.StatusConflict, "checkpoint_changed", err.Error())
		return
	}
	if errors.Is(err, localization.ErrNoMismatch) {
		writeError(writer, http.StatusUnprocessableEntity, "audit_did_not_fail", err.Error())
		return
	}
	if errors.Is(err, checkpoint.ErrNotFound) {
		writeError(writer, http.StatusServiceUnavailable, "checkpoint_unavailable",
			"no finalized checkpoint is available")
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		writeError(writer, http.StatusGatewayTimeout, "request_timeout", "request timed out")
		return
	}
	writeError(writer, http.StatusInternalServerError, "internal_error", err.Error())
}

func methodNotAllowed(writer http.ResponseWriter, allowed string) {
	writer.Header().Set("Allow", allowed)
	writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func hashHex(value [32]byte) string {
	return hex.EncodeToString(value[:])
}
