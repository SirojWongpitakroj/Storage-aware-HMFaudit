package localization

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

var (
	ErrNoMismatch   = errors.New("localization requires a failed audit root")
	ErrInvalidProof = errors.New("invalid localization proof")
)

type Service struct {
	reference ReferenceBuilder
	strategy  Strategy
	achp      ACHPConfig
}

// NewService returns a localization service. Unless an option says otherwise
// it localizes with ACHP, using DefaultACHPConfig, and falls back to the
// fixed-depth traversal whenever the reference builder cannot retrieve
// frontiers or ACHP cannot make progress.
func NewService(reference ReferenceBuilder, options ...Option) (*Service, error) {
	if reference == nil {
		return nil, fmt.Errorf("new localization service: reference builder is nil")
	}
	service := &Service{reference: reference, strategy: StrategyACHP, achp: DefaultACHPConfig()}
	for _, option := range options {
		if err := option(service); err != nil {
			return nil, fmt.Errorf("new localization service: %w", err)
		}
	}
	return service, nil
}

// Localize authenticates the reference state against the anchored root and
// finds the corrupted leaves under it.
//
// With StrategyACHP (the default) it retrieves cost-chosen frontiers of the
// reference tree round by round, authenticating each before comparing it. With
// StrategyFixedDepth it performs one authenticated reference-proof build,
// reusing the failed proof's authentication nodes where they are the committed
// ones, so normally only the stored requested leaves are read again, and walks
// the result κ levels per round. An ACHP request that cannot be served (the
// reference builder lacks frontier retrieval, or ACHP made no progress) is
// served fixed-depth, and the proof says why in FallbackReason.
func (service *Service) Localize(ctx context.Context, request Request) (Result, error) {
	addresses, err := normalizeAddresses(request.Addresses)
	if err != nil {
		return Result{}, fmt.Errorf("localize tamper: %w", err)
	}
	if request.K != 0 && request.K != DefaultJumpLevels {
		return Result{}, fmt.Errorf("localize tamper: k must be %d", DefaultJumpLevels)
	}
	request.K = DefaultJumpLevels
	auditorTrace, err := hpp.TraceHMFProof(request.FailedProof, addresses)
	if err != nil {
		return Result{}, fmt.Errorf("localize tamper: verify auditor proof: %w", err)
	}
	if !equalHash(auditorTrace.GlobalRoot, request.AuditorGlobalRoot) {
		return Result{}, fmt.Errorf("localize tamper: reported auditor root does not match failed proof")
	}
	if equalHash(request.AuditorGlobalRoot, request.AnchoredGlobalRoot) {
		return Result{}, ErrNoMismatch
	}

	strategy := request.Strategy
	if strategy == StrategyDefault {
		strategy = service.strategy
	}
	fallbackReason := ""
	switch strategy {
	case StrategyFixedDepth:
	case StrategyACHP:
		result, err := service.localizeACHP(ctx, request, addresses, auditorTrace)
		if err == nil {
			return result, nil
		}
		var fallback *fallbackError
		if !errors.As(err, &fallback) {
			return Result{}, fmt.Errorf("localize tamper: %w", err)
		}
		fallbackReason = fallback.reason
	default:
		return Result{}, fmt.Errorf("localize tamper: unknown strategy %q", strategy)
	}

	reference, err := service.authenticatedReference(ctx, request.FailedProof, addresses, request.AnchoredGlobalRoot)
	if err != nil {
		return Result{}, fmt.Errorf("localize tamper: authenticate reference state: %w", err)
	}
	var referenceTrace hpp.ProofTrace
	if reference.Trace != nil {
		referenceTrace = *reference.Trace
	} else if referenceTrace, err = hpp.TraceHMFProof(reference.Proof, addresses); err != nil {
		return Result{}, fmt.Errorf("localize tamper: trace authenticated reference proof: %w", err)
	}
	if !equalHash(reference.CalculatedGlobalRoot, request.AnchoredGlobalRoot) ||
		!equalHash(referenceTrace.GlobalRoot, request.AnchoredGlobalRoot) {
		return Result{}, fmt.Errorf("localize tamper: reference proof is not bound to anchored root")
	}

	badShards, rounds, suspects := analyze(
		addresses, request.FailedProof, reference.Proof, auditorTrace, referenceTrace, request.K,
	)
	proof := Proof{
		AnchoredGlobalRoot:  request.AnchoredGlobalRoot,
		AuditorGlobalRoot:   request.AuditorGlobalRoot,
		ReferenceGlobalRoot: referenceTrace.GlobalRoot,
		Strategy:            StrategyFixedDepth, FallbackReason: fallbackReason,
		K: request.K, Addresses: addresses,
		FailedProof: request.FailedProof, ReferenceProof: reference.Proof,
		BadShards: badShards, Rounds: rounds, Suspects: suspects,
	}
	return Result{CalculatedReferenceRoot: referenceTrace.GlobalRoot, Proof: proof}, nil
}

// authenticatedReference first rebuilds the reference around the failed
// proof's authentication nodes, which only reads the stored requested leaves.
// That rebuild succeeds only when those nodes are the committed ones, so any
// other failure (an altered authentication node, a missing leaf) falls back to
// a complete reference build from the reference store.
func (service *Service) authenticatedReference(ctx context.Context, failed hpp.HMFProof,
	addresses []hpp.PhysicalAddress, trustedRoot [32]byte) (hpp.VerificationResult, error) {

	if builder, ok := service.reference.(ProofReferenceBuilder); ok {
		if reference, err := builder.ReferenceFromProof(ctx, failed, addresses, trustedRoot); err == nil {
			return reference, nil
		}
	}
	return service.reference.BuildAndVerify(ctx, addresses, trustedRoot)
}

// VerifyProof lets the auditor independently authenticate the reference state
// and replay the complete pruning transcript: the k-level transcript of a
// fixed-depth proof, or the authenticated frontier transcript of an ACHP proof.
func VerifyProof(proof Proof, expectedAddresses []hpp.PhysicalAddress,
	trustedRoot [32]byte) error {

	addresses, err := normalizeAddresses(expectedAddresses)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	if !reflect.DeepEqual(addresses, proof.Addresses) {
		return fmt.Errorf("%w: addresses or k do not match", ErrInvalidProof)
	}
	switch proof.Strategy {
	case StrategyACHP:
		return verifyACHP(proof, addresses, trustedRoot)
	case StrategyDefault, StrategyFixedDepth:
	default:
		return fmt.Errorf("%w: unknown strategy %q", ErrInvalidProof, proof.Strategy)
	}
	if proof.K != DefaultJumpLevels {
		return fmt.Errorf("%w: addresses or k do not match", ErrInvalidProof)
	}
	if !equalHash(proof.AnchoredGlobalRoot, trustedRoot) ||
		!equalHash(proof.ReferenceGlobalRoot, trustedRoot) {
		return fmt.Errorf("%w: reference root does not match trusted root", ErrInvalidProof)
	}
	auditorTrace, err := hpp.TraceHMFProof(proof.FailedProof, addresses)
	if err != nil {
		return fmt.Errorf("%w: auditor proof: %v", ErrInvalidProof, err)
	}
	if !equalHash(auditorTrace.GlobalRoot, proof.AuditorGlobalRoot) ||
		equalHash(proof.AuditorGlobalRoot, trustedRoot) {
		return fmt.Errorf("%w: auditor proof is not the reported failed computation", ErrInvalidProof)
	}
	referenceTrace, err := hpp.TraceHMFProof(proof.ReferenceProof, addresses)
	if err != nil {
		return fmt.Errorf("%w: reference proof: %v", ErrInvalidProof, err)
	}
	if !equalHash(referenceTrace.GlobalRoot, trustedRoot) {
		return fmt.Errorf("%w: reference proof: calculated global root does not match trusted root", ErrInvalidProof)
	}
	badShards, rounds, suspects := analyze(
		addresses, proof.FailedProof, proof.ReferenceProof, auditorTrace, referenceTrace, proof.K,
	)
	if !reflect.DeepEqual(badShards, proof.BadShards) ||
		!reflect.DeepEqual(rounds, proof.Rounds) || !reflect.DeepEqual(suspects, proof.Suspects) {
		return fmt.Errorf("%w: pruning transcript was altered or is incomplete", ErrInvalidProof)
	}
	return nil
}

func normalizeAddresses(input []hpp.PhysicalAddress) ([]hpp.PhysicalAddress, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("at least one physical address is required")
	}
	unique := make(map[hpp.PhysicalAddress]struct{}, len(input))
	for _, address := range input {
		if address.RegionID == "" || address.ShardID < 0 || address.SegmentID < 0 || address.LeafID < 0 {
			return nil, fmt.Errorf("physical addresses require a region and nonnegative indexes")
		}
		unique[address] = struct{}{}
	}
	result := make([]hpp.PhysicalAddress, 0, len(unique))
	for address := range unique {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return lessAddress(result[i], result[j]) })
	return result, nil
}

func lessAddress(left, right hpp.PhysicalAddress) bool {
	if left.RegionID != right.RegionID {
		return left.RegionID < right.RegionID
	}
	if left.ShardID != right.ShardID {
		return left.ShardID < right.ShardID
	}
	if left.SegmentID != right.SegmentID {
		return left.SegmentID < right.SegmentID
	}
	return left.LeafID < right.LeafID
}

func equalHash(left, right [32]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}
