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
}

func NewService(reference ReferenceBuilder) (*Service, error) {
	if reference == nil {
		return nil, fmt.Errorf("new localization service: reference builder is nil")
	}
	return &Service{reference: reference}, nil
}

// Localize performs one authenticated reference-proof build. The underlying
// HPP reader batches and concurrently fetches the deduplicated forest nodes.
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

	reference, err := service.reference.BuildAndVerify(ctx, addresses, request.AnchoredGlobalRoot)
	if err != nil {
		return Result{}, fmt.Errorf("localize tamper: authenticate reference state: %w", err)
	}
	referenceTrace, err := hpp.TraceHMFProof(reference.Proof, addresses)
	if err != nil {
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
		K:                   request.K, Addresses: addresses,
		FailedProof: request.FailedProof, ReferenceProof: reference.Proof,
		BadShards: badShards, Rounds: rounds, Suspects: suspects,
	}
	return Result{CalculatedReferenceRoot: referenceTrace.GlobalRoot, Proof: proof}, nil
}

// VerifyProof lets the auditor independently authenticate the reference state
// and replay the complete k-level pruning transcript.
func VerifyProof(proof Proof, expectedAddresses []hpp.PhysicalAddress,
	trustedRoot [32]byte) error {

	addresses, err := normalizeAddresses(expectedAddresses)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	if proof.K != DefaultJumpLevels || !reflect.DeepEqual(addresses, proof.Addresses) {
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
	if _, err := hpp.VerifyHMFProofAgainstRoot(proof.ReferenceProof, addresses, trustedRoot); err != nil {
		return fmt.Errorf("%w: reference proof: %v", ErrInvalidProof, err)
	}
	referenceTrace, err := hpp.TraceHMFProof(proof.ReferenceProof, addresses)
	if err != nil {
		return fmt.Errorf("%w: reference trace: %v", ErrInvalidProof, err)
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
