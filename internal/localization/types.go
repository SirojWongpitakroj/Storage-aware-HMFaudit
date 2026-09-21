package localization

import (
	"context"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

type Classification string

// DefaultJumpLevels is the maximum tree height: node indexes are int64, so no
// tree exceeds 63 levels. Each pruning round therefore jumps from a tree's
// root straight to its leaves (analyze clamps the target level at zero).
const DefaultJumpLevels int32 = 63

const (
	LeafMismatch               Classification = "LEAF_MISMATCH"
	AuthenticationNodeMismatch Classification = "AUTHENTICATION_NODE_MISMATCH"
	TopologyMismatch           Classification = "TOPOLOGY_MISMATCH"
)

// ReferenceBuilder obtains a proof from the reference store and authenticates
// it against the checkpoint root before localization trusts any of its nodes.
type ReferenceBuilder interface {
	BuildAndVerify(ctx context.Context, addresses []hpp.PhysicalAddress,
		trustedRoot [32]byte) (hpp.VerificationResult, error)
}

// ProofReferenceBuilder is an optional ReferenceBuilder capability. It
// rebuilds the reference around the failed proof's plan and authentication
// nodes, fetching only the stored requested leaves, and authenticates the
// result against the checkpoint root. Localize falls back to BuildAndVerify
// whenever this rebuild is unavailable or fails.
type ProofReferenceBuilder interface {
	ReferenceFromProof(ctx context.Context, proof hpp.HMFProof, addresses []hpp.PhysicalAddress,
		trustedRoot [32]byte) (hpp.VerificationResult, error)
}

type Request struct {
	Addresses          []hpp.PhysicalAddress
	AuditorGlobalRoot  [32]byte
	FailedProof        hpp.HMFProof
	AnchoredGlobalRoot [32]byte
	K                  int32
}

type NodeComparison struct {
	Ref           hpp.NodeRef
	AuditorHash   [32]byte
	ReferenceHash [32]byte
	Match         bool
}

type PruningRound struct {
	Tree        hpp.TreeRef
	FromLevel   int32
	TargetLevel int32
	Comparisons []NodeComparison
}

type Suspect struct {
	Ref            hpp.NodeRef
	Address        *hpp.PhysicalAddress
	AuditorHash    [32]byte
	ReferenceHash  [32]byte
	Classification Classification
}

// Proof is self-contained. The auditor can authenticate ReferenceProof against
// AnchoredGlobalRoot and replay every pruning decision with VerifyProof.
type Proof struct {
	AnchoredGlobalRoot  [32]byte
	AuditorGlobalRoot   [32]byte
	ReferenceGlobalRoot [32]byte
	K                   int32
	Addresses           []hpp.PhysicalAddress
	FailedProof         hpp.HMFProof
	ReferenceProof      hpp.HMFProof
	BadShards           []hpp.TreeRef
	Rounds              []PruningRound
	Suspects            []Suspect
}

type Result struct {
	CalculatedReferenceRoot [32]byte
	Proof                   Proof
}
