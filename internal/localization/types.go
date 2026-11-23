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

// FrontierSource is the optional reference-store capability ACHP needs: the
// partition-aware retrieval of explicit stored nodes, and the reference
// topology for the rare case that the failed proof's topology cannot be
// authenticated. *hpp.Service implements it over the same readers its proof
// building uses. A ReferenceBuilder without it is localized fixed-depth.
type FrontierSource interface {
	FetchNodes(ctx context.Context, refs []hpp.NodeRef) ([]hpp.ProofNode, error)
	ReferencePlan(ctx context.Context, addresses []hpp.PhysicalAddress) (hpp.ProofPlan, error)
}

type Request struct {
	Addresses          []hpp.PhysicalAddress
	AuditorGlobalRoot  [32]byte
	FailedProof        hpp.HMFProof
	AnchoredGlobalRoot [32]byte
	// K is the fixed-depth jump size. It must be zero or DefaultJumpLevels and
	// is used only by StrategyFixedDepth; ACHP chooses depths adaptively.
	K int32
	// Strategy overrides the service's strategy for this request.
	Strategy Strategy
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
	// Strategy is the strategy that produced the proof; empty means
	// StrategyFixedDepth, the only strategy before ACHP.
	Strategy Strategy
	// FallbackReason is set when ACHP was requested but the fixed-depth
	// traversal produced this proof, and says why.
	FallbackReason string
	// K is the fixed-depth jump size; it is zero for an ACHP proof.
	K           int32
	Addresses   []hpp.PhysicalAddress
	FailedProof hpp.HMFProof
	// ReferenceProof is the authenticated reference multiproof of a
	// fixed-depth localization. An ACHP proof carries ACHP evidence instead.
	ReferenceProof hpp.HMFProof
	BadShards      []hpp.TreeRef
	// Rounds is the per-tree comparison transcript. For ACHP it is a view
	// derived from the ACHP transcript, one entry per retrieved expansion.
	Rounds   []PruningRound
	Suspects []Suspect
	// Unresolved lists nodes the authenticated evidence could not settle
	// (ACHP only). A localization with unresolved nodes is incomplete: it
	// proves the suspects it lists, not the absence of others beneath them.
	Unresolved []UnresolvedNode
	// ACHP is the authenticated pruning transcript (ACHP only).
	ACHP *ACHPTranscript
}

type Result struct {
	CalculatedReferenceRoot [32]byte
	Proof                   Proof
}
