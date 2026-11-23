package localization

import (
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// Disposition is ACHP's verdict on one compared node.
type Disposition string

const (
	// DispositionPrune: the authenticated reference commitment equals the
	// auditor's query-derived commitment, so nothing beneath the node differs.
	DispositionPrune Disposition = "PRUNE"
	// DispositionSuspect: the authenticated reference commitment differs.
	DispositionSuspect Disposition = "SUSPECT"
	// DispositionUnresolved: the evidence needed to compare the node was
	// missing or failed authentication. Such a node is never pruned.
	DispositionUnresolved Disposition = "UNRESOLVED"
)

// EvidenceStatus records whether a retrieved expansion authenticated.
type EvidenceStatus string

const (
	EvidenceAuthenticated EvidenceStatus = "AUTHENTICATED"
	EvidenceMissing       EvidenceStatus = "MISSING_EVIDENCE"
	EvidenceInvalid       EvidenceStatus = "INVALID_EVIDENCE"
)

// ExpansionKind distinguishes ordinary frontier expansions from the topology
// probe that confirms a leaf-count disagreement.
type ExpansionKind string

const (
	ExpansionFrontier ExpansionKind = "FRONTIER"
	ExpansionTopology ExpansionKind = "TOPOLOGY"
)

// NodeJudgement is one comparison of an auditor commitment with an
// authenticated reference commitment.
type NodeJudgement struct {
	Ref           hpp.NodeRef
	AuditorHash   [32]byte
	ReferenceHash [32]byte
	Disposition   Disposition
	// Classification is set only when the judgement ends the descent with a
	// suspect: a confirmed leaf, or an authentication node the auditor
	// supplied with a different value.
	Classification Classification
}

// Expansion is one authenticated retrieval inside a round: the nodes fetched
// to reconstruct the commitment of Node from a frontier beneath it.
type Expansion struct {
	Kind ExpansionKind
	Tree hpp.TreeRef
	// LeafCount is the leaf count the retrieval assumed for Tree. It is bound
	// to the anchored root by the root-commitment check, not trusted.
	LeafCount int64
	// Node is the node whose authenticated commitment the frontier rebuilds.
	Node hpp.NodePosition
	// RootCommit is set when Node is the tree's top node. Its raw hash is then
	// part of Fetched and is authenticated through the tree's committed root,
	// which an earlier judgement (or the anchored root) authenticated.
	RootCommit bool
	// Expanded are the on-path interior nodes whose children were fetched,
	// Node included. The frontier is their children that are not expanded.
	Expanded []hpp.NodePosition
	Fetched  []hpp.ProofNode
	Status   EvidenceStatus
	// Judgements covers every frontier node, in canonical order. It is empty
	// unless Status is EvidenceAuthenticated.
	Judgements []NodeJudgement
}

// CostEstimate is the model's estimate, in seconds, for a chosen frontier. It
// is recorded for diagnosis and is not part of what an auditor verifies.
type CostEstimate struct {
	IO           float64
	Network      float64
	Verification float64
	Future       float64
	Total        float64
}

// ACHPRound is one joint retrieval across every active suspect branch.
type ACHPRound struct {
	Index int
	// Candidates is how many distinct joint frontiers were costed.
	Candidates int
	Chosen     CostEstimate
	// PlanningTime is the wall time spent enumerating and costing candidate
	// frontiers this round. It is observational: it takes no part in any
	// decision and is not replayed by VerifyProof.
	PlanningTime time.Duration
	Expansions   []Expansion
}

// ACHPParameters records the knobs that steered the run.
type ACHPParameters struct {
	MaxCandidates int
	MismatchPrior float64
}

// ACHPTranscript is the authenticated record of an ACHP localization. An
// auditor replays it against the failed proof and the trusted root without
// reproducing any cost estimate.
type ACHPTranscript struct {
	Parameters ACHPParameters
	Rounds     []ACHPRound
}

// UnresolvedReason says why a node stayed unresolved.
type UnresolvedReason = EvidenceStatus

// UnresolvedNode is a branch the evidence could not settle.
type UnresolvedNode struct {
	Ref         hpp.NodeRef
	AuditorHash [32]byte
	Reason      UnresolvedReason
}
