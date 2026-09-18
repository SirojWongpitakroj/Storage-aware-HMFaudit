package hpp

import "context"

type PhysicalAddress struct {
	RegionID  string
	ShardID   int64
	SegmentID int64
	LeafID    int64
}

type RequestedLeaf struct {
	Address PhysicalAddress
	Hash    [32]byte
}

type TreeLayer uint8

const (
	LayerSegment TreeLayer = iota + 1
	LayerShard
	LayerRegion
	LayerGlobal
)

type TreeRef struct {
	Layer     TreeLayer
	RegionID  string
	ShardID   int64
	SegmentID int64
}

type SegmentKey struct {
	RegionID  string
	ShardID   int64
	SegmentID int64
}

type ShardKey struct {
	RegionID string
	ShardID  int64
}

type NodePosition struct {
	Level int32
	Index int64
}

type NodeRef struct {
	Tree     TreeRef
	Position NodePosition
}

type SegmentMetadata struct {
	LeafCount      int64
	ShardLeafIndex int64
	Sealed         bool
}

type UpperTreeMetadata struct {
	LeafCount       int64
	ParentLeafIndex int64
}

type HierarchyMetadata struct {
	Segments map[SegmentKey]SegmentMetadata
	Shards   map[ShardKey]UpperTreeMetadata
	Regions  map[string]UpperTreeMetadata
	Global   UpperTreeMetadata
}

type TreePlan struct {
	Tree      TreeRef
	LeafCount int64
	Targets   []int64
	Required  []NodePosition
}

type ParentLink struct {
	Child           TreeRef
	Parent          TreeRef
	ParentLeafIndex int64
}

type SegmentRequest struct {
	Tree        TreeRef
	RegionID    string
	ShardID     int64
	SegmentID   int64
	Level       int32
	NodeIndexes []int64
}

type UpperRequest struct {
	Tree        TreeRef
	ScopeType   string
	ScopeID     string
	BucketID    int64
	Level       int32
	NodeIndexes []int64
}

type ProofPlan struct {
	Addresses       []PhysicalAddress
	Trees           []TreePlan
	ParentLinks     []ParentLink
	SegmentRequests []SegmentRequest
	UpperRequests   []UpperRequest
}

type ProofNode struct {
	Ref  NodeRef
	Hash [32]byte
}

type HMFProof struct {
	Plan   ProofPlan
	Leaves []RequestedLeaf
	Nodes  []ProofNode
}

type VerificationResult struct {
	CalculatedGlobalRoot [32]byte
	Proof                HMFProof
}

type MetadataReader interface {
	LoadHierarchyMetadata(ctx context.Context, addresses []PhysicalAddress) (HierarchyMetadata, error)
}

type ProofNodeReader interface {
	FetchProofNodes(ctx context.Context, plan ProofPlan) ([]ProofNode, error)
}
