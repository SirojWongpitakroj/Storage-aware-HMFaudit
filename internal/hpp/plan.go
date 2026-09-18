package hpp

import "context"

type PhysicalAddress struct {
	RegionID  string `json:"region_id"`
	ShardID   int64  `json:"shard_id"`
	SegmentID int64  `json:"segment_id"`
	LeafID    int64  `json:"leaf_id"`
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
	Layer     TreeLayer `json:"layer"`
	RegionID  string    `json:"region_id"`
	ShardID   int64     `json:"shard_id"`
	SegmentID int64     `json:"segment_id"`
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
	Level int32 `json:"level"`
	Index int64 `json:"index"`
}

type NodeRef struct {
	Tree     TreeRef      `json:"tree"`
	Position NodePosition `json:"position"`
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
	Tree      TreeRef        `json:"tree"`
	LeafCount int64          `json:"leaf_count"`
	Targets   []int64        `json:"targets"`
	Required  []NodePosition `json:"required"`
}

type ParentLink struct {
	Child           TreeRef `json:"child"`
	Parent          TreeRef `json:"parent"`
	ParentLeafIndex int64   `json:"parent_leaf_index"`
}

type SegmentRequest struct {
	Tree        TreeRef `json:"tree"`
	RegionID    string  `json:"region_id"`
	ShardID     int64   `json:"shard_id"`
	SegmentID   int64   `json:"segment_id"`
	Level       int32   `json:"level"`
	NodeIndexes []int64 `json:"node_indexes"`
}

type UpperRequest struct {
	Tree        TreeRef `json:"tree"`
	ScopeType   string  `json:"scope_type"`
	ScopeID     string  `json:"scope_id"`
	BucketID    int64   `json:"bucket_id"`
	Level       int32   `json:"level"`
	NodeIndexes []int64 `json:"node_indexes"`
}

type ProofPlan struct {
	Addresses       []PhysicalAddress `json:"addresses"`
	Trees           []TreePlan        `json:"trees"`
	ParentLinks     []ParentLink      `json:"parent_links"`
	SegmentRequests []SegmentRequest  `json:"segment_requests"`
	UpperRequests   []UpperRequest    `json:"upper_requests"`
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

// ProofTrace contains every supplied or reconstructed node used while
// verifying one HMF multiproof. RawRoots are roots before topology binding;
// CommittedRoots bind each root to its tree identity and leaf count.
type ProofTrace struct {
	GlobalRoot     [32]byte
	RawRoots       map[TreeRef][32]byte
	CommittedRoots map[TreeRef][32]byte
	Nodes          map[NodeRef][32]byte
}

type MetadataReader interface {
	LoadHierarchyMetadata(ctx context.Context, addresses []PhysicalAddress) (HierarchyMetadata, error)
}

type ProofNodeReader interface {
	FetchProofNodes(ctx context.Context, plan ProofPlan) ([]ProofNode, error)
}
