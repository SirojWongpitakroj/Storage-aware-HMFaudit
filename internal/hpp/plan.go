package hpp

type PhysicalAddress struct {
	RegionID  string
	ShardID   int64
	SegmentID int64
	LeafID    int64
}

type NodePosition struct {
	Level int32
	Index int64
}

type SegmentRequest struct {
	RegionID  string
	ShardID   int64
	SegmentID int64
	Nodes     []NodePosition
}

type UpperRequest struct {
	ScopeType string // SHARD, REGION, GLOBAL
	ScopeID   string
	BucketID  int64
	Nodes     []NodePosition
}

type ProofPlan struct {
	Addresses       []PhysicalAddress
	SegmentRequests []SegmentRequest
	UpperRequests   []UpperRequest
}
