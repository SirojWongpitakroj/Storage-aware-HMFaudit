package hmf

type TreeType string

const (
	TreeGlobal  TreeType = "Global"
	TreeRegion  TreeType = "Region"
	TreeShard   TreeType = "Shard"
	TreeSegment TreeType = "Segment"
)

type TreeID struct {
	Type      TreeType
	RegionID  string
	ShardID   int
	SegmentID int
}

type MerkleNode struct {
	Level int
	Index int
	Hash  [32]byte
}

type MerkleTree struct {
	TreeID    TreeID
	Root      [32]byte
	LeafCount int
	Height    int
}
