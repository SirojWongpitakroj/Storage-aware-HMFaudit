package domain

type SegmentNode struct {
	Hash [32]byte
}

type SegmentTree struct {
	Nodes     [][]SegmentNode
	MaxLeaves int
	Sealed    bool
}

type MMRNode struct {
	Hash   [32]byte
	Height int
}

type ShardTree struct {
	RootHash  [32]byte
	Nodes     [][]MMRNode
	Peaks     *peakStack //(height, index)
	NumLeaves int
}
