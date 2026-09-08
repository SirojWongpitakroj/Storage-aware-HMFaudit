package domain

type SegmentNode struct {
	Hash [32]byte
}

type SegmentTree struct {
	Nodes     [][]SegmentNode
	MaxLeaves int
}
