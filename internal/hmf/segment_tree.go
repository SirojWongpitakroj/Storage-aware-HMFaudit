package hmf

import (
	"fmt"
	"math"

	"github.com/SirojWongpitakroj/hmf-audit/domain"
)

type SegmentTree struct {
	*MerkleTree
	*builder
	MaxLeaves int
	Sealed    bool
}

// in-memory segment builder
type builder struct {
	levels [][]MerkleNode
}

// NewSegmentTree initiate a new MerkleTree
func NewSegmentTree(regionID string, shardID, segmentID int64, maxLeaves int) *SegmentTree {
	tree := &SegmentTree{
		MerkleTree: &MerkleTree{
			TreeID: TreeID{
				Type:      TreeSegment,
				RegionID:  regionID,
				ShardID:   shardID,
				SegmentID: segmentID,
			},
			Height: 15,
		},
		MaxLeaves: maxLeaves,
		Sealed:    false,
		builder: &builder{
			levels: make([][]MerkleNode, int(math.Log2(float64(maxLeaves)))+1),
		},
	}

	tree.levels[0] = make([]MerkleNode, 0, maxLeaves)
	return tree
}

// Append inserts a log into the mutable tree.
func (tree *SegmentTree) Append(h [32]byte) error {
	if tree.Sealed {
		return fmt.Errorf("append segment tree: segment tree sealed")
	}

	tree.levels[0] = append(tree.levels[0], MerkleNode{
		Level: 0,
		Index: tree.LeafCount,
		Hash:  h,
	})

	tree.LeafCount++
	return nil
}

// Build immutable segment tree
func (tree *SegmentTree) buildInternalNode() {
	for l := 1; l < 15; l++ { //start at first internal level and exclude root level
		for i := int64(1); i < tree.LeafCount; i = i + 2 {
			parentIdx := i / 2
			combinedHash := domain.HashPair(
				"NODE",
				&tree.levels[l-1][i-1].Hash,
				&tree.levels[l-1][i].Hash,
			)
			tree.levels[l] = append(tree.levels[l], MerkleNode{
				Level: l,
				Index: parentIdx,
				Hash:  combinedHash,
			})
		}

		//handle no sib case
		if len(tree.levels[l-1])%2 == 1 {
			tree.levels[l] = append(tree.levels[l], MerkleNode{
				Level: l,
				Index: int64((len(tree.levels[l-1]) - 1) / 2),
				Hash:  tree.levels[l-1][len(tree.levels[l-1])-1].Hash,
			})
		}
	}

	//set RootNode
	tree.Root = tree.levels[15][0].Hash
}

func (tree *SegmentTree) Seal() {
	tree.Sealed = true

	tree.buildInternalNode()

	//TODO: Save Segment if want more performance then Save in build InternalNode
}
