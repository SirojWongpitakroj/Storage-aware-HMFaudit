package hmf

import (
	"fmt"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
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
		},
		MaxLeaves: maxLeaves,
		Sealed:    false,
		builder: &builder{
			levels: make([][]MerkleNode, 1),
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
	if tree.LeafCount >= int64(tree.MaxLeaves) {
		return fmt.Errorf("append segment tree: segment tree is full")
	}

	tree.levels[0] = append(tree.levels[0], MerkleNode{
		Level: 0,
		Index: tree.LeafCount,
		Hash:  h,
	})

	tree.LeafCount++
	return nil
}

// Build immutable segment tree and return all nodes for persistence.
func (tree *SegmentTree) buildInternalNode() ([]MerkleNode, error) {
	if tree.LeafCount == 0 {
		return nil, fmt.Errorf("build segment tree: segment tree has no leaves")
	}

	updates := append([]MerkleNode(nil), tree.levels[0]...)
	for level := 1; len(tree.levels[level-1]) > 1; level++ {
		children := tree.levels[level-1]
		nodes := make([]MerkleNode, 0, (len(children)+1)/2)

		for index := 0; index < len(children); index += 2 {
			node := MerkleNode{
				Level: level,
				Index: int64(index / 2),
				Hash:  children[index].Hash,
			}
			if index+1 < len(children) {
				node.Hash = domain.HashPair("NODE", &children[index].Hash, &children[index+1].Hash)
			}
			nodes = append(nodes, node)
			updates = append(updates, node)
		}

		tree.levels = append(tree.levels, nodes)
	}

	tree.Height = len(tree.levels) - 1
	tree.Root = tree.levels[tree.Height][0].Hash
	return updates, nil
}

func (tree *SegmentTree) Seal() ([]MerkleNode, error) {
	if tree.Sealed {
		return nil, fmt.Errorf("seal segment tree: the tree is already sealed")
	}
	updates, err := tree.buildInternalNode()
	if err != nil {
		return nil, err
	}
	tree.Sealed = true

	return updates, nil
}
