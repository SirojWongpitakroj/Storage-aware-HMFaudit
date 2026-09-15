package hmf

import (
	"fmt"
	"math/bits"

	"github.com/SirojWongpitakroj/hmf-audit/domain"
)

type GlobalTree struct {
	*MerkleTree
	levels     [][]MerkleNode
	numRegions int
}

func NewGlobalTree(numRegions int) *GlobalTree {
	if numRegions <= 0 {
		panic("new global tree: numRegions must be positive")
	}

	treeHeight := bits.Len(uint(numRegions - 1))

	tree := GlobalTree{
		MerkleTree: &MerkleTree{
			TreeID: TreeID{
				Type: TreeGlobal,
			},
			LeafCount: numRegions,
			Height:    treeHeight,
		},
		levels:     make([][]MerkleNode, treeHeight+1),
		numRegions: numRegions,
	}

	nodeCount := numRegions
	for level := 0; level <= treeHeight; level++ {
		tree.levels[level] = make([]MerkleNode, nodeCount)
		nodeCount = (nodeCount + 1) / 2
	}
	return &tree
}

func (tree *GlobalTree) Build(regionHashes [][32]byte) ([]MerkleNode, error) {
	if len(regionHashes) != tree.numRegions {
		return nil, fmt.Errorf("build global tree: got %d region roots, want %d", len(regionHashes), tree.numRegions)
	}

	updates := []MerkleNode{}
	for index, hash := range regionHashes {
		leaf := MerkleNode{
			Level: 0,
			Index: index,
			Hash:  hash,
		}
		tree.levels[0][index] = leaf
		updates = append(updates, leaf)
	}

	for level := 1; level <= tree.Height; level++ {
		for parentIndex := range tree.levels[level] {
			leftIndex := parentIndex * 2
			rightIndex := leftIndex + 1
			parent := MerkleNode{
				Level: level,
				Index: parentIndex,
				Hash:  tree.levels[level-1][leftIndex].Hash,
			}
			if rightIndex < len(tree.levels[level-1]) {
				parent.Hash = domain.HashPair(
					"NODE",
					&tree.levels[level-1][leftIndex].Hash,
					&tree.levels[level-1][rightIndex].Hash,
				)
			}
			tree.levels[level][parentIndex] = parent
			updates = append(updates, parent)
		}
	}

	tree.Root = tree.levels[tree.Height][0].Hash
	return updates, nil
}

func (tree *GlobalTree) recomputePath(regionIndex int, updates []MerkleNode) ([]MerkleNode, error) {
	if regionIndex < 0 || regionIndex >= tree.numRegions {
		return nil, fmt.Errorf("recompute global path: region index %d out of range", regionIndex)
	}

	index := regionIndex
	for level := 1; level <= tree.Height; level++ {
		parentIndex := index / 2
		children := tree.levels[level-1]
		leftIndex := parentIndex * 2
		rightIndex := leftIndex + 1

		parent := MerkleNode{
			Level: level,
			Index: parentIndex,
			Hash:  children[leftIndex].Hash,
		}
		if rightIndex < len(children) {
			parent.Hash = domain.HashPair(
				"NODE",
				&children[leftIndex].Hash,
				&children[rightIndex].Hash,
			)
		}

		tree.levels[level][parentIndex] = parent
		updates = append(updates, parent)
		index = parentIndex
	}

	tree.Root = tree.levels[tree.Height][0].Hash
	return updates, nil
}

func (tree *GlobalTree) updateRegionRoot(regionIndex int, regionRoot [32]byte) ([]MerkleNode, error) {
	if regionIndex < 0 || regionIndex >= tree.numRegions {
		return nil, fmt.Errorf("update global tree: region index %d out of range", regionIndex)
	}

	leaf := MerkleNode{
		Level: 0,
		Index: regionIndex,
		Hash:  regionRoot,
	}
	tree.levels[0][regionIndex] = leaf

	return tree.recomputePath(regionIndex, []MerkleNode{leaf})
}
