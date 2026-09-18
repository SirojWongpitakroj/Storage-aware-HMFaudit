// Package hmf implements hierarchical Merkle trees.
package hmf

import (
	"fmt"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
)

type ShardTree struct {
	*MerkleTree
	frontiers []MerkleNode
}

func (tree *ShardTree) popFrontier() (MerkleNode, error) {
	frontierLen := len(tree.frontiers)
	if frontierLen == 0 {
		return MerkleNode{},
			fmt.Errorf("pop frontier node: do not have MerkleNode to pop")
	}

	poppedNode := tree.frontiers[frontierLen-1]
	tree.frontiers = tree.frontiers[:frontierLen-1]
	return poppedNode, nil
}

// Main function

func NewShardTree(regionID string, shardID int64) *ShardTree {
	tree := ShardTree{
		MerkleTree: &MerkleTree{
			TreeID: TreeID{
				Type:     TreeShard,
				RegionID: regionID,
				ShardID:  shardID,
			},
		},
		frontiers: make([]MerkleNode, 0),
	}
	return &tree
}

// Frontiers returns a copy of the current append frontier for persistence.
func (tree *ShardTree) Frontiers() []MerkleNode {
	return append([]MerkleNode(nil), tree.frontiers...)
}

// get node to update and get new frontierNode
func (tree *ShardTree) mergeFrontier(segmentHash [32]byte) ([]MerkleNode, error) {
	currNode := MerkleNode{
		Level: 0,
		Index: tree.LeafCount,
		Hash:  segmentHash,
	}

	updates := []MerkleNode{currNode}

	for len(tree.frontiers) > 0 &&
		tree.frontiers[len(tree.frontiers)-1].Level == currNode.Level {

		left, err := tree.popFrontier()
		if err != nil {
			return nil, err
		}

		currNode = MerkleNode{
			Level: currNode.Level + 1,
			Index: currNode.Index / 2,
			Hash:  domain.HashPair("NODE", &left.Hash, &currNode.Hash),
		}
		updates = append(updates, currNode)
	}
	tree.frontiers = append(tree.frontiers, currNode)

	return updates, nil
}

func (tree *ShardTree) materializeRootPath(updates []MerkleNode) ([]MerkleNode, MerkleNode, error) {
	if len(tree.frontiers) <= 0 {
		return updates, MerkleNode{}, fmt.Errorf("update shard root path error: no node in frontier")
	}
	if len(tree.frontiers) <= 1 {
		return updates, tree.frontiers[0], nil
	}

	right := tree.frontiers[len(tree.frontiers)-1]
	for i := len(tree.frontiers) - 2; i >= 0; i-- {
		left := tree.frontiers[i]
		//recusively promote
		for right.Level < left.Level {
			right = MerkleNode{
				Level: right.Level + 1,
				Index: right.Index / 2,
				Hash:  right.Hash, // promotion: unchanged
			}
			updates = append(updates, right)
		}

		//append HashPair of Peak
		right = MerkleNode{
			Level: left.Level + 1,
			Index: left.Index / 2,
			Hash:  domain.HashPair("NODE", &left.Hash, &right.Hash),
		}
		updates = append(updates, right)
	}

	return updates, right, nil
}

func (tree *ShardTree) Append(segmentHash [32]byte) ([]MerkleNode, error) {
	updates, err := tree.mergeFrontier(segmentHash)
	if err != nil {
		return updates, err
	}

	updates, shardRoot, err := tree.materializeRootPath(updates)
	if err != nil {
		return updates, err
	}

	//TODO: Updates Nodes in Path

	tree.Root = shardRoot.Hash
	tree.LeafCount++
	tree.Height = shardRoot.Level
	return updates, err
}
