package hmf

import "github.com/SirojWongpitakroj/hmf-audit/domain"

type RegionTree struct {
	RegionID  int
	Tree      *domain.MerkleTree
	numShards int
}

func NewRegionTree(numShards int) *RegionTree {
	merkleT := domain.NewMerkleTree()

	tree := RegionTree{
		Tree:      merkleT,
		numShards: numShards,
	}
	merkleT.Nodes[0] = make([]domain.MerkleNode, numShards)
	return &tree
}

func (tree *RegionTree) BuildRegionTree(shardHashes [][32]byte) ([32]byte, bool) {
	merkleT := tree.Tree
	for _, h := range shardHashes {
		merkleT.Nodes[0] = append(merkleT.Nodes[0], domain.MerkleNode{Hash: h})
	}

	root, ok := merkleT.BuildTree()
	if !ok {
		return [32]byte{}, false
	}
	merkleT.Root = root
	return root, true
}
