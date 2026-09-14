package hmf

import "github.com/SirojWongpitakroj/hmf-audit/domain"

type GlobalTree struct {
	Tree       *domain.MerkleTree
	numRegions int
}

func NewGlobalTree(numRegions int) *GlobalTree {
	merkleT := domain.NewMerkleTree()

	tree := GlobalTree{
		Tree:       merkleT,
		numRegions: numRegions,
	}
	merkleT.Nodes[0] = make([]domain.MerkleNode, numRegions)
	return &tree
}

func (tree *GlobalTree) BuildGlobalTree(regionHashes [][32]byte) ([32]byte, bool) {
	merkleT := tree.Tree
	for _, h := range regionHashes {
		merkleT.Nodes[0] = append(merkleT.Nodes[0], domain.MerkleNode{Hash: h})
	}

	root, ok := merkleT.BuildTree()
	if !ok {
		return [32]byte{}, false
	}

	merkleT.Root = root
	return root, true
}
