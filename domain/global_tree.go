package domain

type GlobalTree struct {
	Tree       *MerkleTree
	numRegions int
}

func NewGlobalTree(numRegions int) *GlobalTree {
	merkleT := NewMerkleTree()

	tree := GlobalTree{
		Tree:       merkleT,
		numRegions: numRegions,
	}
	merkleT.Nodes[0] = make([]MerkleNode, numRegions)
	return &tree
}

func (tree *GlobalTree) BuildGlobalTree(regionHashes [][32]byte) ([32]byte, bool) {
	merkleT := tree.Tree
	for _, h := range regionHashes {
		merkleT.Nodes[0] = append(merkleT.Nodes[0], MerkleNode{Hash: h})
	}

	root, ok := merkleT.BuildTree()
	if !ok {
		return [32]byte{}, false
	}

	merkleT.Root = root
	return root, true
}
