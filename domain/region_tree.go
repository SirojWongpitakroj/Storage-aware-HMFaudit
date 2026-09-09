package domain

type RegionTree struct {
	Tree      *MerkleTree
	numShards int
}

func NewRegionTree(numShards int) *RegionTree {
	merkleT := NewMerkleTree()

	tree := RegionTree{
		Tree:      merkleT,
		numShards: numShards,
	}
	merkleT.Nodes[0] = make([]MerkleNode, numShards)
	return &tree
}

func (tree *RegionTree) BuildRegionTree(shardHashes [][32]byte) ([32]byte, bool) {
	merkleT := tree.Tree
	for _, h := range shardHashes {
		merkleT.Nodes[0] = append(merkleT.Nodes[0], MerkleNode{Hash: h})
	}

	root, ok := merkleT.BuildTree()
	if !ok {
		return [32]byte{}, false
	}
	merkleT.Root = root
	return root, true
}
