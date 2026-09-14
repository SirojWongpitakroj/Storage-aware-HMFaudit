package domain

import "math/bits"

type MerkleNode struct {
	Hash [32]byte
}

type MerkleTree struct {
	Root  [32]byte
	Nodes [][]MerkleNode
}

func NewMerkleTree() *MerkleTree {
	tree := MerkleTree{
		Nodes: make([][]MerkleNode, 1),
	}
	return &tree
}

func (tree *MerkleTree) AddLeaf(h [32]byte) {
	tree.Nodes[0] = append(tree.Nodes[0], MerkleNode{Hash: h})
}

func (tree *MerkleTree) LeafCount() int {
	return len(tree.Nodes[0])
}

func (tree *MerkleTree) NodeAt(level, i int) ([32]byte, bool) {
	//check if level is valid
	if level < 0 || level >= len(tree.Nodes) {
		return [32]byte{}, false
	}

	//check if the index i is valid within the level
	if i < 0 || i >= len(tree.Nodes[level]) {
		return [32]byte{}, false
	}

	return tree.Nodes[level][i].Hash, true
}

func (tree *MerkleTree) LevelCount() int {
	return len(tree.Nodes)
}

func (tree *MerkleTree) BuildTree() ([32]byte, bool) {
	if tree.LevelCount() > 1 {
		return tree.Root, false
	}

	numNodes := tree.LeafCount()
	if numNodes == 0 {
		return [32]byte{}, false
	}
	if numNodes == 1 {
		return tree.Nodes[0][0].Hash, true
	}

	levels := bits.Len(uint(numNodes - 1))
	for l := range levels {
		tree.Nodes = append(tree.Nodes, make([]MerkleNode, 0))
		for i := 0; i < numNodes; i = i + 2 {
			if i+1 >= numNodes {
				break
			}

			tree.Nodes[l+1] = append(tree.Nodes[l+1], MerkleNode{
				Hash: HashPair(
					&tree.Nodes[l][i].Hash,
					&tree.Nodes[l][i+1].Hash),
			})
		}

		//exist a left Nodes with no right sib
		if numNodes%2 != 0 {
			tree.Nodes[l+1] = append(tree.Nodes[l+1], MerkleNode{
				Hash: tree.Nodes[l][numNodes-1].Hash,
			})
		}
		numNodes = len(tree.Nodes[l+1])
	}

	//return rootHash
	root, _ := tree.NodeAt(tree.LevelCount()-1, 0)
	return root, true
}

func (tree *MerkleTree) UpdateRoot(index int) bool {
	var currHash [32]byte
	for l := range tree.LevelCount() - 1 {
		isLeftChild := index%2 == 0
		var sibIdx int
		if isLeftChild {
			sibIdx = index + 1
		} else {
			sibIdx = index - 1
		}

		currHash, ok := tree.NodeAt(l, index)
		if !ok {
			return false
		}

		sibHash, ok := tree.NodeAt(l, sibIdx)
		if !ok {
			return false
		}

		var parentHash [32]byte
		if isLeftChild {
			parentHash = HashPair(&currHash, &sibHash)
		} else {
			parentHash = HashPair(&sibHash, &currHash)
		}

		parentIdx := index / 2
		index = parentIdx
		currHash = parentHash

	}

	tree.Root = currHash
	return true
}
