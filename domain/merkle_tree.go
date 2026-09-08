package domain

import "math"

//initiate a new MerkleTree
func NewMerkleTree(maxLeaves int) *SegmentTree {
	tree := &SegmentTree{
		Nodes:     make([][]SegmentNode, 1),
		MaxLeaves: maxLeaves,
	}
	tree.Nodes[0] = make([]SegmentNode, 0, tree.MaxLeaves)
	return tree
}

//Insert a log into a mutable tree
func (tree *SegmentTree) InsertLog(h [32]byte) {
	if len(tree.Nodes[0]) >= tree.MaxLeaves {
		return
	}
	tree.Nodes[0] = append(tree.Nodes[0], SegmentNode{Hash: h})
}

//Build immutable segment tree
func (tree *SegmentTree) BuildSegmentTree() [32]byte {
	numNodes := len(tree.Nodes[0])
	levels := int(math.Ceil(math.Log2(float64(numNodes))))
	for l := 0; l < levels; l++ {
		tree.Nodes = append(tree.Nodes, make([]SegmentNode, 0))
		for i := 0; i < numNodes; i = i + 2 {
			if i+1 >= numNodes {
				break
			}

			tree.Nodes[l+1] = append(tree.Nodes[l+1], SegmentNode{
				Hash: HashPair(
					&tree.Nodes[l][i].Hash,
					&tree.Nodes[l][i+1].Hash),
			})
		}

		//exist a left Nodes with no right sib
		if numNodes%2 != 0 {
			tree.Nodes[l+1] = append(tree.Nodes[l+1], SegmentNode{
				Hash: tree.Nodes[l][numNodes-1].Hash,
			})
		}
		numNodes = len(tree.Nodes[l+1])
	}

	//return rootHash
	return tree.Nodes[len(tree.Nodes)-1][0].Hash
}
