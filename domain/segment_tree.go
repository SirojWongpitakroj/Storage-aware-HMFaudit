package domain

type SegmentTree struct {
	Tree      *MerkleTree
	MaxLeaves int
	Sealed    bool
}

// initiate a new MerkleTree
func NewSegmentTree(maxLeaves int) *SegmentTree {
	merkleT := NewMerkleTree()

	tree := &SegmentTree{
		Tree:      merkleT,
		MaxLeaves: maxLeaves,
		Sealed:    false,
	}
	merkleT.Nodes[0] = make([]MerkleNode, 0, tree.MaxLeaves)
	return tree
}

// Insert a log into a mutable tree
func (tree *SegmentTree) Append(h [32]byte) {
	merkleT := tree.Tree
	//if sealed then cannot append
	if tree.Sealed {
		return
	}

	if merkleT.LeafCount() >= tree.MaxLeaves {
		return
	}
	merkleT.AddLeaf(h)
}

// Build immutable segment tree
func (tree *SegmentTree) BuildSegmentTree() ([32]byte, bool) {
	if !tree.Sealed {
		return [32]byte{}, false
	}

	root, ok := tree.Tree.BuildTree()
	if !ok {
		return [32]byte{}, false
	}

	tree.Tree.Root = root
	return root, true
}

func (merkleT *SegmentTree) Seal() {
	merkleT.Sealed = true
}
