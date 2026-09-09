package domain

type ShardTree struct {
	Tree      *MerkleTree
	Peaks     []peak //(height, index)
	NumLeaves int
}

type peak struct {
	height int
	index  int
}

func (tree *ShardTree) pop() (peak, bool) {
	numPeaks := len(tree.Peaks)
	if numPeaks <= 0 {
		return peak{}, false
	}

	popPeak := tree.Peaks[numPeaks-1]
	tree.Peaks = tree.Peaks[:numPeaks-1]

	return popPeak, true
}

// main function
func (tree *ShardTree) merge(first, second peak) (MerkleNode, peak) {
	merkleT := tree.Tree
	newHeight := first.height + 1
	if newHeight >= merkleT.LevelCount() {
		merkleT.Nodes = append(merkleT.Nodes, nil)
	}

	newHash := HashPair(
		&merkleT.Nodes[first.height][first.index].Hash,
		&merkleT.Nodes[second.height][second.index].Hash,
	)

	newNode := MerkleNode{
		Hash: newHash,
	}

	newPeak := peak{
		height: newHeight,
		index:  len(merkleT.Nodes[newHeight]),
	}

	return newNode, newPeak
}

func NewShardTree() *ShardTree {
	merkleT := NewMerkleTree()

	tree := ShardTree{
		Tree:  merkleT,
		Peaks: make([]peak, 0),
	}
	return &tree
}

// append new Node and get new root Hash
func (tree *ShardTree) Append(segmentHash [32]byte) {
	merkleT := tree.Tree

	//append to Nodes
	merkleT.AddLeaf(segmentHash)
	tree.NumLeaves++

	//update internal node and peak
	candPeak := peak{height: 0, index: merkleT.LeafCount() - 1}
	for len(tree.Peaks) >= 1 {
		oldPeak := tree.Peaks[len(tree.Peaks)-1]

		if candPeak.height != oldPeak.height {
			break
		}

		oldPeak, _ = tree.pop()

		newNode, newPeak := tree.merge(oldPeak, candPeak)
		newHeight := newPeak.height
		//append newNode to appropriate level
		merkleT.Nodes[newHeight] = append(merkleT.Nodes[newHeight], newNode)

		candPeak = newPeak
	}
	tree.Peaks = append(tree.Peaks, candPeak)

	//get rootHash and set new RootHash
	merkleT.Root = tree.Root()
}

// return root hash
func (tree *ShardTree) Root() [32]byte {
	merkleT := tree.Tree
	peaks := tree.Peaks
	if len(peaks) == 0 {
		return [32]byte{}
	}

	curr := len(peaks) - 1
	h := merkleT.Nodes[peaks[curr].height][peaks[curr].index].Hash

	if len(peaks) <= 1 {
		return h
	}

	for i := len(peaks) - 2; i >= 0; i-- {
		h = HashPair(&merkleT.Nodes[peaks[i].height][peaks[i].index].Hash, &h)
	}
	return h
}
