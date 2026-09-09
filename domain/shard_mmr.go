package domain

import (
	"github.com/emirpasic/gods/stacks/arraystack"
)

//utils

type peak struct {
	height int
	index  int
}

type peakStack struct {
	stack *arraystack.Stack
}

func newPeakStack() *peakStack {
	return &peakStack{
		stack: arraystack.New(),
	}
}

func (s *peakStack) Push(p peak) {
	s.stack.Push(p)
}

func (s *peakStack) Pop() (peak, bool) {
	value, ok := s.stack.Pop()
	if !ok {
		return peak{}, false
	}

	p, ok := value.(peak)
	return p, ok
}

func (s *peakStack) Peek() (peak, bool) {
	value, ok := s.stack.Peek()
	if !ok {
		return peak{}, false
	}

	p, ok := value.(peak)
	return p, ok
}

func (s *peakStack) Size() int {
	return s.stack.Size()
}

func (s *peakStack) Values() []peak {
	values := s.stack.Values()
	peaks := make([]peak, len(values))

	for i, value := range values {
		peaks[i] = value.(peak)
	}

	return peaks
}

// main function
func (tree *ShardTree) merge(first, second peak) (MMRNode, peak, int) {
	newHeight := first.height + 1
	if newHeight >= len(tree.Nodes) {
		tree.Nodes = append(tree.Nodes, nil)
	}

	newHash := HashPair(
		&tree.Nodes[first.height][first.index].Hash,
		&tree.Nodes[second.height][second.index].Hash,
	)

	newNode := MMRNode{
		Hash:   newHash,
		Height: newHeight,
	}

	newPeak := peak{
		height: newHeight,
		index:  len(tree.Nodes[newHeight]),
	}

	return newNode, newPeak, newHeight
}

func NewShardMMR() *ShardTree {
	tree := ShardTree{
		Nodes: make([][]MMRNode, 1),
		Peaks: newPeakStack(),
	}
	return &tree
}

// append new Node and get new root Hash
func (tree *ShardTree) Append(segment *SegmentNode) {
	//append to Nodes
	tree.Nodes[0] = append(tree.Nodes[0], MMRNode{
		Hash:   segment.Hash,
		Height: 0,
	})
	tree.NumLeaves++

	//update internal node and peak
	candPeak := peak{height: 0, index: len(tree.Nodes[0]) - 1}
	for tree.Peaks.Size() >= 1 {
		oldPeak, _ := tree.Peaks.Peek()

		if candPeak.height != oldPeak.height {
			break
		}

		oldPeak, _ = tree.Peaks.Pop()

		newNode, newPeak, newHeight := tree.merge(oldPeak, candPeak)
		//append newNode to appropriate level
		tree.Nodes[newHeight] = append(tree.Nodes[newHeight], newNode)

		candPeak = newPeak
	}
	tree.Peaks.Push(candPeak)

	//get rootHash and set new RootHash
	tree.RootHash = tree.Root()
}

// return root hash
func (tree *ShardTree) Root() [32]byte {
	peaks := tree.Peaks.Values()
	if len(peaks) == 0 {
		return [32]byte{}
	}
	curr := len(peaks) - 1
	h := tree.Nodes[peaks[curr].height][peaks[curr].index].Hash

	if len(peaks) <= 1 {
		return h
	}

	for i := len(peaks) - 2; i >= 0; i-- {
		h = HashPair(&tree.Nodes[peaks[i].height][peaks[i].index].Hash, &h)
	}
	return h
}
