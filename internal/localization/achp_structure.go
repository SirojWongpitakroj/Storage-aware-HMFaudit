package localization

import (
	"fmt"
	"sort"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// treeInfo describes one tree's query-derived shape, taken from the failed
// proof's (already traced, hence canonical) plan. A node is "on path" when it
// is an ancestor-or-self of a requested leaf or, in an upper tree, of a child
// tree that holds one. Every child of an on-path node is either on path or a
// supplied authentication (Required) node.
type treeInfo struct {
	tree      hpp.TreeRef
	leafCount int64
	height    int32
	// widths[l] is the number of nodes at level l.
	widths   []int64
	required map[hpp.NodePosition]struct{}
	// weight maps every on-path node to the number of requested leaves
	// beneath it.
	weight map[hpp.NodePosition]int64
	// childTree maps an on-path leaf of an upper tree to the tree it commits.
	childTree map[int64]hpp.TreeRef
}

// structure is the query-derived hierarchy of a failed proof.
type structure struct {
	trees         map[hpp.TreeRef]*treeInfo
	order         []hpp.TreeRef
	addressByLeaf map[hpp.NodeRef]hpp.PhysicalAddress
}

// levelWidths returns the node count at every level of a tree of leafCount
// leaves, leaf level first. The last entry is the root level.
func levelWidths(leafCount int64) []int64 {
	widths := []int64{leafCount}
	for width := leafCount; width > 1; {
		width = (width + 1) / 2
		widths = append(widths, width)
	}
	return widths
}

func newStructure(proof hpp.HMFProof, addresses []hpp.PhysicalAddress) (*structure, error) {
	result := &structure{
		trees:         make(map[hpp.TreeRef]*treeInfo, len(proof.Plan.Trees)),
		addressByLeaf: make(map[hpp.NodeRef]hpp.PhysicalAddress, len(addresses)),
	}
	for _, plan := range proof.Plan.Trees {
		if plan.LeafCount <= 0 {
			return nil, fmt.Errorf("tree %+v has no leaves", plan.Tree)
		}
		widths := levelWidths(plan.LeafCount)
		info := &treeInfo{
			tree: plan.Tree, leafCount: plan.LeafCount, height: int32(len(widths) - 1), widths: widths,
			required:  make(map[hpp.NodePosition]struct{}, len(plan.Required)),
			weight:    make(map[hpp.NodePosition]int64),
			childTree: make(map[int64]hpp.TreeRef),
		}
		for _, position := range plan.Required {
			info.required[position] = struct{}{}
		}
		result.trees[plan.Tree] = info
		result.order = append(result.order, plan.Tree)
	}
	sort.Slice(result.order, func(i, j int) bool { return lessTree(result.order[i], result.order[j]) })
	for _, link := range proof.Plan.ParentLinks {
		parent, parentOK := result.trees[link.Parent]
		_, childOK := result.trees[link.Child]
		if !parentOK || !childOK {
			return nil, fmt.Errorf("parent link %+v -> %+v references an unplanned tree", link.Child, link.Parent)
		}
		parent.childTree[link.ParentLeafIndex] = link.Child
	}
	for _, address := range addresses {
		tree := hpp.TreeRef{Layer: hpp.LayerSegment, RegionID: address.RegionID,
			ShardID: address.ShardID, SegmentID: address.SegmentID}
		result.addressByLeaf[hpp.NodeRef{Tree: tree, Position: hpp.NodePosition{Level: 0, Index: address.LeafID}}] = address
	}

	// Weights are filled layer by layer so an upper tree's leaf weight is its
	// child tree's total.
	for layer := hpp.LayerSegment; layer <= hpp.LayerGlobal; layer++ {
		for _, tree := range result.order {
			if tree.Layer != layer {
				continue
			}
			info := result.trees[tree]
			leaves := make(map[int64]int64)
			if layer == hpp.LayerSegment {
				for _, plan := range proof.Plan.Trees {
					if plan.Tree == tree {
						for _, target := range plan.Targets {
							leaves[target] = 1
						}
					}
				}
			} else {
				for index, child := range info.childTree {
					leaves[index] = result.total(child)
				}
			}
			info.fillWeights(leaves)
		}
	}
	return result, nil
}

// fillWeights records every on-path node with its requested-leaf weight.
func (info *treeInfo) fillWeights(leaves map[int64]int64) {
	current := leaves
	for level := int32(0); ; level++ {
		next := make(map[int64]int64, len(current))
		for index, weight := range current {
			info.weight[hpp.NodePosition{Level: level, Index: index}] = weight
			next[index/2] += weight
		}
		if level >= info.height {
			return
		}
		current = next
	}
}

// total is the number of requested leaves beneath a tree.
func (s *structure) total(tree hpp.TreeRef) int64 {
	info, ok := s.trees[tree]
	if !ok {
		return 0
	}
	return info.weight[hpp.NodePosition{Level: info.height, Index: 0}]
}

func (info *treeInfo) top() hpp.NodePosition {
	return hpp.NodePosition{Level: info.height, Index: 0}
}

func (info *treeInfo) onPath(position hpp.NodePosition) bool {
	_, ok := info.weight[position]
	return ok
}

// descendable reports whether a node is an on-path interior node, the only
// kind the auditor has query-derived structure beneath.
func (info *treeInfo) descendable(position hpp.NodePosition) bool {
	return position.Level > 0 && info.onPath(position)
}

// children returns the existing children of an interior position: the left
// child always, the right child unless the level's odd node is promoted.
func (info *treeInfo) children(position hpp.NodePosition) []hpp.NodePosition {
	return childrenOf(info.widths, position)
}

func childrenOf(widths []int64, position hpp.NodePosition) []hpp.NodePosition {
	if position.Level <= 0 || int(position.Level) >= len(widths) {
		return nil
	}
	childLevel := position.Level - 1
	result := []hpp.NodePosition{{Level: childLevel, Index: position.Index * 2}}
	if position.Index*2+1 < widths[childLevel] {
		result = append(result, hpp.NodePosition{Level: childLevel, Index: position.Index*2 + 1})
	}
	return result
}

func lessPosition(left, right hpp.NodePosition) bool {
	if left.Level != right.Level {
		return left.Level > right.Level
	}
	return left.Index < right.Index
}

func sortPositions(positions []hpp.NodePosition) {
	sort.Slice(positions, func(i, j int) bool { return lessPosition(positions[i], positions[j]) })
}

// frontierOf derives the retrieved frontier from an expanded set: the children
// of every expanded node that are not themselves expanded, in canonical order.
// It reports false if the set is not a valid expansion rooted at root: every
// expanded node must be an on-path interior node reachable from root through
// expanded nodes.
func (info *treeInfo) frontierOf(root hpp.NodePosition, expanded []hpp.NodePosition) ([]hpp.NodePosition, bool) {
	if len(expanded) == 0 {
		return nil, false
	}
	set := make(map[hpp.NodePosition]struct{}, len(expanded))
	for _, position := range expanded {
		if _, duplicate := set[position]; duplicate || !info.descendable(position) {
			return nil, false
		}
		set[position] = struct{}{}
	}
	if _, ok := set[root]; !ok {
		return nil, false
	}
	// Every expanded node other than root must have an expanded parent.
	for position := range set {
		if position == root {
			continue
		}
		parent := hpp.NodePosition{Level: position.Level + 1, Index: position.Index / 2}
		if _, ok := set[parent]; !ok {
			return nil, false
		}
	}
	var frontier []hpp.NodePosition
	for position := range set {
		for _, child := range info.children(position) {
			if _, expandedChild := set[child]; !expandedChild {
				frontier = append(frontier, child)
			}
		}
	}
	sortPositions(frontier)
	return frontier, true
}
