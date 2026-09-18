package localization

import (
	"sort"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

type treeShape struct {
	leafCount int64
	children  map[int64]hpp.TreeRef
}

func analyze(addresses []hpp.PhysicalAddress, auditorProof, referenceProof hpp.HMFProof,
	auditor, reference hpp.ProofTrace, k int32) ([]hpp.TreeRef, []PruningRound, []Suspect) {

	auditorShapes := proofShapes(auditorProof)
	referenceShapes := proofShapes(referenceProof)
	trees := unionTrees(auditorShapes, referenceShapes)

	var badShards []hpp.TreeRef
	for _, tree := range trees {
		if tree.Layer != hpp.LayerShard {
			continue
		}
		left, leftOK := auditor.CommittedRoots[tree]
		right, rightOK := reference.CommittedRoots[tree]
		if !leftOK || !rightOK || !equalHash(left, right) {
			badShards = append(badShards, tree)
		}
	}

	addressByNode := make(map[hpp.NodeRef]hpp.PhysicalAddress, len(addresses))
	for _, address := range addresses {
		tree := hpp.TreeRef{Layer: hpp.LayerSegment, RegionID: address.RegionID,
			ShardID: address.ShardID, SegmentID: address.SegmentID}
		addressByNode[hpp.NodeRef{Tree: tree, Position: hpp.NodePosition{Level: 0, Index: address.LeafID}}] = address
	}

	var rounds []PruningRound
	var suspects []Suspect
	for _, tree := range trees {
		leftRoot, leftOK := auditor.CommittedRoots[tree]
		rightRoot, rightOK := reference.CommittedRoots[tree]
		if leftOK && rightOK && equalHash(leftRoot, rightRoot) {
			continue
		}
		leftShape, leftShapeOK := auditorShapes[tree]
		rightShape, rightShapeOK := referenceShapes[tree]
		if !leftOK || !rightOK || !leftShapeOK || !rightShapeOK || leftShape.leafCount != rightShape.leafCount {
			suspects = append(suspects, topologySuspect(tree, auditor, reference,
				maxInt32(treeHeight(leftShape.leafCount), treeHeight(rightShape.leafCount))))
			continue
		}

		active := []hpp.NodePosition{{Level: treeHeight(leftShape.leafCount), Index: 0}}
		for len(active) > 0 {
			from := active[0].Level
			target := from - k
			if target < 0 {
				target = 0
			}
			frontierSet := make(map[hpp.NodePosition]struct{})
			for _, position := range active {
				collectFrontier(tree, position, target, auditor.Nodes, reference.Nodes, frontierSet)
			}
			frontier := sortedPositions(frontierSet)
			round := PruningRound{Tree: tree, FromLevel: from, TargetLevel: target}
			var next []hpp.NodePosition
			for _, position := range frontier {
				ref := hpp.NodeRef{Tree: tree, Position: position}
				left, leftExists := auditor.Nodes[ref]
				right, rightExists := reference.Nodes[ref]
				match := leftExists && rightExists && equalHash(left, right)
				round.Comparisons = append(round.Comparisons, NodeComparison{
					Ref: ref, AuditorHash: left, ReferenceHash: right, Match: match,
				})
				if match {
					continue
				}
				if position.Level == 0 {
					if child, exists := rightShape.children[position.Index]; exists && treeMismatch(child, auditor, reference) {
						continue
					}
					suspects = append(suspects, nodeSuspect(ref, left, right, addressByNode))
					continue
				}
				if canDescend(tree, position, auditor.Nodes, reference.Nodes) {
					next = append(next, position)
				} else {
					suspects = append(suspects, Suspect{Ref: ref, AuditorHash: left,
						ReferenceHash: right, Classification: AuthenticationNodeMismatch})
				}
			}
			if len(round.Comparisons) > 0 {
				rounds = append(rounds, round)
			}
			active = next
		}
	}
	sort.Slice(suspects, func(i, j int) bool { return lessNodeRef(suspects[i].Ref, suspects[j].Ref) })
	return badShards, rounds, suspects
}

func proofShapes(proof hpp.HMFProof) map[hpp.TreeRef]treeShape {
	result := make(map[hpp.TreeRef]treeShape, len(proof.Plan.Trees))
	for _, plan := range proof.Plan.Trees {
		result[plan.Tree] = treeShape{leafCount: plan.LeafCount, children: make(map[int64]hpp.TreeRef)}
	}
	for _, link := range proof.Plan.ParentLinks {
		shape := result[link.Parent]
		shape.children[link.ParentLeafIndex] = link.Child
		result[link.Parent] = shape
	}
	return result
}

func unionTrees(left, right map[hpp.TreeRef]treeShape) []hpp.TreeRef {
	set := make(map[hpp.TreeRef]struct{}, len(left)+len(right))
	for tree := range left {
		set[tree] = struct{}{}
	}
	for tree := range right {
		set[tree] = struct{}{}
	}
	result := make([]hpp.TreeRef, 0, len(set))
	for tree := range set {
		result = append(result, tree)
	}
	sort.Slice(result, func(i, j int) bool { return lessTree(result[i], result[j]) })
	return result
}

func collectFrontier(tree hpp.TreeRef, position hpp.NodePosition, target int32,
	left, right map[hpp.NodeRef][32]byte, result map[hpp.NodePosition]struct{}) {

	if position.Level <= target || !canDescend(tree, position, left, right) {
		result[position] = struct{}{}
		return
	}
	childLevel := position.Level - 1
	for _, index := range []int64{position.Index * 2, position.Index*2 + 1} {
		child := hpp.NodeRef{Tree: tree, Position: hpp.NodePosition{Level: childLevel, Index: index}}
		_, leftOK := left[child]
		_, rightOK := right[child]
		if leftOK || rightOK {
			collectFrontier(tree, child.Position, target, left, right, result)
		}
	}
}

func canDescend(tree hpp.TreeRef, position hpp.NodePosition,
	left, right map[hpp.NodeRef][32]byte) bool {

	if position.Level <= 0 {
		return false
	}
	childLevel := position.Level - 1
	first := hpp.NodeRef{Tree: tree, Position: hpp.NodePosition{Level: childLevel, Index: position.Index * 2}}
	_, leftOK := left[first]
	_, rightOK := right[first]
	return leftOK && rightOK
}

func treeMismatch(tree hpp.TreeRef, left, right hpp.ProofTrace) bool {
	leftRoot, leftOK := left.CommittedRoots[tree]
	rightRoot, rightOK := right.CommittedRoots[tree]
	return !leftOK || !rightOK || !equalHash(leftRoot, rightRoot)
}

func nodeSuspect(ref hpp.NodeRef, left, right [32]byte,
	addresses map[hpp.NodeRef]hpp.PhysicalAddress) Suspect {

	result := Suspect{Ref: ref, AuditorHash: left, ReferenceHash: right,
		Classification: AuthenticationNodeMismatch}
	if address, exists := addresses[ref]; exists {
		copy := address
		result.Address = &copy
		result.Classification = LeafMismatch
	}
	return result
}

func topologySuspect(tree hpp.TreeRef, left, right hpp.ProofTrace, level int32) Suspect {
	ref := hpp.NodeRef{Tree: tree, Position: hpp.NodePosition{Level: level, Index: 0}}
	return Suspect{Ref: ref, AuditorHash: left.CommittedRoots[tree],
		ReferenceHash: right.CommittedRoots[tree], Classification: TopologyMismatch}
}

func treeHeight(leafCount int64) int32 {
	var height int32
	for leafCount > 1 {
		leafCount = (leafCount + 1) / 2
		height++
	}
	return height
}

func maxInt32(left, right int32) int32 {
	if left > right {
		return left
	}
	return right
}

func sortedPositions(set map[hpp.NodePosition]struct{}) []hpp.NodePosition {
	result := make([]hpp.NodePosition, 0, len(set))
	for position := range set {
		result = append(result, position)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Level != result[j].Level {
			return result[i].Level > result[j].Level
		}
		return result[i].Index < result[j].Index
	})
	return result
}

func lessTree(left, right hpp.TreeRef) bool {
	if left.Layer != right.Layer {
		return left.Layer < right.Layer
	}
	if left.RegionID != right.RegionID {
		return left.RegionID < right.RegionID
	}
	if left.ShardID != right.ShardID {
		return left.ShardID < right.ShardID
	}
	return left.SegmentID < right.SegmentID
}

func lessNodeRef(left, right hpp.NodeRef) bool {
	if left.Tree != right.Tree {
		return lessTree(left.Tree, right.Tree)
	}
	if left.Position.Level != right.Position.Level {
		return left.Position.Level < right.Position.Level
	}
	return left.Position.Index < right.Position.Index
}
