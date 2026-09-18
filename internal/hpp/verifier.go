package hpp

import (
	"crypto/subtle"
	"fmt"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
)

func VerifyHMFProof(proof HMFProof, addresses []PhysicalAddress) ([32]byte, error) {
	requestedHashes, err := validateProofLeaves(proof.Plan.Addresses, addresses, proof.Leaves)
	if err != nil {
		return [32]byte{}, err
	}

	plans := make(map[TreeRef]TreePlan, len(proof.Plan.Trees))
	expectedNodes := make(map[NodeRef]struct{})
	for _, tree := range proof.Plan.Trees {
		if _, duplicate := plans[tree.Tree]; duplicate {
			return [32]byte{}, fmt.Errorf("verify HMF proof: duplicate plan for tree %+v", tree.Tree)
		}
		if err := validateTreePlanShape(tree); err != nil {
			return [32]byte{}, err
		}
		plans[tree.Tree] = tree
		for _, position := range tree.Required {
			expectedNodes[NodeRef{Tree: tree.Tree, Position: position}] = struct{}{}
		}
	}

	nodes := make(map[NodeRef][32]byte, len(proof.Nodes))
	for _, node := range proof.Nodes {
		if _, expected := expectedNodes[node.Ref]; !expected {
			return [32]byte{}, fmt.Errorf("verify HMF proof: unexpected proof node %+v", node.Ref)
		}
		if _, duplicate := nodes[node.Ref]; duplicate {
			return [32]byte{}, fmt.Errorf("verify HMF proof: duplicate proof node %+v", node.Ref)
		}
		nodes[node.Ref] = node.Hash
	}
	for expected := range expectedNodes {
		if _, exists := nodes[expected]; !exists {
			return [32]byte{}, fmt.Errorf("verify HMF proof: missing proof node %+v", expected)
		}
	}

	children := make(map[TreeRef]map[int64]TreeRef)
	parentOf := make(map[TreeRef]TreeRef)
	for _, link := range proof.Plan.ParentLinks {
		if _, exists := plans[link.Child]; !exists {
			return [32]byte{}, fmt.Errorf("verify HMF proof: parent link references unknown child %+v", link.Child)
		}
		if _, exists := plans[link.Parent]; !exists {
			return [32]byte{}, fmt.Errorf("verify HMF proof: parent link references unknown parent %+v", link.Parent)
		}
		if !validParentLink(link.Child, link.Parent) {
			return [32]byte{}, fmt.Errorf("verify HMF proof: invalid hierarchy link %+v -> %+v", link.Child, link.Parent)
		}
		if _, duplicate := parentOf[link.Child]; duplicate {
			return [32]byte{}, fmt.Errorf("verify HMF proof: tree %+v has multiple parent links", link.Child)
		}
		parentOf[link.Child] = link.Parent
		if children[link.Parent] == nil {
			children[link.Parent] = make(map[int64]TreeRef)
		}
		if existing, duplicate := children[link.Parent][link.ParentLeafIndex]; duplicate && existing != link.Child {
			return [32]byte{}, fmt.Errorf("verify HMF proof: conflicting children at leaf %d of %+v",
				link.ParentLeafIndex, link.Parent)
		}
		children[link.Parent][link.ParentLeafIndex] = link.Child
	}
	for tree := range plans {
		if tree.Layer == LayerGlobal {
			if tree != globalTree() {
				return [32]byte{}, fmt.Errorf("verify HMF proof: invalid global tree identity %+v", tree)
			}
			continue
		}
		if _, exists := parentOf[tree]; !exists {
			return [32]byte{}, fmt.Errorf("verify HMF proof: tree %+v is not linked to the global hierarchy", tree)
		}
	}

	roots := make(map[TreeRef][32]byte, len(plans))
	for layer := LayerSegment; layer <= LayerGlobal; layer++ {
		for treeRef, treePlan := range plans {
			if treeRef.Layer != layer {
				continue
			}
			known := make(map[int64][32]byte)
			if layer == LayerSegment {
				for address, hash := range requestedHashes {
					if address.RegionID == treeRef.RegionID && address.ShardID == treeRef.ShardID && address.SegmentID == treeRef.SegmentID {
						known[address.LeafID] = hash
					}
				}
			} else {
				for index, child := range children[treeRef] {
					rawRoot, exists := roots[child]
					if !exists {
						return [32]byte{}, fmt.Errorf("verify HMF proof: root unavailable for child %+v", child)
					}
					known[index] = committedRoot(child, plans[child].LeafCount, rawRoot)
				}
			}
			if err := validateTargets(treePlan, known); err != nil {
				return [32]byte{}, err
			}
			treeNodes := make(map[NodePosition][32]byte, len(treePlan.Required))
			for _, position := range treePlan.Required {
				treeNodes[position] = nodes[NodeRef{Tree: treeRef, Position: position}]
			}
			root, err := reconstructTreeRoot(treePlan.LeafCount, known, treeNodes)
			if err != nil {
				return [32]byte{}, fmt.Errorf("verify HMF proof tree %+v: %w", treeRef, err)
			}
			roots[treeRef] = root
		}
	}

	root, exists := roots[globalTree()]
	if !exists {
		return [32]byte{}, fmt.Errorf("verify HMF proof: global tree root was not reconstructed")
	}
	return committedRoot(globalTree(), plans[globalTree()].LeafCount, root), nil
}

// TraceHMFProof verifies the proof and returns the complete deduplicated DAG
// of supplied and reconstructed nodes used by that verification.
func TraceHMFProof(proof HMFProof, addresses []PhysicalAddress) (ProofTrace, error) {
	globalRoot, err := VerifyHMFProof(proof, addresses)
	if err != nil {
		return ProofTrace{}, err
	}
	plans := make(map[TreeRef]TreePlan, len(proof.Plan.Trees))
	for _, plan := range proof.Plan.Trees {
		plans[plan.Tree] = plan
	}
	children := make(map[TreeRef]map[int64]TreeRef)
	for _, link := range proof.Plan.ParentLinks {
		if children[link.Parent] == nil {
			children[link.Parent] = make(map[int64]TreeRef)
		}
		children[link.Parent][link.ParentLeafIndex] = link.Child
	}
	proofNodes := make(map[NodeRef][32]byte, len(proof.Nodes))
	for _, node := range proof.Nodes {
		proofNodes[node.Ref] = node.Hash
	}
	leafHashes := make(map[PhysicalAddress][32]byte, len(proof.Leaves))
	for _, leaf := range proof.Leaves {
		leafHashes[leaf.Address] = leaf.Hash
	}

	trace := ProofTrace{
		GlobalRoot: globalRoot, RawRoots: make(map[TreeRef][32]byte, len(plans)),
		CommittedRoots: make(map[TreeRef][32]byte, len(plans)), Nodes: make(map[NodeRef][32]byte),
	}
	for layer := LayerSegment; layer <= LayerGlobal; layer++ {
		for treeRef, treePlan := range plans {
			if treeRef.Layer != layer {
				continue
			}
			known := make(map[int64][32]byte)
			if layer == LayerSegment {
				for address, hash := range leafHashes {
					if address.RegionID == treeRef.RegionID && address.ShardID == treeRef.ShardID &&
						address.SegmentID == treeRef.SegmentID {
						known[address.LeafID] = hash
					}
				}
			} else {
				for index, child := range children[treeRef] {
					known[index] = trace.CommittedRoots[child]
				}
			}
			treeProofNodes := make(map[NodePosition][32]byte, len(treePlan.Required))
			for _, position := range treePlan.Required {
				treeProofNodes[position] = proofNodes[NodeRef{Tree: treeRef, Position: position}]
			}
			rawRoot, expanded, err := reconstructTreeTrace(treePlan.LeafCount, known, treeProofNodes)
			if err != nil {
				return ProofTrace{}, fmt.Errorf("trace HMF proof tree %+v: %w", treeRef, err)
			}
			trace.RawRoots[treeRef] = rawRoot
			trace.CommittedRoots[treeRef] = committedRoot(treeRef, treePlan.LeafCount, rawRoot)
			for position, hash := range expanded {
				trace.Nodes[NodeRef{Tree: treeRef, Position: position}] = hash
			}
		}
	}
	return trace, nil
}

func committedRoot(tree TreeRef, leafCount int64, rawRoot [32]byte) [32]byte {
	switch tree.Layer {
	case LayerSegment:
		return hmf.CommitSegmentRoot(tree.RegionID, tree.ShardID, tree.SegmentID, leafCount, rawRoot)
	case LayerShard:
		return hmf.CommitShardRoot(tree.RegionID, tree.ShardID, leafCount, rawRoot)
	case LayerRegion:
		return hmf.CommitRegionRoot(tree.RegionID, leafCount, rawRoot)
	case LayerGlobal:
		return hmf.CommitGlobalRoot(leafCount, rawRoot)
	default:
		return [32]byte{}
	}
}

func validateTreePlanShape(plan TreePlan) error {
	targets := make(map[int64]struct{}, len(plan.Targets))
	for _, target := range plan.Targets {
		if _, duplicate := targets[target]; duplicate {
			return fmt.Errorf("verify HMF proof: duplicate target %d for tree %+v", target, plan.Tree)
		}
		targets[target] = struct{}{}
	}
	canonical, err := planTree(plan.Tree, plan.LeafCount, targets)
	if err != nil {
		return fmt.Errorf("verify HMF proof: invalid tree plan: %w", err)
	}
	if len(canonical.Targets) != len(plan.Targets) || len(canonical.Required) != len(plan.Required) {
		return fmt.Errorf("verify HMF proof: noncanonical plan for tree %+v", plan.Tree)
	}
	for index := range canonical.Targets {
		if canonical.Targets[index] != plan.Targets[index] {
			return fmt.Errorf("verify HMF proof: unsorted or incorrect targets for tree %+v", plan.Tree)
		}
	}
	for index := range canonical.Required {
		if canonical.Required[index] != plan.Required[index] {
			return fmt.Errorf("verify HMF proof: incorrect required nodes for tree %+v", plan.Tree)
		}
	}
	return nil
}

func validParentLink(child, parent TreeRef) bool {
	if parent.Layer != child.Layer+1 {
		return false
	}
	switch child.Layer {
	case LayerSegment:
		return parent.RegionID == child.RegionID && parent.ShardID == child.ShardID && parent.SegmentID == 0
	case LayerShard:
		return parent.RegionID == child.RegionID && parent.ShardID == 0 && parent.SegmentID == 0
	case LayerRegion:
		return parent == globalTree()
	default:
		return false
	}
}

func VerifyHMFProofAgainstRoot(proof HMFProof, addresses []PhysicalAddress,
	trustedRoot [32]byte) ([32]byte, error) {

	calculated, err := VerifyHMFProof(proof, addresses)
	if err != nil {
		return [32]byte{}, err
	}
	if subtle.ConstantTimeCompare(calculated[:], trustedRoot[:]) != 1 {
		return calculated, fmt.Errorf("verify HMF proof: calculated global root does not match trusted root")
	}
	return calculated, nil
}

func validateProofLeaves(planned, requested []PhysicalAddress,
	leaves []RequestedLeaf) (map[PhysicalAddress][32]byte, error) {

	normalized, err := normalizeAddresses(requested)
	if err != nil {
		return nil, err
	}
	if len(normalized) != len(planned) {
		return nil, fmt.Errorf("verify HMF proof: requested addresses do not match proof plan")
	}
	for index := range normalized {
		if normalized[index] != planned[index] {
			return nil, fmt.Errorf("verify HMF proof: requested address %d does not match proof plan", index)
		}
	}

	result := make(map[PhysicalAddress][32]byte, len(leaves))
	for _, leaf := range leaves {
		if _, duplicate := result[leaf.Address]; duplicate {
			return nil, fmt.Errorf("verify HMF proof: duplicate target leaf for address %+v", leaf.Address)
		}
		result[leaf.Address] = leaf.Hash
	}
	if len(result) != len(planned) {
		return nil, fmt.Errorf("verify HMF proof: target leaves do not match proof plan")
	}
	for _, address := range planned {
		if _, exists := result[address]; !exists {
			return nil, fmt.Errorf("verify HMF proof: target leaf missing for address %+v", address)
		}
	}
	return result, nil
}

func validateTargets(plan TreePlan, known map[int64][32]byte) error {
	if len(known) != len(plan.Targets) {
		return fmt.Errorf("verify HMF proof: tree %+v has %d known leaves, want %d",
			plan.Tree, len(known), len(plan.Targets))
	}
	for _, target := range plan.Targets {
		if _, exists := known[target]; !exists {
			return fmt.Errorf("verify HMF proof: target leaf %d missing for tree %+v", target, plan.Tree)
		}
	}
	return nil
}

func reconstructTreeRoot(leafCount int64, knownLeaves map[int64][32]byte,
	proofNodes map[NodePosition][32]byte) ([32]byte, error) {
	root, _, err := reconstructTreeTrace(leafCount, knownLeaves, proofNodes)
	return root, err
}

func reconstructTreeTrace(leafCount int64, knownLeaves map[int64][32]byte,
	proofNodes map[NodePosition][32]byte) ([32]byte, map[NodePosition][32]byte, error) {

	if leafCount <= 0 || len(knownLeaves) == 0 {
		return [32]byte{}, nil, fmt.Errorf("invalid tree leaf count or empty target set")
	}
	expanded := make(map[NodePosition][32]byte, len(knownLeaves)+len(proofNodes))
	current := make(map[int64][32]byte, len(knownLeaves))
	for index, hash := range knownLeaves {
		if index < 0 || index >= leafCount {
			return [32]byte{}, nil, fmt.Errorf("known leaf index %d out of range", index)
		}
		current[index] = hash
		expanded[NodePosition{Level: 0, Index: index}] = hash
	}
	for position, hash := range proofNodes {
		expanded[position] = hash
	}
	used := make(map[NodePosition]bool, len(proofNodes))
	width := leafCount
	level := int32(0)
	for width > 1 {
		parents := make(map[int64]struct{})
		for index := range current {
			parents[index/2] = struct{}{}
		}
		next := make(map[int64][32]byte, len(parents))
		for parentIndex := range parents {
			leftIndex := parentIndex * 2
			rightIndex := leftIndex + 1
			left, err := nodeHashAt(current, proofNodes, used, NodePosition{Level: level, Index: leftIndex})
			if err != nil {
				return [32]byte{}, nil, err
			}
			parent := left
			if rightIndex < width {
				right, err := nodeHashAt(current, proofNodes, used, NodePosition{Level: level, Index: rightIndex})
				if err != nil {
					return [32]byte{}, nil, err
				}
				parent = domain.HashPair("NODE", &left, &right)
			}
			next[parentIndex] = parent
			expanded[NodePosition{Level: level + 1, Index: parentIndex}] = parent
		}
		current = next
		width = (width + 1) / 2
		level++
	}
	if len(current) != 1 {
		return [32]byte{}, nil, fmt.Errorf("tree reconstruction produced %d roots", len(current))
	}
	for position := range proofNodes {
		if !used[position] {
			return [32]byte{}, nil, fmt.Errorf("unused proof node %+v", position)
		}
	}
	return current[0], expanded, nil
}

func nodeHashAt(current map[int64][32]byte, proof map[NodePosition][32]byte,
	used map[NodePosition]bool, position NodePosition) ([32]byte, error) {

	if hash, exists := current[position.Index]; exists {
		return hash, nil
	}
	hash, exists := proof[position]
	if !exists {
		return [32]byte{}, fmt.Errorf("missing proof node at level %d index %d", position.Level, position.Index)
	}
	used[position] = true
	return hash, nil
}
