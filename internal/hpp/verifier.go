package hpp

import (
	"crypto/subtle"
	"fmt"
	"sort"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
)

func VerifyHMFProof(proof HMFProof, addresses []PhysicalAddress) ([32]byte, error) {
	trace, err := evaluateHMFProof(proof, addresses, false)
	return trace.GlobalRoot, err
}

// TraceHMFProof verifies the proof and returns the complete deduplicated DAG
// of supplied and reconstructed nodes used by that verification.
func TraceHMFProof(proof HMFProof, addresses []PhysicalAddress) (ProofTrace, error) {
	return evaluateHMFProof(proof, addresses, true)
}

// evaluateHMFProof validates and reconstructs the proof in one pass. With
// record set it also returns every supplied and reconstructed node and each
// tree's raw and committed root; otherwise only GlobalRoot is set.
func evaluateHMFProof(proof HMFProof, addresses []PhysicalAddress, record bool) (ProofTrace, error) {
	requestedHashes, err := validateProofLeaves(proof.Plan.Addresses, addresses, proof.Leaves)
	if err != nil {
		return ProofTrace{}, err
	}

	plans := make(map[TreeRef]TreePlan, len(proof.Plan.Trees))
	treeNodes := make(map[TreeRef]map[NodePosition][32]byte, len(proof.Plan.Trees))
	for _, tree := range proof.Plan.Trees {
		if _, duplicate := plans[tree.Tree]; duplicate {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: duplicate plan for tree %+v", tree.Tree)
		}
		if err := validateTreePlanShape(tree); err != nil {
			return ProofTrace{}, err
		}
		plans[tree.Tree] = tree
		treeNodes[tree.Tree] = make(map[NodePosition][32]byte, len(tree.Required))
	}

	// A validated plan lists Required in canonical (level, index) order, so
	// membership is a binary search rather than a separate expected-node set.
	for _, node := range proof.Nodes {
		plan, known := plans[node.Ref.Tree]
		if !known || !containsPosition(plan.Required, node.Ref.Position) {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: unexpected proof node %+v", node.Ref)
		}
		nodes := treeNodes[node.Ref.Tree]
		if _, duplicate := nodes[node.Ref.Position]; duplicate {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: duplicate proof node %+v", node.Ref)
		}
		nodes[node.Ref.Position] = node.Hash
	}
	for tree, plan := range plans {
		nodes := treeNodes[tree]
		if len(nodes) == len(plan.Required) {
			continue
		}
		for _, position := range plan.Required {
			if _, exists := nodes[position]; !exists {
				return ProofTrace{}, fmt.Errorf("verify HMF proof: missing proof node %+v",
					NodeRef{Tree: tree, Position: position})
			}
		}
	}

	segmentLeaves := make(map[TreeRef]map[int64][32]byte)
	for address, hash := range requestedHashes {
		tree := segmentTree(SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID})
		if segmentLeaves[tree] == nil {
			segmentLeaves[tree] = make(map[int64][32]byte)
		}
		segmentLeaves[tree][address.LeafID] = hash
	}

	children := make(map[TreeRef]map[int64]TreeRef)
	parentOf := make(map[TreeRef]TreeRef)
	for _, link := range proof.Plan.ParentLinks {
		if _, exists := plans[link.Child]; !exists {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: parent link references unknown child %+v", link.Child)
		}
		if _, exists := plans[link.Parent]; !exists {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: parent link references unknown parent %+v", link.Parent)
		}
		if !validParentLink(link.Child, link.Parent) {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: invalid hierarchy link %+v -> %+v", link.Child, link.Parent)
		}
		if _, duplicate := parentOf[link.Child]; duplicate {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: tree %+v has multiple parent links", link.Child)
		}
		parentOf[link.Child] = link.Parent
		if children[link.Parent] == nil {
			children[link.Parent] = make(map[int64]TreeRef)
		}
		if existing, duplicate := children[link.Parent][link.ParentLeafIndex]; duplicate && existing != link.Child {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: conflicting children at leaf %d of %+v",
				link.ParentLeafIndex, link.Parent)
		}
		children[link.Parent][link.ParentLeafIndex] = link.Child
	}
	for tree := range plans {
		if tree.Layer == LayerGlobal {
			if tree != globalTree() {
				return ProofTrace{}, fmt.Errorf("verify HMF proof: invalid global tree identity %+v", tree)
			}
			continue
		}
		if _, exists := parentOf[tree]; !exists {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: tree %+v is not linked to the global hierarchy", tree)
		}
	}

	roots := make(map[TreeRef][32]byte, len(plans))
	var trace ProofTrace
	if record {
		trace = ProofTrace{
			RawRoots: make(map[TreeRef][32]byte, len(plans)), CommittedRoots: make(map[TreeRef][32]byte, len(plans)),
			Nodes: make(map[NodeRef][32]byte, 2*(len(proof.Nodes)+len(requestedHashes))),
		}
	}
	for layer := LayerSegment; layer <= LayerGlobal; layer++ {
		for treeRef, treePlan := range plans {
			if treeRef.Layer != layer {
				continue
			}
			var known map[int64][32]byte
			if layer == LayerSegment {
				known = segmentLeaves[treeRef]
			} else {
				known = make(map[int64][32]byte, len(children[treeRef]))
				for index, child := range children[treeRef] {
					rawRoot, exists := roots[child]
					if !exists {
						return ProofTrace{}, fmt.Errorf("verify HMF proof: root unavailable for child %+v", child)
					}
					known[index] = committedRoot(child, plans[child].LeafCount, rawRoot)
				}
			}
			if err := validateTargets(treePlan, known); err != nil {
				return ProofTrace{}, err
			}
			root, err := reconstructTreeTrace(treePlan.LeafCount, known, treeNodes[treeRef], treeRef, trace.Nodes)
			if err != nil {
				return ProofTrace{}, fmt.Errorf("verify HMF proof tree %+v: %w", treeRef, err)
			}
			roots[treeRef] = root
			if record {
				trace.RawRoots[treeRef] = root
				trace.CommittedRoots[treeRef] = committedRoot(treeRef, treePlan.LeafCount, root)
			}
		}
	}

	root, exists := roots[globalTree()]
	if !exists {
		return ProofTrace{}, fmt.Errorf("verify HMF proof: global tree root was not reconstructed")
	}
	trace.GlobalRoot = committedRoot(globalTree(), plans[globalTree()].LeafCount, root)
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
	return calculated, matchTrustedRoot(calculated, trustedRoot)
}

func matchTrustedRoot(calculated, trustedRoot [32]byte) error {
	if subtle.ConstantTimeCompare(calculated[:], trustedRoot[:]) != 1 {
		return fmt.Errorf("verify HMF proof: calculated global root does not match trusted root")
	}
	return nil
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
	return reconstructTreeTrace(leafCount, knownLeaves, proofNodes, TreeRef{}, nil)
}

type indexedHash struct {
	index int64
	hash  [32]byte
}

// reconstructTreeTrace folds the known leaves and proof nodes up to the
// tree's raw root, walking each level as a sorted slice. When out is non-nil
// every supplied and reconstructed node of tree is recorded in it.
func reconstructTreeTrace(leafCount int64, knownLeaves map[int64][32]byte,
	proofNodes map[NodePosition][32]byte, tree TreeRef, out map[NodeRef][32]byte) ([32]byte, error) {

	if leafCount <= 0 || len(knownLeaves) == 0 {
		return [32]byte{}, fmt.Errorf("invalid tree leaf count or empty target set")
	}
	current := make([]indexedHash, 0, len(knownLeaves))
	for index, hash := range knownLeaves {
		if index < 0 || index >= leafCount {
			return [32]byte{}, fmt.Errorf("known leaf index %d out of range", index)
		}
		current = append(current, indexedHash{index: index, hash: hash})
		if out != nil {
			out[NodeRef{Tree: tree, Position: NodePosition{Level: 0, Index: index}}] = hash
		}
	}
	sort.Slice(current, func(left, right int) bool { return current[left].index < current[right].index })
	if out != nil {
		for position, hash := range proofNodes {
			out[NodeRef{Tree: tree, Position: position}] = hash
		}
	}

	used := 0
	proofAt := func(position NodePosition) ([32]byte, error) {
		hash, exists := proofNodes[position]
		if !exists {
			return [32]byte{}, fmt.Errorf("missing proof node at level %d index %d", position.Level, position.Index)
		}
		used++
		return hash, nil
	}
	next := make([]indexedHash, 0, len(current))
	width := leafCount
	level := int32(0)
	for width > 1 {
		next = next[:0]
		for position := 0; position < len(current); {
			parentIndex := current[position].index / 2
			leftIndex := parentIndex * 2
			rightIndex := leftIndex + 1
			var left [32]byte
			if current[position].index == leftIndex {
				left = current[position].hash
				position++
			} else {
				hash, err := proofAt(NodePosition{Level: level, Index: leftIndex})
				if err != nil {
					return [32]byte{}, err
				}
				left = hash
			}
			parent := left
			if rightIndex < width {
				var right [32]byte
				if position < len(current) && current[position].index == rightIndex {
					right = current[position].hash
					position++
				} else {
					hash, err := proofAt(NodePosition{Level: level, Index: rightIndex})
					if err != nil {
						return [32]byte{}, err
					}
					right = hash
				}
				parent = domain.HashPair("NODE", &left, &right)
			}
			next = append(next, indexedHash{index: parentIndex, hash: parent})
			if out != nil {
				out[NodeRef{Tree: tree, Position: NodePosition{Level: level + 1, Index: parentIndex}}] = parent
			}
		}
		current, next = next, current
		width = (width + 1) / 2
		level++
	}
	if len(current) != 1 {
		return [32]byte{}, fmt.Errorf("tree reconstruction produced %d roots", len(current))
	}
	// Each position is looked up at most once, so every supplied node was
	// consumed exactly when the lookup count equals the number supplied.
	if used != len(proofNodes) {
		return [32]byte{}, fmt.Errorf("%d of %d proof nodes were unused", len(proofNodes)-used, len(proofNodes))
	}
	return current[0].hash, nil
}

// containsPosition reports whether sorted (canonical plan order) holds position.
func containsPosition(sorted []NodePosition, position NodePosition) bool {
	index := sort.Search(len(sorted), func(i int) bool {
		if sorted[i].Level != position.Level {
			return sorted[i].Level > position.Level
		}
		return sorted[i].Index >= position.Index
	})
	return index < len(sorted) && sorted[index] == position
}
