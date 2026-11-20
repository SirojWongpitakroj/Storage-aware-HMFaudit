package hpp

import (
	"cmp"
	"crypto/subtle"
	"fmt"
	"slices"
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
	// requestedHashes[i] is the hash of the leaf at proof.Plan.Addresses[i].
	requestedHashes, err := validateProofLeaves(proof.Plan.Addresses, addresses, proof.Leaves)
	if err != nil {
		return ProofTrace{}, err
	}

	plans := make(map[TreeRef]TreePlan, len(proof.Plan.Trees))
	treeNodes := make(map[TreeRef]*proofNodeSet, len(proof.Plan.Trees))
	for _, tree := range proof.Plan.Trees {
		if _, duplicate := plans[tree.Tree]; duplicate {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: duplicate plan for tree %+v", tree.Tree)
		}
		if err := validateTreePlanShape(tree); err != nil {
			return ProofTrace{}, err
		}
		plans[tree.Tree] = tree
		treeNodes[tree.Tree] = newProofNodeSet(len(tree.Required))
	}

	// A validated plan lists Required in canonical (level, index) order, so a supplied node's slot is
	// found by binary search, and the supplied hashes sit in a slice aligned with Required.
	for _, node := range proof.Nodes {
		plan, known := plans[node.Ref.Tree]
		slot := -1
		if known {
			slot = positionIndex(plan.Required, node.Ref.Position)
		}
		if slot < 0 {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: unexpected proof node %+v", node.Ref)
		}
		nodes := treeNodes[node.Ref.Tree]
		if nodes.present[slot] {
			return ProofTrace{}, fmt.Errorf("verify HMF proof: duplicate proof node %+v", node.Ref)
		}
		nodes.hashes[slot] = node.Hash
		nodes.present[slot] = true
		nodes.count++
	}
	for tree, plan := range plans {
		nodes := treeNodes[tree]
		if nodes.count == len(plan.Required) {
			continue
		}
		for slot, position := range plan.Required {
			if !nodes.present[slot] {
				return ProofTrace{}, fmt.Errorf("verify HMF proof: missing proof node %+v",
					NodeRef{Tree: tree, Position: position})
			}
		}
	}

	// validateProofLeaves proved Plan.Addresses is sorted and distinct, so each segment's leaves
	// are one ascending run.
	segmentLeaves := make(map[TreeRef][]indexedHash)
	for index, address := range proof.Plan.Addresses {
		tree := segmentTree(SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID})
		segmentLeaves[tree] = append(segmentLeaves[tree], indexedHash{index: address.LeafID, hash: requestedHashes[index]})
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
			var known []indexedHash
			if layer == LayerSegment {
				known = segmentLeaves[treeRef]
			} else {
				known = make([]indexedHash, 0, len(children[treeRef]))
				for index, child := range children[treeRef] {
					rawRoot, exists := roots[child]
					if !exists {
						return ProofTrace{}, fmt.Errorf("verify HMF proof: root unavailable for child %+v", child)
					}
					known = append(known, indexedHash{index: index, hash: committedRoot(child, plans[child].LeafCount, rawRoot)})
				}
				slices.SortFunc(known, func(left, right indexedHash) int { return cmp.Compare(left.index, right.index) })
			}
			if err := validateTargets(treePlan, known); err != nil {
				return ProofTrace{}, err
			}
			var traced map[NodeRef][32]byte
			if record {
				traced = trace.Nodes
			}
			root, err := reconstructTreeTrace(treePlan.LeafCount, known, treeNodes[treeRef], treePlan.Required, treeRef, traced)
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
	// The targets must be distinct; they are sorted into a scratch copy so that no lookup set is built.
	sorted := slices.Clone(plan.Targets)
	slices.Sort(sorted)
	for index := 1; index < len(sorted); index++ {
		if sorted[index] == sorted[index-1] {
			return fmt.Errorf("verify HMF proof: duplicate target %d for tree %+v", sorted[index], plan.Tree)
		}
	}
	if plan.LeafCount <= 0 {
		return fmt.Errorf("verify HMF proof: invalid tree plan: %w",
			fmt.Errorf("HPP: tree %+v must contain at least one leaf", plan.Tree))
	}
	if len(sorted) == 0 {
		return fmt.Errorf("verify HMF proof: invalid tree plan: %w",
			fmt.Errorf("HPP: tree %+v has no target leaves", plan.Tree))
	}
	for _, target := range sorted {
		if target < 0 || target >= plan.LeafCount {
			return fmt.Errorf("verify HMF proof: invalid tree plan: %w",
				fmt.Errorf("HPP: target leaf %d outside tree %+v", target, plan.Tree))
		}
	}
	weights := make([]int64, len(sorted))
	for index := range weights {
		weights[index] = 1
	}
	canonical, err := planSortedTree(plan.Tree, plan.LeafCount, sorted, weights)
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

// validateProofLeaves checks the requested addresses and the supplied leaves against the plan and returns
// the leaf hashes in plan address order (result[i] belongs to planned[i]).
func validateProofLeaves(planned, requested []PhysicalAddress, leaves []RequestedLeaf) ([][32]byte, error) {
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
	// planned equals the normalized request, so it is sorted and distinct: leaves that arrive in plan
	// order (a proof builder's own output) match it element by element.
	inOrder := len(leaves) == len(planned)
	for index := 0; inOrder && index < len(leaves); index++ {
		inOrder = leaves[index].Address == planned[index]
	}
	result := make([][32]byte, len(planned))
	if inOrder {
		for index := range leaves {
			result[index] = leaves[index].Hash
		}
		return result, nil
	}

	byAddress := make(map[PhysicalAddress][32]byte, len(leaves))
	for _, leaf := range leaves {
		if _, duplicate := byAddress[leaf.Address]; duplicate {
			return nil, fmt.Errorf("verify HMF proof: duplicate target leaf for address %+v", leaf.Address)
		}
		byAddress[leaf.Address] = leaf.Hash
	}
	if len(byAddress) != len(planned) {
		return nil, fmt.Errorf("verify HMF proof: target leaves do not match proof plan")
	}
	for index, address := range planned {
		hash, exists := byAddress[address]
		if !exists {
			return nil, fmt.Errorf("verify HMF proof: target leaf missing for address %+v", address)
		}
		result[index] = hash
	}
	return result, nil
}

// validateTargets requires known (ascending, distinct) to hold exactly the plan's target leaves.
func validateTargets(plan TreePlan, known []indexedHash) error {
	if len(known) != len(plan.Targets) {
		return fmt.Errorf("verify HMF proof: tree %+v has %d known leaves, want %d",
			plan.Tree, len(known), len(plan.Targets))
	}
	next := 0
	for _, target := range plan.Targets {
		for next < len(known) && known[next].index < target {
			next++
		}
		if next == len(known) || known[next].index != target {
			return fmt.Errorf("verify HMF proof: target leaf %d missing for tree %+v", target, plan.Tree)
		}
	}
	return nil
}

type indexedHash struct {
	index int64
	hash  [32]byte
}

// proofNodeSet holds the supplied authentication nodes of one tree in a slice aligned with the plan's
// Required list: hashes[i] is the node Required[i] when present[i] is set.
type proofNodeSet struct {
	hashes  [][32]byte
	present []bool
	count   int
}

func newProofNodeSet(size int) *proofNodeSet {
	return &proofNodeSet{hashes: make([][32]byte, size), present: make([]bool, size)}
}

// reconstructTreeRoot rebuilds a tree's raw root from known leaves and a set of proof nodes held in maps.
func reconstructTreeRoot(leafCount int64, knownLeaves map[int64][32]byte,
	proofNodes map[NodePosition][32]byte) ([32]byte, error) {

	known := make([]indexedHash, 0, len(knownLeaves))
	for index, hash := range knownLeaves {
		known = append(known, indexedHash{index: index, hash: hash})
	}
	required := make([]NodePosition, 0, len(proofNodes))
	for position := range proofNodes {
		required = append(required, position)
	}
	slices.SortFunc(required, func(left, right NodePosition) int {
		if left.Level != right.Level {
			return cmp.Compare(left.Level, right.Level)
		}
		return cmp.Compare(left.Index, right.Index)
	})
	nodes := newProofNodeSet(len(required))
	for slot, position := range required {
		nodes.hashes[slot] = proofNodes[position]
		nodes.present[slot] = true
		nodes.count++
	}
	return reconstructTreeTrace(leafCount, known, nodes, required, TreeRef{}, nil)
}

// reconstructTreeTrace folds the known leaves and proof nodes up to the tree's raw root, walking each
// level as a sorted slice. The proof nodes are consumed in the plan's canonical order, so each one is
// read from its slot with a cursor. When out is non-nil every supplied and reconstructed node of tree
// is recorded in it.
func reconstructTreeTrace(leafCount int64, knownLeaves []indexedHash, nodes *proofNodeSet,
	required []NodePosition, tree TreeRef, out map[NodeRef][32]byte) ([32]byte, error) {

	if leafCount <= 0 || len(knownLeaves) == 0 {
		return [32]byte{}, fmt.Errorf("invalid tree leaf count or empty target set")
	}
	current := make([]indexedHash, len(knownLeaves))
	copy(current, knownLeaves)
	for _, leaf := range current {
		if leaf.index < 0 || leaf.index >= leafCount {
			return [32]byte{}, fmt.Errorf("known leaf index %d out of range", leaf.index)
		}
		if out != nil {
			out[NodeRef{Tree: tree, Position: NodePosition{Level: 0, Index: leaf.index}}] = leaf.hash
		}
	}
	if !slices.IsSortedFunc(current, func(left, right indexedHash) int { return cmp.Compare(left.index, right.index) }) {
		slices.SortFunc(current, func(left, right indexedHash) int { return cmp.Compare(left.index, right.index) })
	}
	if out != nil {
		for slot, position := range required {
			if nodes.present[slot] {
				out[NodeRef{Tree: tree, Position: position}] = nodes.hashes[slot]
			}
		}
	}

	used := 0
	cursor := 0
	proofAt := func(position NodePosition) ([32]byte, error) {
		slot := cursor
		if slot >= len(required) || required[slot] != position {
			slot = positionIndex(required, position)
		}
		if slot < 0 || !nodes.present[slot] {
			return [32]byte{}, fmt.Errorf("missing proof node at level %d index %d", position.Level, position.Index)
		}
		cursor = slot + 1
		used++
		return nodes.hashes[slot], nil
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
	if supplied := nodes.count; used != supplied {
		return [32]byte{}, fmt.Errorf("%d of %d proof nodes were unused", supplied-used, supplied)
	}
	return current[0].hash, nil
}

// positionIndex returns the index of position in the canonically ordered list, or -1.
func positionIndex(sorted []NodePosition, position NodePosition) int {
	index := sort.Search(len(sorted), func(i int) bool {
		if sorted[i].Level != position.Level {
			return sorted[i].Level > position.Level
		}
		return sorted[i].Index >= position.Index
	})
	if index < len(sorted) && sorted[index] == position {
		return index
	}
	return -1
}
