package hpp

import (
	"fmt"
	"sort"
)

// IndependentPlanResult is the output of PlanIndependent and, since both
// share the same shape, also of ExpandRequiredWithOccurrences: the retrieval
// requests each derived, plus diagnostic counts of how many auxiliary node
// positions were derived before and after deduplication.
type IndependentPlanResult struct {
	SegmentRequests []SegmentRequest
	UpperRequests   []UpperRequest
	// LogicalOccurrences counts every auxiliary node position derived across
	// all addresses, including repeats. UniqueNodes counts distinct node
	// identities requested. For an overlapping batch, LogicalOccurrences >
	// UniqueNodes.
	//
	// For PlanIndependent, UniqueNodes can also exceed the canonical joint
	// plan's required-node count: independent, per-address derivation cannot
	// recognize that a required sibling of one address coincides with an
	// ancestor (not a sibling) of another address's own path, which joint
	// planning would have made free. PlanIndependent's retrieval requests are
	// therefore a superset of the canonical minimal set, never a subset, so
	// fetching them is always sufficient to answer the same query -- but
	// doing so can cost genuinely unnecessary Cassandra reads, not just
	// duplicate ones. ExpandRequiredWithOccurrences does not have this
	// problem: UniqueNodes always equals the canonical joint plan's
	// required-node count exactly, since it reuses that canonical set rather
	// than re-deriving positions independently.
	LogicalOccurrences int
	UniqueNodes        int
}

// PlanIndependent is a benchmark-only alternative to Planner.Plan used to
// measure the NO_SHARED_PLANNING ablation described in the HMF-Audit
// component-ablation protocol. It never runs in production; it is additive
// to this package and does not change Planner.Plan's behavior, and it does
// not itself decide what a verifiable proof contains -- callers always build
// the final HMFProof.Plan from the unmodified Planner.Plan, and use
// PlanIndependent only to decide what to fetch from storage and to measure
// that ablated derivation's own cost.
//
// Planner.Plan derives authentication requirements jointly for the whole
// batch: requested addresses that are Merkle siblings, or that share an
// ancestor, never generate a redundant requirement, because planTree walks
// one merged sorted list of every active position per tree level. PlanIndependent
// instead derives each address's classic single-leaf authentication path
// independently, at every layer (Segment -> Shard -> Region -> Global), even
// when two addresses share a segment, shard, or region, by calling the same
// planTree helper once per address per layer instead of once per tree for
// the whole batch. This loses shared-path planning's benefit regardless of
// the dedup argument, so PlanIndependent alone can only produce the
// NO_SHARED_PLANNING configuration (shared planning off); see
// ExpandRequiredWithOccurrences for the NO_DEDUP configuration (shared
// planning on, dedup off).
//
//   - dedup=true (NO_SHARED_PLANNING): the independently-derived positions
//     are deduplicated by node identity before becoming the plan's retrieval
//     requests. This removes exact duplicate requirements (the same node
//     required by two different addresses' independent paths), but -- as
//     UniqueNodes' doc above explains -- it does not always shrink to
//     exactly Planner.Plan's minimal set, because pure identity-dedup cannot
//     recognize an ancestor/descendant relationship between two addresses'
//     independently-derived requirements the way joint planning does.
//   - dedup=false: the retrieval requests keep every duplicate occurrence, so
//     LogicalOccurrences exceeds UniqueNodes by the count of exact-duplicate
//     requirements. This configuration (shared planning AND dedup both off)
//     is diagnostic only; it is not used by any ablation variant, since the
//     ablation protocol isolates dedup's cost separately via
//     ExpandRequiredWithOccurrences.
func PlanIndependent(addresses []PhysicalAddress, metadata HierarchyMetadata, dedup bool) (IndependentPlanResult, error) {
	normalized, err := normalizeAddresses(addresses)
	if err != nil {
		return IndependentPlanResult{}, err
	}
	if len(normalized) == 0 {
		return IndependentPlanResult{}, fmt.Errorf("HPP: at least one physical address is required")
	}

	occurrences := make(map[TreeRef][]NodePosition) // raw per-address contributions, duplicates allowed
	targets := make(map[TreeRef]map[int64]struct{})

	addTarget := func(tree TreeRef, index int64) {
		if targets[tree] == nil {
			targets[tree] = make(map[int64]struct{})
		}
		targets[tree][index] = struct{}{}
	}
	derive := func(tree TreeRef, leafCount, targetIndex int64) error {
		addTarget(tree, targetIndex)
		plan, err := planTree(tree, leafCount, map[int64]int64{targetIndex: 1})
		if err != nil {
			return err
		}
		occurrences[tree] = append(occurrences[tree], plan.Required...)
		return nil
	}

	for _, address := range normalized {
		if err := addressChain(address, metadata, derive); err != nil {
			return IndependentPlanResult{}, err
		}
	}

	trees := make([]TreePlan, 0, len(targets))
	rawByTree := make(map[TreeRef][]NodePosition, len(occurrences))
	result := IndependentPlanResult{}
	for tree, targetSet := range targets {
		sortedTargets := make([]int64, 0, len(targetSet))
		for index := range targetSet {
			sortedTargets = append(sortedTargets, index)
		}
		sort.Slice(sortedTargets, func(i, j int) bool { return sortedTargets[i] < sortedTargets[j] })

		// A position independently derived by one address's path can coincide
		// with another address's own target leaf (e.g. two requested leaves
		// that are Merkle siblings); that target's hash is supplied directly,
		// not fetched as an auxiliary node.
		filtered := make([]NodePosition, 0, len(occurrences[tree]))
		for _, position := range occurrences[tree] {
			if position.Level == 0 {
				if _, isTarget := targetSet[position.Index]; isTarget {
					continue
				}
			}
			filtered = append(filtered, position)
		}
		result.LogicalOccurrences += len(filtered)

		unique := uniqueSortedPositions(filtered)
		result.UniqueNodes += len(unique)

		trees = append(trees, TreePlan{Tree: tree, Targets: sortedTargets})
		if dedup {
			rawByTree[tree] = unique
		} else {
			rawByTree[tree] = filtered
		}
	}
	sort.Slice(trees, func(i, j int) bool { return treeRefLess(trees[i].Tree, trees[j].Tree) })

	result.SegmentRequests, result.UpperRequests = buildRequestsFromOccurrences(trees, rawByTree)
	return result, nil
}

// addressChain walks one address's Segment -> Shard -> Region -> Global
// chain and calls visit once per layer with that layer's tree, leaf count,
// and the address's own target index within it. Only PlanIndependent uses
// this: ExpandRequiredWithOccurrences never re-derives a per-address path, so
// it has no need for this per-address traversal.
func addressChain(address PhysicalAddress, metadata HierarchyMetadata,
	visit func(tree TreeRef, leafCount, targetIndex int64) error) error {

	segKey := SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
	segment, exists := metadata.Segments[segKey]
	if !exists {
		return fmt.Errorf("HPP: metadata missing for segment %+v", segKey)
	}
	if !segment.Sealed {
		return fmt.Errorf("HPP: segment %+v is not sealed", segKey)
	}
	if address.LeafID >= segment.LeafCount {
		return fmt.Errorf("HPP: leaf %d outside segment %+v with %d leaves",
			address.LeafID, segKey, segment.LeafCount)
	}
	segTree := segmentTree(segKey)
	if err := visit(segTree, segment.LeafCount, address.LeafID); err != nil {
		return err
	}

	shardKey := ShardKey{RegionID: address.RegionID, ShardID: address.ShardID}
	shardMeta, exists := metadata.Shards[shardKey]
	if !exists {
		return fmt.Errorf("HPP: metadata missing for shard %+v", shardKey)
	}
	shTree := shardTree(shardKey)
	if err := visit(shTree, shardMeta.LeafCount, segment.ShardLeafIndex); err != nil {
		return err
	}

	regionMeta, exists := metadata.Regions[address.RegionID]
	if !exists {
		return fmt.Errorf("HPP: metadata missing for region %s", address.RegionID)
	}
	rTree := regionTree(address.RegionID)
	if err := visit(rTree, regionMeta.LeafCount, shardMeta.ParentLeafIndex); err != nil {
		return err
	}

	if metadata.Global.LeafCount <= 0 {
		return fmt.Errorf("HPP: global tree metadata is invalid")
	}
	gTree := globalTree()
	return visit(gTree, metadata.Global.LeafCount, regionMeta.ParentLeafIndex)
}

// ExpandRequiredWithOccurrences is a benchmark-only alternative to
// Planner.Plan used to measure the NO_DEDUP ablation described in the
// HMF-Audit component-ablation protocol: shared-path planning ON, dedup OFF
// (a node required by more than one address is requested once per requesting
// address, instead of once), retrieval partition-aware. It never runs in
// production.
//
// canonical must be the result of NewPlanner().Plan for the same addresses
// and metadata; callers that already compute it for the verifiable proof
// (every ablation variant does) pass it in rather than re-deriving it.
//
// Unlike a superseded implementation of this ablation, which re-derived every
// address's classic single-leaf path independently per layer (paying the same
// per-address, per-layer cost NO_SHARED_PLANNING pays, purely to reconstruct
// what the joint plan's duplicate-free Required list would have looked like
// with duplicates restored), this reuses canonical's own Required positions
// and their RequiredOccurrences counts directly -- both already computed by
// the single joint merge-walk in planTree that produced canonical itself. It
// costs only O(len(Required)) beyond canonical's own planning: no address's
// authentication path is ever re-derived.
func ExpandRequiredWithOccurrences(canonical ProofPlan) (IndependentPlanResult, error) {
	if len(canonical.Trees) == 0 {
		return IndependentPlanResult{}, fmt.Errorf("HPP: canonical plan has no trees")
	}

	trees := make([]TreePlan, 0, len(canonical.Trees))
	rawByTree := make(map[TreeRef][]NodePosition, len(canonical.Trees))
	result := IndependentPlanResult{}
	for _, treePlan := range canonical.Trees {
		if len(treePlan.RequiredOccurrences) != len(treePlan.Required) {
			return IndependentPlanResult{}, fmt.Errorf(
				"HPP: tree %+v has %d required positions but %d occurrence counts",
				treePlan.Tree, len(treePlan.Required), len(treePlan.RequiredOccurrences))
		}
		positions := make([]NodePosition, 0, len(treePlan.Required))
		for index, position := range treePlan.Required {
			occurrences := treePlan.RequiredOccurrences[index]
			if occurrences <= 0 {
				return IndependentPlanResult{}, fmt.Errorf(
					"HPP: required position %+v in tree %+v has non-positive occurrence count %d",
					position, treePlan.Tree, occurrences)
			}
			for count := int64(0); count < occurrences; count++ {
				positions = append(positions, position)
			}
			result.LogicalOccurrences += int(occurrences)
		}
		result.UniqueNodes += len(treePlan.Required)
		rawByTree[treePlan.Tree] = positions // keep duplicates: dedup is off
		trees = append(trees, TreePlan{Tree: treePlan.Tree, Targets: treePlan.Targets})
	}
	sort.Slice(trees, func(i, j int) bool { return treeRefLess(trees[i].Tree, trees[j].Tree) })

	result.SegmentRequests, result.UpperRequests = buildRequestsFromOccurrences(trees, rawByTree)
	return result, nil
}

func uniqueSortedPositions(positions []NodePosition) []NodePosition {
	set := make(map[NodePosition]struct{}, len(positions))
	for _, position := range positions {
		set[position] = struct{}{}
	}
	result := make([]NodePosition, 0, len(set))
	for position := range set {
		result = append(result, position)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Level != result[j].Level {
			return result[i].Level < result[j].Level
		}
		return result[i].Index < result[j].Index
	})
	return result
}

// buildRequestsFromOccurrences mirrors buildRequests but accepts each tree's
// retrieval-request node positions directly (occurrencesByTree), which may
// contain duplicates (the NO_DEDUP ablation) or extra, non-canonical
// positions (the NO_SHARED_PLANNING ablation). Segment-layer target leaves
// are still fetched explicitly at level 0, matching buildRequests's
// self-contained-proof behavior.
func buildRequestsFromOccurrences(trees []TreePlan,
	occurrencesByTree map[TreeRef][]NodePosition) ([]SegmentRequest, []UpperRequest) {

	type segmentRequestKey struct {
		tree  TreeRef
		level int32
	}
	type upperRequestKey struct {
		tree      TreeRef
		scopeType string
		scopeID   string
		bucketID  int64
		level     int32
	}
	segments := make(map[segmentRequestKey][]int64)
	uppers := make(map[upperRequestKey][]int64)
	for _, tree := range trees {
		if tree.Tree.Layer == LayerSegment {
			key := segmentRequestKey{tree: tree.Tree, level: 0}
			segments[key] = append(segments[key], tree.Targets...)
		}
		for _, position := range occurrencesByTree[tree.Tree] {
			switch tree.Tree.Layer {
			case LayerSegment:
				key := segmentRequestKey{tree: tree.Tree, level: position.Level}
				segments[key] = append(segments[key], position.Index)
			case LayerShard, LayerRegion, LayerGlobal:
				scopeType, scopeID, bucketID := upperScope(tree.Tree, position)
				key := upperRequestKey{
					tree: tree.Tree, scopeType: scopeType, scopeID: scopeID,
					bucketID: bucketID, level: position.Level,
				}
				uppers[key] = append(uppers[key], position.Index)
			}
		}
	}

	segmentRequests := make([]SegmentRequest, 0, len(segments))
	for key, indexes := range segments {
		sort.Slice(indexes, func(left, right int) bool { return indexes[left] < indexes[right] })
		segmentRequests = append(segmentRequests, SegmentRequest{
			Tree: key.tree, RegionID: key.tree.RegionID, ShardID: key.tree.ShardID,
			SegmentID: key.tree.SegmentID, Level: key.level, NodeIndexes: indexes,
		})
	}
	sort.Slice(segmentRequests, func(left, right int) bool {
		if segmentRequests[left].Tree != segmentRequests[right].Tree {
			return treeRefLess(segmentRequests[left].Tree, segmentRequests[right].Tree)
		}
		return segmentRequests[left].Level < segmentRequests[right].Level
	})

	upperRequests := make([]UpperRequest, 0, len(uppers))
	for key, indexes := range uppers {
		sort.Slice(indexes, func(left, right int) bool { return indexes[left] < indexes[right] })
		upperRequests = append(upperRequests, UpperRequest{
			Tree: key.tree, ScopeType: key.scopeType, ScopeID: key.scopeID,
			BucketID: key.bucketID, Level: key.level, NodeIndexes: indexes,
		})
	}
	sort.Slice(upperRequests, func(left, right int) bool {
		if upperRequests[left].Tree != upperRequests[right].Tree {
			return treeRefLess(upperRequests[left].Tree, upperRequests[right].Tree)
		}
		if upperRequests[left].BucketID != upperRequests[right].BucketID {
			return upperRequests[left].BucketID < upperRequests[right].BucketID
		}
		return upperRequests[left].Level < upperRequests[right].Level
	})
	return segmentRequests, upperRequests
}
