package hpp

import (
	"fmt"
	"slices"
	"sort"
)

type Planner struct{}

func NewPlanner() *Planner {
	return &Planner{}
}

func (planner *Planner) Plan(addresses []PhysicalAddress, metadata HierarchyMetadata) (ProofPlan, error) {
	normalized, err := normalizeAddresses(addresses)
	if err != nil {
		return ProofPlan{}, err
	}
	if len(normalized) == 0 {
		return ProofPlan{}, fmt.Errorf("HPP: at least one physical address is required")
	}

	// Every target map below is index -> weight, where weight is the number of
	// this batch's original addresses whose independent authentication path
	// would pass through that index -- not just a presence set. A segment's
	// weight starts as one per distinct requested leaf; each layer above sums
	// its children's weights before becoming a single target of the next
	// layer's planTree call, so a required node's occurrence count (see
	// TreePlan.RequiredOccurrences) always reflects genuine per-address
	// sharing, never just per-distinct-child-key sharing.
	segmentTargets := make(map[SegmentKey]map[int64]int64)
	for _, address := range normalized {
		key := SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
		segment, exists := metadata.Segments[key]
		if !exists {
			return ProofPlan{}, fmt.Errorf("HPP: metadata missing for segment %+v", key)
		}
		if !segment.Sealed {
			return ProofPlan{}, fmt.Errorf("HPP: segment %+v is not sealed", key)
		}
		if address.LeafID >= segment.LeafCount {
			return ProofPlan{}, fmt.Errorf("HPP: leaf %d outside segment %+v with %d leaves",
				address.LeafID, key, segment.LeafCount)
		}
		if segmentTargets[key] == nil {
			segmentTargets[key] = make(map[int64]int64)
		}
		segmentTargets[key][address.LeafID]++
	}

	plan := ProofPlan{Addresses: normalized}
	shardChildren := make(map[ShardKey]map[int64]TreeRef)
	shardWeights := make(map[ShardKey]map[int64]int64)
	for key, targets := range segmentTargets {
		segment := metadata.Segments[key]
		tree := segmentTree(key)
		treePlan, err := planTree(tree, segment.LeafCount, targets)
		if err != nil {
			return ProofPlan{}, err
		}
		plan.Trees = append(plan.Trees, treePlan)

		shardKey := ShardKey{RegionID: key.RegionID, ShardID: key.ShardID}
		if shardChildren[shardKey] == nil {
			shardChildren[shardKey] = make(map[int64]TreeRef)
			shardWeights[shardKey] = make(map[int64]int64)
		}
		if existing, duplicate := shardChildren[shardKey][segment.ShardLeafIndex]; duplicate && existing != tree {
			return ProofPlan{}, fmt.Errorf("HPP: segments share shard leaf index %d in %+v", segment.ShardLeafIndex, shardKey)
		}
		shardChildren[shardKey][segment.ShardLeafIndex] = tree
		shardWeights[shardKey][segment.ShardLeafIndex] = sumWeights(targets)
	}

	regionChildren := make(map[string]map[int64]TreeRef)
	regionWeights := make(map[string]map[int64]int64)
	for key, children := range shardChildren {
		metadataForTree, exists := metadata.Shards[key]
		if !exists {
			return ProofPlan{}, fmt.Errorf("HPP: metadata missing for shard %+v", key)
		}
		targets := shardWeights[key]
		parent := shardTree(key)
		for index, child := range children {
			if index < 0 || index >= metadataForTree.LeafCount {
				return ProofPlan{}, fmt.Errorf("HPP: segment leaf index %d outside shard %+v", index, key)
			}
			plan.ParentLinks = append(plan.ParentLinks, ParentLink{Child: child, Parent: parent, ParentLeafIndex: index})
		}
		treePlan, err := planTree(parent, metadataForTree.LeafCount, targets)
		if err != nil {
			return ProofPlan{}, err
		}
		plan.Trees = append(plan.Trees, treePlan)

		if regionChildren[key.RegionID] == nil {
			regionChildren[key.RegionID] = make(map[int64]TreeRef)
			regionWeights[key.RegionID] = make(map[int64]int64)
		}
		if existing, duplicate := regionChildren[key.RegionID][metadataForTree.ParentLeafIndex]; duplicate && existing != parent {
			return ProofPlan{}, fmt.Errorf("HPP: shards share region leaf index %d in region %s",
				metadataForTree.ParentLeafIndex, key.RegionID)
		}
		regionChildren[key.RegionID][metadataForTree.ParentLeafIndex] = parent
		regionWeights[key.RegionID][metadataForTree.ParentLeafIndex] = sumWeights(targets)
	}

	globalChildren := make(map[int64]TreeRef)
	globalWeights := make(map[int64]int64)
	for regionID, children := range regionChildren {
		metadataForTree, exists := metadata.Regions[regionID]
		if !exists {
			return ProofPlan{}, fmt.Errorf("HPP: metadata missing for region %s", regionID)
		}
		targets := regionWeights[regionID]
		parent := regionTree(regionID)
		for index, child := range children {
			if index < 0 || index >= metadataForTree.LeafCount {
				return ProofPlan{}, fmt.Errorf("HPP: shard leaf index %d outside region %s", index, regionID)
			}
			plan.ParentLinks = append(plan.ParentLinks, ParentLink{Child: child, Parent: parent, ParentLeafIndex: index})
		}
		treePlan, err := planTree(parent, metadataForTree.LeafCount, targets)
		if err != nil {
			return ProofPlan{}, err
		}
		plan.Trees = append(plan.Trees, treePlan)

		if existing, duplicate := globalChildren[metadataForTree.ParentLeafIndex]; duplicate && existing != parent {
			return ProofPlan{}, fmt.Errorf("HPP: regions share global leaf index %d", metadataForTree.ParentLeafIndex)
		}
		globalChildren[metadataForTree.ParentLeafIndex] = parent
		globalWeights[metadataForTree.ParentLeafIndex] = sumWeights(targets)
	}

	if metadata.Global.LeafCount <= 0 {
		return ProofPlan{}, fmt.Errorf("HPP: global tree metadata is invalid")
	}
	global := globalTree()
	for index, child := range globalChildren {
		if index < 0 || index >= metadata.Global.LeafCount {
			return ProofPlan{}, fmt.Errorf("HPP: region leaf index %d outside global tree", index)
		}
		plan.ParentLinks = append(plan.ParentLinks, ParentLink{Child: child, Parent: global, ParentLeafIndex: index})
	}
	globalPlan, err := planTree(global, metadata.Global.LeafCount, globalWeights)
	if err != nil {
		return ProofPlan{}, err
	}
	plan.Trees = append(plan.Trees, globalPlan)

	sort.Slice(plan.Trees, func(left, right int) bool { return treeRefLess(plan.Trees[left].Tree, plan.Trees[right].Tree) })
	sort.Slice(plan.ParentLinks, func(left, right int) bool {
		if plan.ParentLinks[left].Parent != plan.ParentLinks[right].Parent {
			return treeRefLess(plan.ParentLinks[left].Parent, plan.ParentLinks[right].Parent)
		}
		return plan.ParentLinks[left].ParentLeafIndex < plan.ParentLinks[right].ParentLeafIndex
	})
	plan.SegmentRequests, plan.UpperRequests = buildRequests(plan.Trees)
	return plan, nil
}

// sumWeights totals a target-weight map's values -- the number of original
// addresses feeding into all of that map's targets combined.
func sumWeights(weights map[int64]int64) int64 {
	var total int64
	for _, weight := range weights {
		total += weight
	}
	return total
}

// planTree computes the joint merge-walk for one tree. targetWeights maps
// each active leaf/child index to the number of this batch's original
// addresses whose independent authentication path would pass through it --
// ordinarily 1 per distinct index, but greater than 1 when a caller has
// already collapsed several addresses (or several lower-layer children) into
// one target of this tree, such as Planner.Plan's shard/region/global-layer
// calls.
func planTree(tree TreeRef, leafCount int64, targetWeights map[int64]int64) (TreePlan, error) {
	if leafCount <= 0 {
		return TreePlan{}, fmt.Errorf("HPP: tree %+v must contain at least one leaf", tree)
	}
	if len(targetWeights) == 0 {
		return TreePlan{}, fmt.Errorf("HPP: tree %+v has no target leaves", tree)
	}
	active := make([]int64, 0, len(targetWeights))
	for index := range targetWeights {
		if index < 0 || index >= leafCount {
			return TreePlan{}, fmt.Errorf("HPP: target leaf %d outside tree %+v", index, tree)
		}
		active = append(active, index)
	}
	slices.Sort(active)
	// weights[i] tracks how many of this batch's original addresses have
	// merged into active[i] so far, seeded from targetWeights. Whenever two
	// active siblings merge into one parent, their weights sum. When only one
	// sibling is active, the OTHER (required) sibling's occurrence count is
	// exactly that active sibling's weight -- the number of original
	// addresses whose independent path would need it. This is computed in the
	// same single joint merge-walk that produces Required, so it costs no
	// extra tree traversal and never re-derives any address's path
	// independently.
	weights := make([]int64, len(active))
	for index, position := range active {
		weights[index] = targetWeights[position]
	}
	return planSortedTree(tree, leafCount, active, weights)
}

// planSortedTree is planTree for targets already in ascending order: active holds the distinct target
// indexes inside the tree and weights[i] the number of original addresses behind active[i]. Both slices
// are used as scratch space and are not valid afterwards.
func planSortedTree(tree TreeRef, leafCount int64, active, weights []int64) (TreePlan, error) {
	result := TreePlan{Tree: tree, LeafCount: leafCount, Targets: append([]int64(nil), active...)}

	// Walking each level's sorted active indexes emits Required already in
	// canonical (level, index) order.
	next := make([]int64, 0, len(active))
	nextWeights := make([]int64, 0, len(active))
	width := leafCount
	level := int32(0)
	for width > 1 {
		next = next[:0]
		nextWeights = nextWeights[:0]
		for position := 0; position < len(active); {
			parent := active[position] / 2
			left, right := parent*2, parent*2+1
			var leftWeight, rightWeight int64
			haveLeft := active[position] == left
			if haveLeft {
				leftWeight = weights[position]
				position++
			}
			haveRight := position < len(active) && active[position] == right
			if haveRight {
				rightWeight = weights[position]
				position++
			}
			if !haveLeft {
				result.Required = append(result.Required, NodePosition{Level: level, Index: left})
				result.RequiredOccurrences = append(result.RequiredOccurrences, rightWeight)
			}
			if !haveRight && right < width {
				result.Required = append(result.Required, NodePosition{Level: level, Index: right})
				result.RequiredOccurrences = append(result.RequiredOccurrences, leftWeight)
			}
			next = append(next, parent)
			nextWeights = append(nextWeights, leftWeight+rightWeight)
		}
		active, next = next, active
		weights, nextWeights = nextWeights, weights
		width = (width + 1) / 2
		level++
	}
	return result, nil
}

func buildRequests(trees []TreePlan) ([]SegmentRequest, []UpperRequest) {
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
		// The authenticated address identifies a Segment leaf position, but not
		// its hash. Fetch every target leaf with the level-zero siblings so the
		// returned proof is self-contained.
		if tree.Tree.Layer == LayerSegment {
			key := segmentRequestKey{tree: tree.Tree, level: 0}
			segments[key] = append(segments[key], tree.Targets...)
		}
		for _, position := range tree.Required {
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
		slices.Sort(indexes)
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
		slices.Sort(indexes)
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

func upperScope(tree TreeRef, position NodePosition) (string, string, int64) {
	switch tree.Layer {
	case LayerShard:
		return "SHARD", fmt.Sprintf("%s:S%d", tree.RegionID, tree.ShardID), shardBucketID(position.Level, position.Index)
	case LayerRegion:
		return "REGION", tree.RegionID, 0
	default:
		return "GLOBAL", "GLOBAL", 0
	}
}
