package hpp

import (
	"fmt"
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

	segmentTargets := make(map[SegmentKey]map[int64]struct{})
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
			segmentTargets[key] = make(map[int64]struct{})
		}
		segmentTargets[key][address.LeafID] = struct{}{}
	}

	plan := ProofPlan{Addresses: normalized}
	shardChildren := make(map[ShardKey]map[int64]TreeRef)
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
		}
		if existing, duplicate := shardChildren[shardKey][segment.ShardLeafIndex]; duplicate && existing != tree {
			return ProofPlan{}, fmt.Errorf("HPP: segments share shard leaf index %d in %+v", segment.ShardLeafIndex, shardKey)
		}
		shardChildren[shardKey][segment.ShardLeafIndex] = tree
	}

	regionChildren := make(map[string]map[int64]TreeRef)
	for key, children := range shardChildren {
		metadataForTree, exists := metadata.Shards[key]
		if !exists {
			return ProofPlan{}, fmt.Errorf("HPP: metadata missing for shard %+v", key)
		}
		targets := make(map[int64]struct{}, len(children))
		parent := shardTree(key)
		for index, child := range children {
			if index < 0 || index >= metadataForTree.LeafCount {
				return ProofPlan{}, fmt.Errorf("HPP: segment leaf index %d outside shard %+v", index, key)
			}
			targets[index] = struct{}{}
			plan.ParentLinks = append(plan.ParentLinks, ParentLink{Child: child, Parent: parent, ParentLeafIndex: index})
		}
		treePlan, err := planTree(parent, metadataForTree.LeafCount, targets)
		if err != nil {
			return ProofPlan{}, err
		}
		plan.Trees = append(plan.Trees, treePlan)

		if regionChildren[key.RegionID] == nil {
			regionChildren[key.RegionID] = make(map[int64]TreeRef)
		}
		if existing, duplicate := regionChildren[key.RegionID][metadataForTree.ParentLeafIndex]; duplicate && existing != parent {
			return ProofPlan{}, fmt.Errorf("HPP: shards share region leaf index %d in region %s",
				metadataForTree.ParentLeafIndex, key.RegionID)
		}
		regionChildren[key.RegionID][metadataForTree.ParentLeafIndex] = parent
	}

	globalChildren := make(map[int64]TreeRef)
	for regionID, children := range regionChildren {
		metadataForTree, exists := metadata.Regions[regionID]
		if !exists {
			return ProofPlan{}, fmt.Errorf("HPP: metadata missing for region %s", regionID)
		}
		targets := make(map[int64]struct{}, len(children))
		parent := regionTree(regionID)
		for index, child := range children {
			if index < 0 || index >= metadataForTree.LeafCount {
				return ProofPlan{}, fmt.Errorf("HPP: shard leaf index %d outside region %s", index, regionID)
			}
			targets[index] = struct{}{}
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
	}

	if metadata.Global.LeafCount <= 0 {
		return ProofPlan{}, fmt.Errorf("HPP: global tree metadata is invalid")
	}
	globalTargets := make(map[int64]struct{}, len(globalChildren))
	global := globalTree()
	for index, child := range globalChildren {
		if index < 0 || index >= metadata.Global.LeafCount {
			return ProofPlan{}, fmt.Errorf("HPP: region leaf index %d outside global tree", index)
		}
		globalTargets[index] = struct{}{}
		plan.ParentLinks = append(plan.ParentLinks, ParentLink{Child: child, Parent: global, ParentLeafIndex: index})
	}
	globalPlan, err := planTree(global, metadata.Global.LeafCount, globalTargets)
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

func planTree(tree TreeRef, leafCount int64, targets map[int64]struct{}) (TreePlan, error) {
	if leafCount <= 0 {
		return TreePlan{}, fmt.Errorf("HPP: tree %+v must contain at least one leaf", tree)
	}
	if len(targets) == 0 {
		return TreePlan{}, fmt.Errorf("HPP: tree %+v has no target leaves", tree)
	}
	active := make(map[int64]struct{}, len(targets))
	for index := range targets {
		if index < 0 || index >= leafCount {
			return TreePlan{}, fmt.Errorf("HPP: target leaf %d outside tree %+v", index, tree)
		}
		active[index] = struct{}{}
	}

	required := make(map[NodePosition]struct{})
	width := leafCount
	level := int32(0)
	for width > 1 {
		parents := make(map[int64]struct{})
		for index := range active {
			sibling := index ^ 1
			if sibling < width {
				if _, reconstructible := active[sibling]; !reconstructible {
					required[NodePosition{Level: level, Index: sibling}] = struct{}{}
				}
			}
			parents[index/2] = struct{}{}
		}
		active = parents
		width = (width + 1) / 2
		level++
	}

	result := TreePlan{Tree: tree, LeafCount: leafCount}
	for index := range targets {
		result.Targets = append(result.Targets, index)
	}
	sort.Slice(result.Targets, func(left, right int) bool { return result.Targets[left] < result.Targets[right] })
	for position := range required {
		result.Required = append(result.Required, position)
	}
	sortPositions(result.Required)
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
