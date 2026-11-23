package hpp

import (
	"context"
	"fmt"
	"slices"
	"sort"
)

// This file is the HPP surface used by frontier-driven tamper localization. It
// adds no new storage behaviour: explicit nodes are grouped into the same
// SegmentRequest/UpperRequest partition reads that proof planning produces, and
// are fetched by the same ProofNodeReader (so the Cassandra reader's grouped,
// concurrent partition retrieval applies unchanged).

// PartitionKey identifies the storage partition that holds a node. Two nodes
// with equal keys are served by one grouped read; the localization cost model
// uses it to estimate partition-aware I/O.
type PartitionKey struct {
	Table     string // "segment" or "upper"
	Tree      TreeRef
	ScopeType string
	ScopeID   string
	BucketID  int64
}

// PartitionOf maps a node to its storage partition with the same scope and
// bucket rules the planner uses to build requests.
func PartitionOf(ref NodeRef) PartitionKey {
	if ref.Tree.Layer == LayerSegment {
		return PartitionKey{Table: "segment", Tree: ref.Tree}
	}
	scopeType, scopeID, bucketID := upperScope(ref.Tree, ref.Position)
	return PartitionKey{Table: "upper", Tree: ref.Tree, ScopeType: scopeType, ScopeID: scopeID, BucketID: bucketID}
}

// CommittedRoot binds a tree's raw root to the tree's identity and leaf count,
// exactly as a proof verification does when it hands a root to the next layer.
func CommittedRoot(tree TreeRef, leafCount int64, rawRoot [32]byte) [32]byte {
	return committedRoot(tree, leafCount, rawRoot)
}

// ReferencePlan loads the stored hierarchy metadata for the addresses and plans
// the proof, without reading any proof node. Localization uses it to learn the
// reference topology only when the failed proof's topology cannot be
// authenticated.
func (service *Service) ReferencePlan(ctx context.Context, addresses []PhysicalAddress) (ProofPlan, error) {
	normalized, err := normalizeAddresses(addresses)
	if err != nil {
		return ProofPlan{}, fmt.Errorf("reference plan: %w", err)
	}
	if len(normalized) == 0 {
		return ProofPlan{}, fmt.Errorf("reference plan: at least one physical address is required")
	}
	metadata, err := service.metadata.LoadHierarchyMetadata(ctx, normalized)
	if err != nil {
		return ProofPlan{}, fmt.Errorf("reference plan: load hierarchy metadata: %w", err)
	}
	plan, err := service.planner.Plan(normalized, metadata)
	if err != nil {
		return ProofPlan{}, fmt.Errorf("reference plan: %w", err)
	}
	return plan, nil
}

// FetchNodes retrieves the named stored nodes through the partition-aware
// reader: one request per (tree, level) within a partition, so every touched
// partition is read once. The result is in canonical node order and holds only
// requested nodes, each at most once. A reader that cannot return a node may
// return an error (the Cassandra reader does) or omit it; the caller decides
// what a missing node means, and nothing returned is authenticated here.
func (service *Service) FetchNodes(ctx context.Context, refs []NodeRef) ([]ProofNode, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	requested := slices.Clone(refs)
	slices.SortFunc(requested, compareNodeRefs)
	requested = slices.CompactFunc(requested, func(left, right NodeRef) bool { return left == right })
	for _, ref := range requested {
		if ref.Position.Level < 0 || ref.Position.Index < 0 {
			return nil, fmt.Errorf("fetch nodes: invalid node %+v", ref)
		}
		switch ref.Tree.Layer {
		case LayerSegment, LayerShard, LayerRegion, LayerGlobal:
		default:
			return nil, fmt.Errorf("fetch nodes: invalid tree layer in %+v", ref)
		}
	}
	segments, uppers := nodeRequests(requested)
	nodes, err := service.nodes.FetchProofNodes(ctx, ProofPlan{SegmentRequests: segments, UpperRequests: uppers})
	if err != nil {
		return nil, fmt.Errorf("fetch nodes: %w", err)
	}
	slices.SortFunc(nodes, func(left, right ProofNode) int { return compareNodeRefs(left.Ref, right.Ref) })
	for index, node := range nodes {
		if _, found := slices.BinarySearchFunc(requested, node.Ref, compareNodeRefs); !found {
			return nil, fmt.Errorf("fetch nodes: unrequested node %+v returned", node.Ref)
		}
		if index > 0 && nodes[index-1].Ref == node.Ref {
			return nil, fmt.Errorf("fetch nodes: duplicate node %+v returned", node.Ref)
		}
	}
	return nodes, nil
}

// nodeRequests groups explicit nodes into the planner's request shapes. refs
// must be sorted and distinct.
func nodeRequests(refs []NodeRef) ([]SegmentRequest, []UpperRequest) {
	type segmentKey struct {
		tree  TreeRef
		level int32
	}
	type upperKey struct {
		partition PartitionKey
		level     int32
	}
	segmentIndexes := make(map[segmentKey][]int64)
	upperIndexes := make(map[upperKey][]int64)
	for _, ref := range refs {
		if ref.Tree.Layer == LayerSegment {
			key := segmentKey{tree: ref.Tree, level: ref.Position.Level}
			segmentIndexes[key] = append(segmentIndexes[key], ref.Position.Index)
			continue
		}
		key := upperKey{partition: PartitionOf(ref), level: ref.Position.Level}
		upperIndexes[key] = append(upperIndexes[key], ref.Position.Index)
	}

	segments := make([]SegmentRequest, 0, len(segmentIndexes))
	for key, indexes := range segmentIndexes {
		slices.Sort(indexes)
		segments = append(segments, SegmentRequest{
			Tree: key.tree, RegionID: key.tree.RegionID, ShardID: key.tree.ShardID,
			SegmentID: key.tree.SegmentID, Level: key.level, NodeIndexes: indexes,
		})
	}
	sort.Slice(segments, func(left, right int) bool {
		if segments[left].Tree != segments[right].Tree {
			return treeRefLess(segments[left].Tree, segments[right].Tree)
		}
		return segments[left].Level < segments[right].Level
	})

	uppers := make([]UpperRequest, 0, len(upperIndexes))
	for key, indexes := range upperIndexes {
		slices.Sort(indexes)
		uppers = append(uppers, UpperRequest{
			Tree: key.partition.Tree, ScopeType: key.partition.ScopeType, ScopeID: key.partition.ScopeID,
			BucketID: key.partition.BucketID, Level: key.level, NodeIndexes: indexes,
		})
	}
	sort.Slice(uppers, func(left, right int) bool {
		if uppers[left].Tree != uppers[right].Tree {
			return treeRefLess(uppers[left].Tree, uppers[right].Tree)
		}
		if uppers[left].BucketID != uppers[right].BucketID {
			return uppers[left].BucketID < uppers[right].BucketID
		}
		return uppers[left].Level < uppers[right].Level
	})
	return segments, uppers
}
