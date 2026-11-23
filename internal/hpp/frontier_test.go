package hpp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

// recordingReader answers a plan's requests with a hash derived from each node
// and keeps the plans it was given.
type recordingReader struct {
	plans    []ProofPlan
	extra    []ProofNode // returned in addition to what was requested
	omitNode *NodeRef
	fail     error
}

func nodeHash(ref NodeRef) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%+v", ref)))
}

func (reader *recordingReader) FetchProofNodes(_ context.Context, plan ProofPlan) ([]ProofNode, error) {
	reader.plans = append(reader.plans, plan)
	if reader.fail != nil {
		return nil, reader.fail
	}
	var nodes []ProofNode
	add := func(tree TreeRef, level int32, indexes []int64) {
		for _, index := range indexes {
			ref := NodeRef{Tree: tree, Position: NodePosition{Level: level, Index: index}}
			if reader.omitNode != nil && *reader.omitNode == ref {
				continue
			}
			nodes = append(nodes, ProofNode{Ref: ref, Hash: nodeHash(ref)})
		}
	}
	for _, request := range plan.SegmentRequests {
		add(request.Tree, request.Level, request.NodeIndexes)
	}
	for _, request := range plan.UpperRequests {
		add(request.Tree, request.Level, request.NodeIndexes)
	}
	return append(nodes, reader.extra...), nil
}

type fixedMetadata struct{ metadata HierarchyMetadata }

func (reader fixedMetadata) LoadHierarchyMetadata(context.Context, []PhysicalAddress) (HierarchyMetadata, error) {
	return reader.metadata, nil
}

func frontierService(t *testing.T, reader *recordingReader) *Service {
	t.Helper()
	service, err := NewService(fixedMetadata{metadata: HierarchyMetadata{
		Segments: map[SegmentKey]SegmentMetadata{
			{RegionID: "R0", ShardID: 0, SegmentID: 0}: {LeafCount: 8, ShardLeafIndex: 0, Sealed: true},
			{RegionID: "R0", ShardID: 0, SegmentID: 1}: {LeafCount: 5, ShardLeafIndex: 1, Sealed: true},
		},
		Shards:  map[ShardKey]UpperTreeMetadata{{RegionID: "R0", ShardID: 0}: {LeafCount: 2, ParentLeafIndex: 0}},
		Regions: map[string]UpperTreeMetadata{"R0": {LeafCount: 1, ParentLeafIndex: 0}},
		Global:  UpperTreeMetadata{LeafCount: 1},
	}}, reader)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func TestFetchNodesGroupsRequestsByPartition(t *testing.T) {
	reader := &recordingReader{}
	service := frontierService(t, reader)
	segmentA := TreeRef{Layer: LayerSegment, RegionID: "R0", ShardID: 0, SegmentID: 0}
	segmentB := TreeRef{Layer: LayerSegment, RegionID: "R0", ShardID: 0, SegmentID: 1}
	shard := TreeRef{Layer: LayerShard, RegionID: "R0", ShardID: 0}
	refs := []NodeRef{
		{Tree: segmentB, Position: NodePosition{Level: 0, Index: 4}},
		{Tree: segmentA, Position: NodePosition{Level: 2, Index: 1}},
		{Tree: segmentA, Position: NodePosition{Level: 2, Index: 0}},
		{Tree: segmentA, Position: NodePosition{Level: 0, Index: 3}},
		{Tree: shard, Position: NodePosition{Level: 0, Index: 1}},
		{Tree: shard, Position: NodePosition{Level: 1, Index: 0}},
		{Tree: segmentA, Position: NodePosition{Level: 2, Index: 1}}, // duplicate
	}
	nodes, err := service.FetchNodes(context.Background(), refs)
	if err != nil {
		t.Fatalf("fetch nodes: %v", err)
	}
	if len(reader.plans) != 1 {
		t.Fatalf("reader called %d times, want one joint retrieval", len(reader.plans))
	}
	plan := reader.plans[0]
	if len(plan.Trees) != 0 || len(plan.Addresses) != 0 {
		t.Fatal("a node fetch must not carry a proof plan")
	}
	wantSegments := []SegmentRequest{
		{Tree: segmentA, RegionID: "R0", ShardID: 0, SegmentID: 0, Level: 0, NodeIndexes: []int64{3}},
		{Tree: segmentA, RegionID: "R0", ShardID: 0, SegmentID: 0, Level: 2, NodeIndexes: []int64{0, 1}},
		{Tree: segmentB, RegionID: "R0", ShardID: 0, SegmentID: 1, Level: 0, NodeIndexes: []int64{4}},
	}
	if !reflect.DeepEqual(plan.SegmentRequests, wantSegments) {
		t.Fatalf("segment requests = %+v, want %+v", plan.SegmentRequests, wantSegments)
	}
	if len(plan.UpperRequests) != 2 || plan.UpperRequests[0].ScopeType != "SHARD" ||
		plan.UpperRequests[0].ScopeID != "R0:S0" || plan.UpperRequests[0].Level != 0 ||
		!reflect.DeepEqual(plan.UpperRequests[0].NodeIndexes, []int64{1}) {
		t.Fatalf("upper requests = %+v", plan.UpperRequests)
	}
	if len(nodes) != 6 || !slices.IsSortedFunc(nodes, func(a, b ProofNode) int { return compareNodeRefs(a.Ref, b.Ref) }) {
		t.Fatalf("returned %d nodes (sorted: %v), want the six distinct requested nodes in canonical order",
			len(nodes), slices.IsSortedFunc(nodes, func(a, b ProofNode) int { return compareNodeRefs(a.Ref, b.Ref) }))
	}
	for _, node := range nodes {
		if node.Hash != nodeHash(node.Ref) {
			t.Fatalf("node %+v carries the wrong hash", node.Ref)
		}
	}
	if nodes, err := service.FetchNodes(context.Background(), nil); err != nil || nodes != nil {
		t.Fatalf("empty fetch = %v, %v", nodes, err)
	}
}

func TestFetchNodesRejectsWhatWasNotRequested(t *testing.T) {
	segment := TreeRef{Layer: LayerSegment, RegionID: "R0", ShardID: 0, SegmentID: 0}
	ref := NodeRef{Tree: segment, Position: NodePosition{Level: 1, Index: 0}}
	stranger := ProofNode{Ref: NodeRef{Tree: segment, Position: NodePosition{Level: 1, Index: 1}}}

	reader := &recordingReader{extra: []ProofNode{stranger}}
	if _, err := frontierService(t, reader).FetchNodes(context.Background(), []NodeRef{ref}); err == nil {
		t.Fatal("an unrequested node returned by the reader was accepted")
	}
	reader = &recordingReader{extra: []ProofNode{{Ref: ref}}}
	if _, err := frontierService(t, reader).FetchNodes(context.Background(), []NodeRef{ref}); err == nil {
		t.Fatal("a node returned twice was accepted")
	}
	reader = &recordingReader{fail: fmt.Errorf("store down")}
	if _, err := frontierService(t, reader).FetchNodes(context.Background(), []NodeRef{ref}); err == nil {
		t.Fatal("a reader failure was swallowed")
	}
	for _, bad := range []NodeRef{
		{Tree: segment, Position: NodePosition{Level: -1, Index: 0}},
		{Tree: segment, Position: NodePosition{Level: 0, Index: -1}},
		{Tree: TreeRef{Layer: 9}, Position: NodePosition{}},
	} {
		if _, err := frontierService(t, &recordingReader{}).FetchNodes(context.Background(), []NodeRef{bad}); err == nil {
			t.Fatalf("invalid node %+v accepted", bad)
		}
	}
	// A node the reader omits is left to the caller to notice.
	omitted := &recordingReader{omitNode: &ref}
	nodes, err := frontierService(t, omitted).FetchNodes(context.Background(), []NodeRef{ref})
	if err != nil || len(nodes) != 0 {
		t.Fatalf("omitted node: %v, %v", nodes, err)
	}
}

func TestPartitionOfMatchesThePlannersRequests(t *testing.T) {
	// Every request the planner builds must land in the partition PartitionOf
	// reports for the nodes it lists.
	service := frontierService(t, &recordingReader{})
	plan, err := service.ReferencePlan(context.Background(), []PhysicalAddress{
		{RegionID: "R0", ShardID: 0, SegmentID: 0, LeafID: 2},
		{RegionID: "R0", ShardID: 0, SegmentID: 1, LeafID: 4},
	})
	if err != nil {
		t.Fatalf("reference plan: %v", err)
	}
	for _, request := range plan.SegmentRequests {
		for _, index := range request.NodeIndexes {
			got := PartitionOf(NodeRef{Tree: request.Tree, Position: NodePosition{Level: request.Level, Index: index}})
			if got.Table != "segment" || got.Tree != request.Tree {
				t.Fatalf("segment node %d of %+v maps to %+v", index, request.Tree, got)
			}
		}
	}
	for _, request := range plan.UpperRequests {
		for _, index := range request.NodeIndexes {
			got := PartitionOf(NodeRef{Tree: request.Tree, Position: NodePosition{Level: request.Level, Index: index}})
			if got.ScopeType != request.ScopeType || got.ScopeID != request.ScopeID || got.BucketID != request.BucketID {
				t.Fatalf("upper node %d of %+v maps to %+v, request says %s/%s/%d", index, request.Tree, got,
					request.ScopeType, request.ScopeID, request.BucketID)
			}
		}
	}
}

func TestReferencePlanReadsMetadataButNoNodes(t *testing.T) {
	reader := &recordingReader{}
	service := frontierService(t, reader)
	addresses := []PhysicalAddress{{RegionID: "R0", ShardID: 0, SegmentID: 1, LeafID: 2}}
	plan, err := service.ReferencePlan(context.Background(), addresses)
	if err != nil {
		t.Fatalf("reference plan: %v", err)
	}
	if len(reader.plans) != 0 {
		t.Fatal("planning read proof nodes")
	}
	counts := map[TreeRef]int64{}
	for _, tree := range plan.Trees {
		counts[tree.Tree] = tree.LeafCount
	}
	if counts[TreeRef{Layer: LayerSegment, RegionID: "R0", ShardID: 0, SegmentID: 1}] != 5 ||
		counts[TreeRef{Layer: LayerShard, RegionID: "R0", ShardID: 0}] != 2 {
		t.Fatalf("planned leaf counts = %v", counts)
	}
	for _, invalid := range [][]PhysicalAddress{nil, {{RegionID: "", LeafID: 1}}, {{RegionID: "R0", LeafID: -1}}} {
		if _, err := service.ReferencePlan(context.Background(), invalid); err == nil {
			t.Fatalf("addresses %+v accepted", invalid)
		}
	}
}

func TestCommittedRootMatchesTheVerifier(t *testing.T) {
	tree := TreeRef{Layer: LayerSegment, RegionID: "R0", ShardID: 1, SegmentID: 2}
	raw := sha256.Sum256([]byte("raw"))
	if CommittedRoot(tree, 7, raw) != committedRoot(tree, 7, raw) {
		t.Fatal("exported commitment differs from the verifier's")
	}
	if CommittedRoot(tree, 7, raw) == CommittedRoot(tree, 8, raw) {
		t.Fatal("the commitment does not bind the leaf count")
	}
}
