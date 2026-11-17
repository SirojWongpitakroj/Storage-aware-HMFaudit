package hpp

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
)

// buildLargeMetadata constructs a multi-region, multi-shard, multi-segment
// hierarchy so overlapping and non-overlapping address batches can be tested.
func buildLargeMetadata(regions, shardsPerRegion, segmentsPerShard int, segmentLeaves int64) HierarchyMetadata {
	metadata := HierarchyMetadata{
		Segments: make(map[SegmentKey]SegmentMetadata),
		Shards:   make(map[ShardKey]UpperTreeMetadata),
		Regions:  make(map[string]UpperTreeMetadata),
		Global:   UpperTreeMetadata{LeafCount: int64(regions)},
	}
	for regionIndex := 0; regionIndex < regions; regionIndex++ {
		regionID := fmt.Sprintf("R%d", regionIndex)
		metadata.Regions[regionID] = UpperTreeMetadata{LeafCount: int64(shardsPerRegion), ParentLeafIndex: int64(regionIndex)}
		for shardIndex := 0; shardIndex < shardsPerRegion; shardIndex++ {
			shardKey := ShardKey{RegionID: regionID, ShardID: int64(shardIndex)}
			metadata.Shards[shardKey] = UpperTreeMetadata{LeafCount: int64(segmentsPerShard), ParentLeafIndex: int64(shardIndex)}
			for segmentIndex := 0; segmentIndex < segmentsPerShard; segmentIndex++ {
				segmentKey := SegmentKey{RegionID: regionID, ShardID: int64(shardIndex), SegmentID: int64(segmentIndex)}
				metadata.Segments[segmentKey] = SegmentMetadata{
					LeafCount: segmentLeaves, ShardLeafIndex: int64(segmentIndex), Sealed: true,
				}
			}
		}
	}
	return metadata
}

func requestedNodeSet(segments []SegmentRequest, uppers []UpperRequest) map[NodeRef]struct{} {
	set := make(map[NodeRef]struct{})
	for _, request := range segments {
		for _, index := range request.NodeIndexes {
			set[NodeRef{Tree: request.Tree, Position: NodePosition{Level: request.Level, Index: index}}] = struct{}{}
		}
	}
	for _, request := range uppers {
		for _, index := range request.NodeIndexes {
			set[NodeRef{Tree: request.Tree, Position: NodePosition{Level: request.Level, Index: index}}] = struct{}{}
		}
	}
	return set
}

func canonicalRequiredSet(trees []TreePlan) map[NodeRef]struct{} {
	set := make(map[NodeRef]struct{})
	for _, tree := range trees {
		for _, position := range tree.Required {
			set[NodeRef{Tree: tree.Tree, Position: position}] = struct{}{}
		}
	}
	return set
}

// TestPlanIndependentDedupIsSufficientSupersetOfJointPlan is the ablation
// protocol's Check 7. PlanIndependent(dedup=true) cannot always shrink to
// exactly Planner.Plan's minimal set (pure identity-dedup cannot recognize
// that a required sibling of one address coincides with an ancestor of
// another address's own path, which joint planning makes free) -- but its
// requested node set must always be a SUPERSET of the canonical required set,
// i.e. sufficient to reconstruct the same root, across many random
// overlapping and non-overlapping batches.
func TestPlanIndependentDedupIsSufficientSupersetOfJointPlan(t *testing.T) {
	metadata := buildLargeMetadata(3, 4, 8, 64)
	random := rand.New(rand.NewSource(7))

	var allAddresses []PhysicalAddress
	for regionIndex := 0; regionIndex < 3; regionIndex++ {
		for shardIndex := 0; shardIndex < 4; shardIndex++ {
			for segmentIndex := 0; segmentIndex < 8; segmentIndex++ {
				for leaf := int64(0); leaf < 64; leaf++ {
					allAddresses = append(allAddresses, PhysicalAddress{
						RegionID: fmt.Sprintf("R%d", regionIndex), ShardID: int64(shardIndex),
						SegmentID: int64(segmentIndex), LeafID: leaf,
					})
				}
			}
		}
	}

	exactMatches, supersetOnly := 0, 0
	for trial := 0; trial < 30; trial++ {
		count := 2 + random.Intn(60)
		random.Shuffle(len(allAddresses), func(i, j int) { allAddresses[i], allAddresses[j] = allAddresses[j], allAddresses[i] })
		addresses := append([]PhysicalAddress(nil), allAddresses[:count]...)

		joint, err := NewPlanner().Plan(addresses, metadata)
		if err != nil {
			t.Fatalf("trial %d: joint plan: %v", trial, err)
		}
		independent, err := PlanIndependent(addresses, metadata, true)
		if err != nil {
			t.Fatalf("trial %d: independent plan: %v", trial, err)
		}

		canonical := canonicalRequiredSet(joint.Trees)
		requested := requestedNodeSet(independent.SegmentRequests, independent.UpperRequests)
		for ref := range canonical {
			if _, fetched := requested[ref]; !fetched {
				t.Fatalf("trial %d: independent dedup plan omits canonically-required node %+v", trial, ref)
			}
		}
		if len(requested) == len(canonical) {
			exactMatches++
		} else if len(requested) > len(canonical) {
			supersetOnly++
		} else {
			t.Fatalf("trial %d: independent requested %d nodes, fewer than canonical's %d -- should never under-fetch",
				trial, len(requested), len(canonical))
		}
	}
	t.Logf("exact matches: %d/30, strict supersets: %d/30", exactMatches, supersetOnly)
}

// TestPlanIndependentNoDedupHasMoreOccurrencesThanDedup is the ablation
// protocol's Check 8: NO_DEDUP must show logical occurrences >= unique nodes,
// with genuine duplicates for an overlapping workload (two leaves that share
// ancestors above the sibling level).
func TestPlanIndependentNoDedupHasMoreOccurrencesThanDedup(t *testing.T) {
	segmentKey := SegmentKey{RegionID: "R0", ShardID: 0, SegmentID: 10}
	shardKey := ShardKey{RegionID: "R0", ShardID: 0}
	metadata := HierarchyMetadata{
		Segments: map[SegmentKey]SegmentMetadata{
			segmentKey: {LeafCount: 8, ShardLeafIndex: 0, Sealed: true},
		},
		Shards:  map[ShardKey]UpperTreeMetadata{shardKey: {LeafCount: 2, ParentLeafIndex: 0}},
		Regions: map[string]UpperTreeMetadata{"R0": {LeafCount: 2, ParentLeafIndex: 0}},
		Global:  UpperTreeMetadata{LeafCount: 2},
	}
	addresses := []PhysicalAddress{
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 1},
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 6},
	}

	noDedup, err := PlanIndependent(addresses, metadata, false)
	if err != nil {
		t.Fatalf("no-dedup plan: %v", err)
	}
	if noDedup.LogicalOccurrences <= noDedup.UniqueNodes {
		t.Fatalf("logical occurrences (%d) should exceed unique nodes (%d) for an overlapping batch",
			noDedup.LogicalOccurrences, noDedup.UniqueNodes)
	}

	dedup, err := PlanIndependent(addresses, metadata, true)
	if err != nil {
		t.Fatalf("dedup plan: %v", err)
	}
	noDedupTotal := requestTotal(noDedup.SegmentRequests, noDedup.UpperRequests)
	dedupTotal := requestTotal(dedup.SegmentRequests, dedup.UpperRequests)
	if noDedupTotal <= dedupTotal {
		t.Fatalf("no-dedup retrieval request total (%d) should exceed dedup's (%d)", noDedupTotal, dedupTotal)
	}
}

// TestExpandRequiredWithOccurrencesMatchesCanonicalNodeSetExactly confirms
// ExpandRequiredWithOccurrences's true NO_DEDUP isolation: unlike
// PlanIndependent (which always loses shared-path planning too), its
// requested unique-node identity set must equal Planner.Plan's own requested
// node set exactly -- never a superset, never a subset -- across many random
// overlapping and non-overlapping batches, proving shared planning's benefit
// is fully retained while only dedup is removed. (Compared against
// canonical's own SegmentRequests/UpperRequests, not just TreePlan.Required,
// since both planners also fetch each segment-layer target leaf explicitly at
// level 0 -- see buildRequests's self-contained-proof comment -- and that
// fetch would otherwise look like a spurious mismatch.)
func TestExpandRequiredWithOccurrencesMatchesCanonicalNodeSetExactly(t *testing.T) {
	metadata := buildLargeMetadata(3, 4, 8, 64)
	random := rand.New(rand.NewSource(11))

	var allAddresses []PhysicalAddress
	for regionIndex := 0; regionIndex < 3; regionIndex++ {
		for shardIndex := 0; shardIndex < 4; shardIndex++ {
			for segmentIndex := 0; segmentIndex < 8; segmentIndex++ {
				for leaf := int64(0); leaf < 64; leaf++ {
					allAddresses = append(allAddresses, PhysicalAddress{
						RegionID: fmt.Sprintf("R%d", regionIndex), ShardID: int64(shardIndex),
						SegmentID: int64(segmentIndex), LeafID: leaf,
					})
				}
			}
		}
	}

	for trial := 0; trial < 30; trial++ {
		count := 2 + random.Intn(60)
		random.Shuffle(len(allAddresses), func(i, j int) { allAddresses[i], allAddresses[j] = allAddresses[j], allAddresses[i] })
		addresses := append([]PhysicalAddress(nil), allAddresses[:count]...)

		joint, err := NewPlanner().Plan(addresses, metadata)
		if err != nil {
			t.Fatalf("trial %d: joint plan: %v", trial, err)
		}
		expanded, err := ExpandRequiredWithOccurrences(joint)
		if err != nil {
			t.Fatalf("trial %d: expand required with occurrences: %v", trial, err)
		}

		canonical := requestedNodeSet(joint.SegmentRequests, joint.UpperRequests)
		requested := requestedNodeSet(expanded.SegmentRequests, expanded.UpperRequests)
		if len(requested) != len(canonical) {
			t.Fatalf("trial %d: requested %d unique nodes, want exactly canonical's %d",
				trial, len(requested), len(canonical))
		}
		for ref := range canonical {
			if _, fetched := requested[ref]; !fetched {
				t.Fatalf("trial %d: expanded plan omits canonically-required node %+v", trial, ref)
			}
		}
		for ref := range requested {
			if _, wanted := canonical[ref]; !wanted {
				t.Fatalf("trial %d: expanded plan requests non-canonical node %+v", trial, ref)
			}
		}
	}
}

// TestExpandRequiredWithOccurrencesHasDuplicatesForOverlappingBatch is the
// corrected ablation protocol's Check 8: for a batch where two addresses'
// independent authentication paths cross the same shared ancestor,
// ExpandRequiredWithOccurrences's LogicalOccurrences must exceed its
// UniqueNodes (the node is requested once per requesting address), even
// though the requested node SET still equals canonical's minimal set exactly.
func TestExpandRequiredWithOccurrencesHasDuplicatesForOverlappingBatch(t *testing.T) {
	segmentKey := SegmentKey{RegionID: "R0", ShardID: 0, SegmentID: 10}
	shardKey := ShardKey{RegionID: "R0", ShardID: 0}
	metadata := HierarchyMetadata{
		Segments: map[SegmentKey]SegmentMetadata{
			segmentKey: {LeafCount: 8, ShardLeafIndex: 0, Sealed: true},
		},
		Shards:  map[ShardKey]UpperTreeMetadata{shardKey: {LeafCount: 2, ParentLeafIndex: 0}},
		Regions: map[string]UpperTreeMetadata{"R0": {LeafCount: 2, ParentLeafIndex: 0}},
		Global:  UpperTreeMetadata{LeafCount: 2},
	}
	// Leaves 1 and 6 are not Merkle siblings of each other, but both need the
	// shard/region/global-layer auxiliary nodes above the segment: their
	// shared ancestor chain above the segment root is where the duplicate
	// requirement appears once shared planning's own dedup is switched off.
	addresses := []PhysicalAddress{
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 1},
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 6},
	}

	joint, err := NewPlanner().Plan(addresses, metadata)
	if err != nil {
		t.Fatalf("joint plan: %v", err)
	}
	expanded, err := ExpandRequiredWithOccurrences(joint)
	if err != nil {
		t.Fatalf("expand required with occurrences: %v", err)
	}
	if expanded.LogicalOccurrences <= expanded.UniqueNodes {
		t.Fatalf("logical occurrences (%d) should exceed unique nodes (%d) for an overlapping batch",
			expanded.LogicalOccurrences, expanded.UniqueNodes)
	}

	requested := requestedNodeSet(expanded.SegmentRequests, expanded.UpperRequests)
	canonical := requestedNodeSet(joint.SegmentRequests, joint.UpperRequests)
	if len(requested) != len(canonical) {
		t.Fatalf("requested %d unique nodes, want exactly canonical's %d", len(requested), len(canonical))
	}
}

func requestTotal(segments []SegmentRequest, uppers []UpperRequest) int {
	total := 0
	for _, request := range segments {
		total += len(request.NodeIndexes)
	}
	for _, request := range uppers {
		total += len(request.NodeIndexes)
	}
	return total
}

// TestPlanIndependentRetrievalStillVerifies confirms that fetching exactly
// PlanIndependent's (possibly superset) requested nodes, then filtering down
// to Planner.Plan's canonical Required/Targets before verification (the
// approach the ablation benchmark harness uses for all three ablated
// variants), reconstructs the same finalized Global Root as FULL -- Check 4
// and Check 5 of the ablation protocol.
func TestPlanIndependentRetrievalStillVerifies(t *testing.T) {
	segmentKey := SegmentKey{RegionID: "R0", ShardID: 0, SegmentID: 10}
	shardKey := ShardKey{RegionID: "R0", ShardID: 0}
	metadata := HierarchyMetadata{
		Segments: map[SegmentKey]SegmentMetadata{
			segmentKey: {LeafCount: 8, ShardLeafIndex: 0, Sealed: true},
		},
		Shards:  map[ShardKey]UpperTreeMetadata{shardKey: {LeafCount: 2, ParentLeafIndex: 0}},
		Regions: map[string]UpperTreeMetadata{"R0": {LeafCount: 2, ParentLeafIndex: 0}},
		Global:  UpperTreeMetadata{LeafCount: 2},
	}
	addresses := []PhysicalAddress{
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 1},
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 6},
	}

	segmentLeaves := make([][32]byte, 8)
	for index := range segmentLeaves {
		segmentLeaves[index] = testDigest(fmt.Sprintf("leaf-%d", index))
	}
	segmentRoot, segmentNodes := testTree(segmentLeaves)
	segmentCommitment := hmf.CommitSegmentRoot("R0", 0, 10, 8, segmentRoot)
	shardRawRoot, shardNodes := testTree([][32]byte{segmentCommitment, testDigest("other-segment")})
	shardCommitment := hmf.CommitShardRoot("R0", 0, 2, shardRawRoot)
	regionRawRoot, regionNodes := testTree([][32]byte{shardCommitment, testDigest("other-shard")})
	regionCommitment := hmf.CommitRegionRoot("R0", 2, regionRawRoot)
	globalRawRoot, globalNodes := testTree([][32]byte{regionCommitment, testDigest("other-region")})
	globalRoot := hmf.CommitGlobalRoot(2, globalRawRoot)

	allNodes := map[TreeRef]map[NodePosition][32]byte{
		segmentTree(segmentKey): segmentNodes,
		shardTree(shardKey):     shardNodes,
		regionTree("R0"):        regionNodes,
		globalTree():            globalNodes,
	}

	for _, dedup := range []bool{true, false} {
		independent, err := PlanIndependent(addresses, metadata, dedup)
		if err != nil {
			t.Fatalf("dedup=%v: independent plan: %v", dedup, err)
		}
		// Simulate fetching every requested position (a real reader would
		// naturally collapse duplicate keys server-side; simulate that here
		// by looking each requested position up in the source-of-truth map).
		fetched := make(map[NodeRef][32]byte)
		requested := requestedNodeSet(independent.SegmentRequests, independent.UpperRequests)
		for ref := range requested {
			hash, exists := allNodes[ref.Tree][ref.Position]
			if !exists {
				t.Fatalf("dedup=%v: test node missing for %+v", dedup, ref)
			}
			fetched[ref] = hash
		}

		// The canonical plan (what Planner.Plan produces) determines the
		// final, valid proof structure -- the same approach the ablation
		// benchmark harness uses for every variant.
		canonical, err := NewPlanner().Plan(addresses, metadata)
		if err != nil {
			t.Fatalf("dedup=%v: canonical plan: %v", dedup, err)
		}
		var proofNodes []ProofNode
		for _, tree := range canonical.Trees {
			for _, position := range tree.Required {
				ref := NodeRef{Tree: tree.Tree, Position: position}
				hash, exists := fetched[ref]
				if !exists {
					t.Fatalf("dedup=%v: canonically-required node %+v was not fetched", dedup, ref)
				}
				proofNodes = append(proofNodes, ProofNode{Ref: ref, Hash: hash})
			}
		}
		for _, address := range addresses {
			key := SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
			proofNodes = append(proofNodes, ProofNode{
				Ref:  NodeRef{Tree: segmentTree(key), Position: NodePosition{Level: 0, Index: address.LeafID}},
				Hash: segmentLeaves[address.LeafID],
			})
		}

		service, err := NewService(staticMetadataReader{metadata: metadata}, staticNodeReader{nodes: proofNodes})
		if err != nil {
			t.Fatalf("dedup=%v: new HPP service: %v", dedup, err)
		}
		result, err := service.BuildAndVerify(context.Background(), addresses, globalRoot)
		if err != nil {
			t.Fatalf("dedup=%v: build and verify: %v", dedup, err)
		}
		if result.CalculatedGlobalRoot != globalRoot {
			t.Fatalf("dedup=%v: calculated root = %x, want %x", dedup, result.CalculatedGlobalRoot, globalRoot)
		}
	}
}

// TestExpandRequiredWithOccurrencesRetrievalStillVerifies mirrors
// TestPlanIndependentRetrievalStillVerifies for the corrected NO_DEDUP
// configuration: fetching exactly ExpandRequiredWithOccurrences's requested
// nodes (duplicates collapsed by the simulated reader, as a real one would)
// still reconstructs the same finalized Global Root as FULL.
func TestExpandRequiredWithOccurrencesRetrievalStillVerifies(t *testing.T) {
	segmentKey := SegmentKey{RegionID: "R0", ShardID: 0, SegmentID: 10}
	shardKey := ShardKey{RegionID: "R0", ShardID: 0}
	metadata := HierarchyMetadata{
		Segments: map[SegmentKey]SegmentMetadata{
			segmentKey: {LeafCount: 8, ShardLeafIndex: 0, Sealed: true},
		},
		Shards:  map[ShardKey]UpperTreeMetadata{shardKey: {LeafCount: 2, ParentLeafIndex: 0}},
		Regions: map[string]UpperTreeMetadata{"R0": {LeafCount: 2, ParentLeafIndex: 0}},
		Global:  UpperTreeMetadata{LeafCount: 2},
	}
	addresses := []PhysicalAddress{
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 1},
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 6},
	}

	segmentLeaves := make([][32]byte, 8)
	for index := range segmentLeaves {
		segmentLeaves[index] = testDigest(fmt.Sprintf("leaf-%d", index))
	}
	segmentRoot, segmentNodes := testTree(segmentLeaves)
	segmentCommitment := hmf.CommitSegmentRoot("R0", 0, 10, 8, segmentRoot)
	shardRawRoot, shardNodes := testTree([][32]byte{segmentCommitment, testDigest("other-segment")})
	shardCommitment := hmf.CommitShardRoot("R0", 0, 2, shardRawRoot)
	regionRawRoot, regionNodes := testTree([][32]byte{shardCommitment, testDigest("other-shard")})
	regionCommitment := hmf.CommitRegionRoot("R0", 2, regionRawRoot)
	globalRawRoot, globalNodes := testTree([][32]byte{regionCommitment, testDigest("other-region")})
	globalRoot := hmf.CommitGlobalRoot(2, globalRawRoot)

	allNodes := map[TreeRef]map[NodePosition][32]byte{
		segmentTree(segmentKey): segmentNodes,
		shardTree(shardKey):     shardNodes,
		regionTree("R0"):        regionNodes,
		globalTree():            globalNodes,
	}

	canonical, err := NewPlanner().Plan(addresses, metadata)
	if err != nil {
		t.Fatalf("canonical plan: %v", err)
	}
	expanded, err := ExpandRequiredWithOccurrences(canonical)
	if err != nil {
		t.Fatalf("expand required with occurrences: %v", err)
	}

	fetched := make(map[NodeRef][32]byte)
	requested := requestedNodeSet(expanded.SegmentRequests, expanded.UpperRequests)
	for ref := range requested {
		hash, exists := allNodes[ref.Tree][ref.Position]
		if !exists {
			t.Fatalf("test node missing for %+v", ref)
		}
		fetched[ref] = hash
	}

	var proofNodes []ProofNode
	for _, tree := range canonical.Trees {
		for _, position := range tree.Required {
			ref := NodeRef{Tree: tree.Tree, Position: position}
			hash, exists := fetched[ref]
			if !exists {
				t.Fatalf("canonically-required node %+v was not fetched", ref)
			}
			proofNodes = append(proofNodes, ProofNode{Ref: ref, Hash: hash})
		}
	}
	for _, address := range addresses {
		key := SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
		proofNodes = append(proofNodes, ProofNode{
			Ref:  NodeRef{Tree: segmentTree(key), Position: NodePosition{Level: 0, Index: address.LeafID}},
			Hash: segmentLeaves[address.LeafID],
		})
	}

	service, err := NewService(staticMetadataReader{metadata: metadata}, staticNodeReader{nodes: proofNodes})
	if err != nil {
		t.Fatalf("new HPP service: %v", err)
	}
	result, err := service.BuildAndVerify(context.Background(), addresses, globalRoot)
	if err != nil {
		t.Fatalf("build and verify: %v", err)
	}
	if result.CalculatedGlobalRoot != globalRoot {
		t.Fatalf("calculated root = %x, want %x", result.CalculatedGlobalRoot, globalRoot)
	}
}
