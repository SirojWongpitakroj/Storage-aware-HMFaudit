package hpp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
)

func TestPlanTreeDeduplicatesSharedPathsAndPromotesOddNodes(t *testing.T) {
	tree := TreeRef{Layer: LayerSegment, RegionID: "R0", ShardID: 0, SegmentID: 1}
	shared, err := planTree(tree, 4, map[int64]struct{}{1: {}, 2: {}})
	if err != nil {
		t.Fatalf("plan shared tree: %v", err)
	}
	wantShared := []NodePosition{{Level: 0, Index: 0}, {Level: 0, Index: 3}}
	assertPositions(t, shared.Required, wantShared)

	odd, err := planTree(tree, 5, map[int64]struct{}{4: {}})
	if err != nil {
		t.Fatalf("plan odd tree: %v", err)
	}
	wantOdd := []NodePosition{{Level: 2, Index: 0}}
	assertPositions(t, odd.Required, wantOdd)
}

func TestPlannerAndVerifierReconstructGlobalRoot(t *testing.T) {
	segmentKey := SegmentKey{RegionID: "R0", ShardID: 0, SegmentID: 10}
	shardKey := ShardKey{RegionID: "R0", ShardID: 0}
	metadata := HierarchyMetadata{
		Segments: map[SegmentKey]SegmentMetadata{
			segmentKey: {LeafCount: 4, ShardLeafIndex: 0, Sealed: true},
		},
		Shards: map[ShardKey]UpperTreeMetadata{
			shardKey: {LeafCount: 2, ParentLeafIndex: 0},
		},
		Regions: map[string]UpperTreeMetadata{
			"R0": {LeafCount: 2, ParentLeafIndex: 0},
		},
		Global: UpperTreeMetadata{LeafCount: 2},
	}
	addresses := []PhysicalAddress{
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 1},
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 2},
	}
	plan, err := NewPlanner().Plan(addresses, metadata)
	if err != nil {
		t.Fatalf("plan HMF proof: %v", err)
	}
	if len(plan.SegmentRequests) != 1 {
		t.Fatalf("segment request count = %d, want 1", len(plan.SegmentRequests))
	}
	wantIndexes := []int64{0, 1, 2, 3}
	if fmt.Sprint(plan.SegmentRequests[0].NodeIndexes) != fmt.Sprint(wantIndexes) {
		t.Fatalf("segment request indexes = %v, want target leaves and siblings %v",
			plan.SegmentRequests[0].NodeIndexes, wantIndexes)
	}

	segmentLeaves := [][32]byte{testDigest("log-0"), testDigest("log-1"), testDigest("log-2"), testDigest("log-3")}
	segmentRoot, segmentNodes := testTree(segmentLeaves)
	shardRoot, shardNodes := testTree([][32]byte{segmentRoot, testDigest("other-segment")})
	regionRoot, regionNodes := testTree([][32]byte{shardRoot, testDigest("other-shard")})
	globalRoot, globalNodes := testTree([][32]byte{regionRoot, testDigest("other-region")})

	allNodes := map[TreeRef]map[NodePosition][32]byte{
		segmentTree(segmentKey): segmentNodes,
		shardTree(shardKey):     shardNodes,
		regionTree("R0"):        regionNodes,
		globalTree():            globalNodes,
	}
	proof := HMFProof{Plan: plan}
	for _, tree := range plan.Trees {
		for _, position := range tree.Required {
			hash, exists := allNodes[tree.Tree][position]
			if !exists {
				t.Fatalf("test node missing for tree %+v position %+v", tree.Tree, position)
			}
			proof.Nodes = append(proof.Nodes, ProofNode{Ref: NodeRef{Tree: tree.Tree, Position: position}, Hash: hash})
		}
	}
	requested := []RequestedLeaf{
		{Address: addresses[0], Hash: segmentLeaves[1]},
		{Address: addresses[1], Hash: segmentLeaves[2]},
	}
	proof.Leaves = requested

	calculated, err := VerifyHMFProofAgainstRoot(proof, addresses, globalRoot)
	if err != nil {
		t.Fatalf("verify HMF proof: %v", err)
	}
	if calculated != globalRoot {
		t.Fatalf("calculated root = %x, want %x", calculated, globalRoot)
	}
	fetched := append([]ProofNode(nil), proof.Nodes...)
	for _, leaf := range requested {
		key := SegmentKey{RegionID: leaf.Address.RegionID, ShardID: leaf.Address.ShardID, SegmentID: leaf.Address.SegmentID}
		fetched = append(fetched, ProofNode{
			Ref: NodeRef{
				Tree:     segmentTree(key),
				Position: NodePosition{Level: 0, Index: leaf.Address.LeafID},
			},
			Hash: leaf.Hash,
		})
	}
	service, err := NewService(staticMetadataReader{metadata: metadata}, staticNodeReader{nodes: fetched})
	if err != nil {
		t.Fatalf("new HPP service: %v", err)
	}
	serviceResult, err := service.BuildAndVerify(context.Background(), addresses, globalRoot)
	if err != nil {
		t.Fatalf("service build and verify: %v", err)
	}
	if serviceResult.CalculatedGlobalRoot != globalRoot {
		t.Fatalf("service root = %x, want %x", serviceResult.CalculatedGlobalRoot, globalRoot)
	}
	if len(serviceResult.Proof.Leaves) != len(addresses) {
		t.Fatalf("returned target leaf count = %d, want %d", len(serviceResult.Proof.Leaves), len(addresses))
	}
	if len(serviceResult.Proof.Nodes) != len(proof.Nodes) {
		t.Fatalf("returned sibling count = %d, want %d", len(serviceResult.Proof.Nodes), len(proof.Nodes))
	}

	t.Run("missing proof node", func(t *testing.T) {
		changed := proof
		changed.Nodes = append([]ProofNode(nil), proof.Nodes[1:]...)
		if _, err := VerifyHMFProof(changed, addresses); err == nil {
			t.Fatal("verification accepted a missing proof node")
		}
	})

	t.Run("extra proof node", func(t *testing.T) {
		changed := proof
		changed.Nodes = append([]ProofNode(nil), proof.Nodes...)
		changed.Nodes = append(changed.Nodes, ProofNode{
			Ref:  NodeRef{Tree: globalTree(), Position: NodePosition{Level: 9, Index: 9}},
			Hash: testDigest("extra"),
		})
		if _, err := VerifyHMFProof(changed, addresses); err == nil {
			t.Fatal("verification accepted an extra proof node")
		}
	})

	t.Run("changed sibling hash", func(t *testing.T) {
		changed := proof
		changed.Nodes = append([]ProofNode(nil), proof.Nodes...)
		changed.Nodes[0].Hash[0] ^= 0xff
		if _, err := VerifyHMFProofAgainstRoot(changed, addresses, globalRoot); err == nil {
			t.Fatal("verification accepted a changed sibling hash")
		}
	})

	t.Run("missing requested leaf", func(t *testing.T) {
		changed := proof
		changed.Leaves = append([]RequestedLeaf(nil), proof.Leaves[:1]...)
		if _, err := VerifyHMFProof(changed, addresses); err == nil {
			t.Fatal("verification accepted a missing requested leaf")
		}
	})

	t.Run("changed target leaf hash", func(t *testing.T) {
		changed := proof
		changed.Leaves = append([]RequestedLeaf(nil), proof.Leaves...)
		changed.Leaves[0].Hash[0] ^= 0xff
		if _, err := VerifyHMFProofAgainstRoot(changed, addresses, globalRoot); err == nil {
			t.Fatal("verification accepted a changed target leaf hash")
		}
	})
}

func TestPlannerRejectsUnsealedSegment(t *testing.T) {
	address := PhysicalAddress{RegionID: "R0", ShardID: 0, SegmentID: 1, LeafID: 0}
	metadata := HierarchyMetadata{
		Segments: map[SegmentKey]SegmentMetadata{
			{RegionID: "R0", ShardID: 0, SegmentID: 1}: {LeafCount: 1, Sealed: false},
		},
	}
	if _, err := NewPlanner().Plan([]PhysicalAddress{address}, metadata); err == nil {
		t.Fatal("planner accepted an active segment")
	}
}

func TestPlannerDeduplicatesAddressesAndSharedUpperPaths(t *testing.T) {
	first := PhysicalAddress{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 0}
	second := PhysicalAddress{RegionID: "R0", ShardID: 0, SegmentID: 11, LeafID: 0}
	metadata := HierarchyMetadata{
		Segments: map[SegmentKey]SegmentMetadata{
			{RegionID: "R0", ShardID: 0, SegmentID: 10}: {LeafCount: 2, ShardLeafIndex: 0, Sealed: true},
			{RegionID: "R0", ShardID: 0, SegmentID: 11}: {LeafCount: 2, ShardLeafIndex: 1, Sealed: true},
		},
		Shards: map[ShardKey]UpperTreeMetadata{
			{RegionID: "R0", ShardID: 0}: {LeafCount: 2, ParentLeafIndex: 0},
		},
		Regions: map[string]UpperTreeMetadata{"R0": {LeafCount: 1, ParentLeafIndex: 0}},
		Global:  UpperTreeMetadata{LeafCount: 1},
	}
	plan, err := NewPlanner().Plan([]PhysicalAddress{first, first, second}, metadata)
	if err != nil {
		t.Fatalf("plan shared hierarchy: %v", err)
	}
	if len(plan.Addresses) != 2 {
		t.Fatalf("normalized address count = %d, want 2", len(plan.Addresses))
	}
	for _, tree := range plan.Trees {
		if tree.Tree.Layer == LayerShard {
			if len(tree.Targets) != 2 || len(tree.Required) != 0 {
				t.Fatalf("shard plan targets/required = %+v/%+v, want two reconstructible targets and no proof nodes",
					tree.Targets, tree.Required)
			}
			return
		}
	}
	t.Fatal("shard plan not found")
}

func TestRandomMultiproofsMatchCompleteTreeRoots(t *testing.T) {
	random := rand.New(rand.NewSource(42))
	for leafCount := 1; leafCount <= 40; leafCount++ {
		leaves := make([][32]byte, leafCount)
		for index := range leaves {
			leaves[index] = testDigest(fmt.Sprintf("tree-%d-leaf-%d", leafCount, index))
		}
		wantRoot, allNodes := testTree(leaves)
		for iteration := 0; iteration < 20; iteration++ {
			targets := make(map[int64]struct{})
			for len(targets) == 0 {
				for index := range leaves {
					if random.Intn(4) == 0 {
						targets[int64(index)] = struct{}{}
					}
				}
			}
			plan, err := planTree(TreeRef{Layer: LayerSegment}, int64(leafCount), targets)
			if err != nil {
				t.Fatalf("plan %d-leaf tree: %v", leafCount, err)
			}
			known := make(map[int64][32]byte, len(targets))
			for index := range targets {
				known[index] = leaves[index]
			}
			proof := make(map[NodePosition][32]byte, len(plan.Required))
			for _, position := range plan.Required {
				proof[position] = allNodes[position]
			}
			gotRoot, err := reconstructTreeRoot(int64(leafCount), known, proof)
			if err != nil {
				t.Fatalf("reconstruct %d-leaf tree: %v", leafCount, err)
			}
			if gotRoot != wantRoot {
				t.Fatalf("%d-leaf root = %x, want %x", leafCount, gotRoot, wantRoot)
			}
		}
	}
}

func testTree(leaves [][32]byte) ([32]byte, map[NodePosition][32]byte) {
	nodes := make(map[NodePosition][32]byte)
	current := append([][32]byte(nil), leaves...)
	for index, hash := range current {
		nodes[NodePosition{Level: 0, Index: int64(index)}] = hash
	}
	level := int32(0)
	for len(current) > 1 {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for index := 0; index < len(current); index += 2 {
			hash := current[index]
			if index+1 < len(current) {
				hash = domain.HashPair("NODE", &current[index], &current[index+1])
			}
			next = append(next, hash)
			nodes[NodePosition{Level: level + 1, Index: int64(index / 2)}] = hash
		}
		current = next
		level++
	}
	return current[0], nodes
}

func testDigest(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}

func assertPositions(t *testing.T, got, want []NodePosition) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("positions = %+v, want %+v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("position %d = %+v, want %+v", index, got[index], want[index])
		}
	}
}

type staticMetadataReader struct {
	metadata HierarchyMetadata
}

func (reader staticMetadataReader) LoadHierarchyMetadata(_ context.Context,
	_ []PhysicalAddress) (HierarchyMetadata, error) {

	return reader.metadata, nil
}

type staticNodeReader struct {
	nodes []ProofNode
}

func (reader staticNodeReader) FetchProofNodes(_ context.Context, _ ProofPlan) ([]ProofNode, error) {
	return append([]ProofNode(nil), reader.nodes...), nil
}
