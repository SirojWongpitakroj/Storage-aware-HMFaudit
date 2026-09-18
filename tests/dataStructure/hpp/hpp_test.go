package tests

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

func TestHPPBuildsSelfContainedBatchProofFromAddresses(t *testing.T) {
	segmentA := hpp.SegmentKey{RegionID: "R0", ShardID: 0, SegmentID: 10}
	segmentB := hpp.SegmentKey{RegionID: "R0", ShardID: 0, SegmentID: 11}
	shard := hpp.ShardKey{RegionID: "R0", ShardID: 0}
	metadata := hpp.HierarchyMetadata{
		Segments: map[hpp.SegmentKey]hpp.SegmentMetadata{
			segmentA: {LeafCount: 4, ShardLeafIndex: 0, Sealed: true},
			segmentB: {LeafCount: 2, ShardLeafIndex: 1, Sealed: true},
		},
		Shards: map[hpp.ShardKey]hpp.UpperTreeMetadata{
			shard: {LeafCount: 3, ParentLeafIndex: 0},
		},
		Regions: map[string]hpp.UpperTreeMetadata{
			"R0": {LeafCount: 2, ParentLeafIndex: 0},
		},
		Global: hpp.UpperTreeMetadata{LeafCount: 2},
	}

	segmentALeaves := hashes("segment-a", 4)
	segmentBLeaves := hashes("segment-b", 2)
	segmentARoot, segmentANodes := completeTree(segmentALeaves)
	segmentBRoot, segmentBNodes := completeTree(segmentBLeaves)
	shardRoot, shardNodes := completeTree([][32]byte{segmentARoot, segmentBRoot, digest("unused-segment")})
	regionRoot, regionNodes := completeTree([][32]byte{shardRoot, digest("unused-shard")})
	globalRoot, globalNodes := completeTree([][32]byte{regionRoot, digest("unused-region")})

	allNodes := map[hpp.TreeRef]map[hpp.NodePosition][32]byte{
		{Layer: hpp.LayerSegment, RegionID: "R0", ShardID: 0, SegmentID: 10}: segmentANodes,
		{Layer: hpp.LayerSegment, RegionID: "R0", ShardID: 0, SegmentID: 11}: segmentBNodes,
		{Layer: hpp.LayerShard, RegionID: "R0", ShardID: 0}:                  shardNodes,
		{Layer: hpp.LayerRegion, RegionID: "R0"}:                             regionNodes,
		{Layer: hpp.LayerGlobal}:                                             globalNodes,
	}
	addresses := []hpp.PhysicalAddress{
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 1},
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 2},
		{RegionID: "R0", ShardID: 0, SegmentID: 11, LeafID: 0},
		{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 1}, // duplicate
	}

	nodeReader := &plannedNodeReader{allNodes: allNodes}
	service, err := hpp.NewService(fixedMetadataReader{metadata: metadata}, nodeReader)
	if err != nil {
		t.Fatalf("new HPP service: %v", err)
	}
	result, err := service.BuildAndCalculate(context.Background(), addresses)
	if err != nil {
		t.Fatalf("build and calculate HPP proof: %v", err)
	}
	if result.CalculatedGlobalRoot != globalRoot {
		t.Fatalf("calculated root = %x, want %x", result.CalculatedGlobalRoot, globalRoot)
	}
	if len(result.Proof.Plan.Addresses) != 3 || len(result.Proof.Leaves) != 3 {
		t.Fatalf("proof addresses/leaves = %d/%d, want 3/3",
			len(result.Proof.Plan.Addresses), len(result.Proof.Leaves))
	}
	if len(nodeReader.plan.SegmentRequests) != 2 || len(nodeReader.plan.UpperRequests) != 3 {
		t.Fatalf("request groups segment/upper = %d/%d, want 2/3",
			len(nodeReader.plan.SegmentRequests), len(nodeReader.plan.UpperRequests))
	}
	assertRequestsContainTargetLeaves(t, nodeReader.plan)

	if _, err := hpp.VerifyHMFProofAgainstRoot(result.Proof, addresses, globalRoot); err != nil {
		t.Fatalf("auditor verification: %v", err)
	}

	t.Run("tampered target leaf", func(t *testing.T) {
		changed := result.Proof
		changed.Leaves = append([]hpp.RequestedLeaf(nil), result.Proof.Leaves...)
		changed.Leaves[0].Hash[0] ^= 0xff
		if _, err := hpp.VerifyHMFProofAgainstRoot(changed, addresses, globalRoot); err == nil {
			t.Fatal("accepted a tampered target leaf")
		}
	})

	t.Run("missing sibling", func(t *testing.T) {
		changed := result.Proof
		changed.Nodes = append([]hpp.ProofNode(nil), result.Proof.Nodes[1:]...)
		if _, err := hpp.VerifyHMFProof(changed, addresses); err == nil {
			t.Fatal("accepted an incomplete sibling proof")
		}
	})

	t.Run("different requested address", func(t *testing.T) {
		changed := append([]hpp.PhysicalAddress(nil), addresses...)
		changed[0].LeafID = 0
		if _, err := hpp.VerifyHMFProof(result.Proof, changed); err == nil {
			t.Fatal("accepted addresses that differ from the authenticated batch")
		}
	})
}

func TestHPPRejectsMissingFetchedTargetLeaf(t *testing.T) {
	address := hpp.PhysicalAddress{RegionID: "R0", ShardID: 0, SegmentID: 1, LeafID: 0}
	metadata := hpp.HierarchyMetadata{
		Segments: map[hpp.SegmentKey]hpp.SegmentMetadata{
			{RegionID: "R0", ShardID: 0, SegmentID: 1}: {LeafCount: 1, ShardLeafIndex: 0, Sealed: true},
		},
		Shards: map[hpp.ShardKey]hpp.UpperTreeMetadata{
			{RegionID: "R0", ShardID: 0}: {LeafCount: 1, ParentLeafIndex: 0},
		},
		Regions: map[string]hpp.UpperTreeMetadata{"R0": {LeafCount: 1, ParentLeafIndex: 0}},
		Global:  hpp.UpperTreeMetadata{LeafCount: 1},
	}
	service, err := hpp.NewService(fixedMetadataReader{metadata: metadata}, emptyNodeReader{})
	if err != nil {
		t.Fatalf("new HPP service: %v", err)
	}
	if _, err := service.BuildAndCalculate(context.Background(), []hpp.PhysicalAddress{address}); err == nil {
		t.Fatal("HPP accepted a response with no requested Segment leaf")
	}
}

type fixedMetadataReader struct {
	metadata hpp.HierarchyMetadata
}

func (reader fixedMetadataReader) LoadHierarchyMetadata(context.Context,
	[]hpp.PhysicalAddress) (hpp.HierarchyMetadata, error) {
	return reader.metadata, nil
}

type plannedNodeReader struct {
	allNodes map[hpp.TreeRef]map[hpp.NodePosition][32]byte
	plan     hpp.ProofPlan
}

func (reader *plannedNodeReader) FetchProofNodes(_ context.Context,
	plan hpp.ProofPlan) ([]hpp.ProofNode, error) {
	reader.plan = plan
	result := make([]hpp.ProofNode, 0)
	appendRequest := func(tree hpp.TreeRef, level int32, indexes []int64) error {
		for _, index := range indexes {
			position := hpp.NodePosition{Level: level, Index: index}
			hash, exists := reader.allNodes[tree][position]
			if !exists {
				return fmt.Errorf("test node missing for tree %+v at %+v", tree, position)
			}
			result = append(result, hpp.ProofNode{
				Ref: hpp.NodeRef{Tree: tree, Position: position}, Hash: hash,
			})
		}
		return nil
	}
	for _, request := range plan.SegmentRequests {
		if err := appendRequest(request.Tree, request.Level, request.NodeIndexes); err != nil {
			return nil, err
		}
	}
	for _, request := range plan.UpperRequests {
		if err := appendRequest(request.Tree, request.Level, request.NodeIndexes); err != nil {
			return nil, err
		}
	}
	return result, nil
}

type emptyNodeReader struct{}

func (emptyNodeReader) FetchProofNodes(context.Context, hpp.ProofPlan) ([]hpp.ProofNode, error) {
	return nil, nil
}

func assertRequestsContainTargetLeaves(t *testing.T, plan hpp.ProofPlan) {
	t.Helper()
	targets := make(map[hpp.NodeRef]bool, len(plan.Addresses))
	for _, address := range plan.Addresses {
		tree := hpp.TreeRef{
			Layer: hpp.LayerSegment, RegionID: address.RegionID,
			ShardID: address.ShardID, SegmentID: address.SegmentID,
		}
		targets[hpp.NodeRef{Tree: tree, Position: hpp.NodePosition{Level: 0, Index: address.LeafID}}] = false
	}
	for _, request := range plan.SegmentRequests {
		for _, index := range request.NodeIndexes {
			ref := hpp.NodeRef{Tree: request.Tree, Position: hpp.NodePosition{Level: request.Level, Index: index}}
			if _, target := targets[ref]; target {
				targets[ref] = true
			}
		}
	}
	for target, found := range targets {
		if !found {
			t.Fatalf("target leaf absent from Cassandra requests: %+v", target)
		}
	}
}

func completeTree(leaves [][32]byte) ([32]byte, map[hpp.NodePosition][32]byte) {
	nodes := make(map[hpp.NodePosition][32]byte)
	current := append([][32]byte(nil), leaves...)
	for index, hash := range current {
		nodes[hpp.NodePosition{Level: 0, Index: int64(index)}] = hash
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
			nodes[hpp.NodePosition{Level: level + 1, Index: int64(index / 2)}] = hash
		}
		current = next
		level++
	}
	return current[0], nodes
}

func hashes(prefix string, count int) [][32]byte {
	result := make([][32]byte, count)
	for index := range result {
		result[index] = digest(fmt.Sprintf("%s-%d", prefix, index))
	}
	return result
}

func digest(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}
