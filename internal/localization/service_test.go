package localization

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

func TestLocalizeFindsChangedRequestedLeafAndReturnsVerifiableProof(t *testing.T) {
	fixture := newFixture(t)
	failed := cloneProof(fixture.reference.Proof)
	failed.Leaves[0].Hash[0] ^= 0xff
	auditorRoot, err := hpp.VerifyHMFProof(failed, fixture.addresses)
	if err != nil {
		t.Fatalf("calculate failed root: %v", err)
	}

	service, err := NewService(staticReference{result: fixture.reference})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	result, err := service.Localize(context.Background(), Request{
		Addresses: fixture.addresses, AuditorGlobalRoot: auditorRoot,
		FailedProof: failed, AnchoredGlobalRoot: fixture.reference.CalculatedGlobalRoot, K: DefaultJumpLevels,
	})
	if err != nil {
		t.Fatalf("localize: %v", err)
	}
	if result.CalculatedReferenceRoot != fixture.reference.CalculatedGlobalRoot {
		t.Fatal("reference root was not authenticated against the anchored root")
	}
	if len(result.Proof.BadShards) != 1 {
		t.Fatalf("bad shards = %d, want 1", len(result.Proof.BadShards))
	}
	if len(result.Proof.Suspects) != 1 || result.Proof.Suspects[0].Classification != LeafMismatch {
		t.Fatalf("suspects = %+v, want one leaf mismatch", result.Proof.Suspects)
	}
	if result.Proof.Suspects[0].Address == nil || *result.Proof.Suspects[0].Address != fixture.addresses[0] {
		t.Fatalf("suspect address = %+v, want %+v", result.Proof.Suspects[0].Address, fixture.addresses[0])
	}
	if err := VerifyProof(result.Proof, fixture.addresses, fixture.reference.CalculatedGlobalRoot); err != nil {
		t.Fatalf("verify localization proof: %v", err)
	}

	changed := result.Proof
	changed.Suspects = append([]Suspect(nil), result.Proof.Suspects...)
	changed.Suspects[0].ReferenceHash[0] ^= 1
	if err := VerifyProof(changed, fixture.addresses, fixture.reference.CalculatedGlobalRoot); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("changed localization error = %v, want %v", err, ErrInvalidProof)
	}
}

func TestLocalizeReportsUndisclosedSiblingAsAuthenticationNode(t *testing.T) {
	fixture := newFixture(t)
	failed := cloneProof(fixture.reference.Proof)
	changed := false
	for index := range failed.Nodes {
		ref := failed.Nodes[index].Ref
		if ref.Tree.Layer == hpp.LayerSegment && ref.Position.Level == 1 {
			failed.Nodes[index].Hash[0] ^= 0xff
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("fixture has no compressed segment sibling")
	}
	auditorRoot, err := hpp.VerifyHMFProof(failed, fixture.addresses)
	if err != nil {
		t.Fatalf("calculate failed root: %v", err)
	}
	service, _ := NewService(staticReference{result: fixture.reference})
	result, err := service.Localize(context.Background(), Request{
		Addresses: fixture.addresses, AuditorGlobalRoot: auditorRoot, FailedProof: failed,
		AnchoredGlobalRoot: fixture.reference.CalculatedGlobalRoot, K: DefaultJumpLevels,
	})
	if err != nil {
		t.Fatalf("localize: %v", err)
	}
	if len(result.Proof.Suspects) != 1 ||
		result.Proof.Suspects[0].Classification != AuthenticationNodeMismatch ||
		result.Proof.Suspects[0].Ref.Position.Level != 1 {
		t.Fatalf("suspects = %+v, want the undisclosed authentication node", result.Proof.Suspects)
	}
	if err := VerifyProof(result.Proof, fixture.addresses, fixture.reference.CalculatedGlobalRoot); err != nil {
		t.Fatalf("verify localization proof: %v", err)
	}
}

func TestLocalizeRejectsSuccessfulAuditRoot(t *testing.T) {
	fixture := newFixture(t)
	service, _ := NewService(staticReference{result: fixture.reference})
	_, err := service.Localize(context.Background(), Request{
		Addresses: fixture.addresses, AuditorGlobalRoot: fixture.reference.CalculatedGlobalRoot,
		FailedProof: fixture.reference.Proof, AnchoredGlobalRoot: fixture.reference.CalculatedGlobalRoot,
		K: DefaultJumpLevels,
	})
	if !errors.Is(err, ErrNoMismatch) {
		t.Fatalf("error = %v, want %v", err, ErrNoMismatch)
	}
}

func TestLocalizeDefaultsKToSegmentJumpSize(t *testing.T) {
	fixture := newFixture(t)
	failed := cloneProof(fixture.reference.Proof)
	failed.Leaves[0].Hash[0] ^= 0xff
	auditorRoot, err := hpp.VerifyHMFProof(failed, fixture.addresses)
	if err != nil {
		t.Fatalf("calculate failed root: %v", err)
	}
	service, _ := NewService(staticReference{result: fixture.reference})
	result, err := service.Localize(context.Background(), Request{
		Addresses: fixture.addresses, AuditorGlobalRoot: auditorRoot,
		FailedProof: failed, AnchoredGlobalRoot: fixture.reference.CalculatedGlobalRoot,
	})
	if err != nil {
		t.Fatalf("localize with default k: %v", err)
	}
	if result.Proof.K != DefaultJumpLevels {
		t.Fatalf("default k = %d, want %d", result.Proof.K, DefaultJumpLevels)
	}
}

type fixture struct {
	addresses []hpp.PhysicalAddress
	reference hpp.VerificationResult
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	address := hpp.PhysicalAddress{RegionID: "R0", ShardID: 0, SegmentID: 10, LeafID: 1}
	segmentTree := hpp.TreeRef{Layer: hpp.LayerSegment, RegionID: "R0", ShardID: 0, SegmentID: 10}
	shardTree := hpp.TreeRef{Layer: hpp.LayerShard, RegionID: "R0", ShardID: 0}
	regionTree := hpp.TreeRef{Layer: hpp.LayerRegion, RegionID: "R0"}
	globalTree := hpp.TreeRef{Layer: hpp.LayerGlobal}

	segmentLeaves := [][32]byte{digest("log-0"), digest("log-1"), digest("log-2"), digest("log-3")}
	segmentRaw, segmentNodes := makeTree(segmentLeaves)
	segmentRoot := hmf.CommitSegmentRoot("R0", 0, 10, 4, segmentRaw)
	shardRaw, shardNodes := makeTree([][32]byte{segmentRoot, digest("other-segment")})
	shardRoot := hmf.CommitShardRoot("R0", 0, 2, shardRaw)
	regionRaw, regionNodes := makeTree([][32]byte{shardRoot, digest("other-shard")})
	regionRoot := hmf.CommitRegionRoot("R0", 2, regionRaw)
	globalRaw, globalNodes := makeTree([][32]byte{regionRoot, digest("other-region")})
	globalRoot := hmf.CommitGlobalRoot(2, globalRaw)

	metadata := hpp.HierarchyMetadata{
		Segments: map[hpp.SegmentKey]hpp.SegmentMetadata{
			{RegionID: "R0", ShardID: 0, SegmentID: 10}: {LeafCount: 4, ShardLeafIndex: 0, Sealed: true},
		},
		Shards: map[hpp.ShardKey]hpp.UpperTreeMetadata{
			{RegionID: "R0", ShardID: 0}: {LeafCount: 2, ParentLeafIndex: 0},
		},
		Regions: map[string]hpp.UpperTreeMetadata{"R0": {LeafCount: 2, ParentLeafIndex: 0}},
		Global:  hpp.UpperTreeMetadata{LeafCount: 2},
	}
	nodes := map[hpp.TreeRef]map[hpp.NodePosition][32]byte{
		segmentTree: segmentNodes, shardTree: shardNodes, regionTree: regionNodes, globalTree: globalNodes,
	}
	service, err := hpp.NewService(fixtureMetadata{metadata: metadata}, fixtureNodes{nodes: nodes})
	if err != nil {
		t.Fatalf("new HPP service: %v", err)
	}
	result, err := service.BuildAndVerify(context.Background(), []hpp.PhysicalAddress{address}, globalRoot)
	if err != nil {
		t.Fatalf("build reference proof: %v", err)
	}
	return fixture{addresses: []hpp.PhysicalAddress{address}, reference: result}
}

type staticReference struct{ result hpp.VerificationResult }

func (builder staticReference) BuildAndVerify(context.Context, []hpp.PhysicalAddress, [32]byte) (hpp.VerificationResult, error) {
	return builder.result, nil
}

type fixtureMetadata struct{ metadata hpp.HierarchyMetadata }

func (reader fixtureMetadata) LoadHierarchyMetadata(context.Context, []hpp.PhysicalAddress) (hpp.HierarchyMetadata, error) {
	return reader.metadata, nil
}

type fixtureNodes struct {
	nodes map[hpp.TreeRef]map[hpp.NodePosition][32]byte
}

func (reader fixtureNodes) FetchProofNodes(_ context.Context, plan hpp.ProofPlan) ([]hpp.ProofNode, error) {
	var result []hpp.ProofNode
	for _, tree := range plan.Trees {
		for _, position := range tree.Required {
			result = append(result, hpp.ProofNode{Ref: hpp.NodeRef{Tree: tree.Tree, Position: position}, Hash: reader.nodes[tree.Tree][position]})
		}
	}
	for _, address := range plan.Addresses {
		tree := hpp.TreeRef{Layer: hpp.LayerSegment, RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
		position := hpp.NodePosition{Level: 0, Index: address.LeafID}
		result = append(result, hpp.ProofNode{Ref: hpp.NodeRef{Tree: tree, Position: position}, Hash: reader.nodes[tree][position]})
	}
	return result, nil
}

func cloneProof(input hpp.HMFProof) hpp.HMFProof {
	result := input
	result.Leaves = append([]hpp.RequestedLeaf(nil), input.Leaves...)
	result.Nodes = append([]hpp.ProofNode(nil), input.Nodes...)
	return result
}

func makeTree(leaves [][32]byte) ([32]byte, map[hpp.NodePosition][32]byte) {
	nodes := make(map[hpp.NodePosition][32]byte)
	current := append([][32]byte(nil), leaves...)
	for index, hash := range current {
		nodes[hpp.NodePosition{Level: 0, Index: int64(index)}] = hash
	}
	var level int32
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

func digest(value string) [32]byte { return sha256.Sum256([]byte(value)) }
