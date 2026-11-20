package hpp

import (
	"cmp"
	"context"
	"fmt"
	"strings"
)

type Service struct {
	planner  *Planner
	metadata MetadataReader
	nodes    ProofNodeReader
}

func NewService(metadata MetadataReader, nodes ProofNodeReader) (*Service, error) {
	if metadata == nil {
		return nil, fmt.Errorf("new HPP service: metadata reader is nil")
	}
	if nodes == nil {
		return nil, fmt.Errorf("new HPP service: proof-node reader is nil")
	}
	return &Service{planner: NewPlanner(), metadata: metadata, nodes: nodes}, nil
}

func (service *Service) BuildProof(ctx context.Context, addresses []PhysicalAddress) (HMFProof, error) {
	normalized, err := normalizeAddresses(addresses)
	if err != nil {
		return HMFProof{}, fmt.Errorf("build HMF proof: %w", err)
	}
	if len(normalized) == 0 {
		return HMFProof{}, fmt.Errorf("build HMF proof: at least one physical address is required")
	}
	metadata, err := service.metadata.LoadHierarchyMetadata(ctx, normalized)
	if err != nil {
		return HMFProof{}, fmt.Errorf("build HMF proof: load hierarchy metadata: %w", err)
	}
	plan, err := service.planner.Plan(normalized, metadata)
	if err != nil {
		return HMFProof{}, fmt.Errorf("build HMF proof: %w", err)
	}
	nodes, err := service.nodes.FetchProofNodes(ctx, plan)
	if err != nil {
		return HMFProof{}, fmt.Errorf("build HMF proof: fetch proof nodes: %w", err)
	}
	leaves, rest, err := splitTargetLeaves(plan.Addresses, nodes)
	if err != nil {
		return HMFProof{}, fmt.Errorf("build HMF proof: %w", err)
	}
	return HMFProof{Plan: plan, Leaves: leaves, Nodes: rest}, nil
}

// ReferenceFromProof rebuilds the reference proof for a failed audit without
// refetching what the failed proof already carries. It keeps the supplied
// plan and authentication nodes, loads only the stored hashes of the
// requested leaves, and accepts the result only if it reproduces trustedRoot.
// A supplied proof whose plan or authentication nodes differ from the
// committed state therefore fails here, and the caller must fall back to
// BuildAndVerify.
func (service *Service) ReferenceFromProof(ctx context.Context, proof HMFProof,
	addresses []PhysicalAddress, trustedRoot [32]byte) (VerificationResult, error) {

	leafPlan := ProofPlan{Addresses: proof.Plan.Addresses}
	var segments []TreePlan
	for _, tree := range proof.Plan.Trees {
		if tree.Tree.Layer == LayerSegment {
			segments = append(segments, TreePlan{Tree: tree.Tree, LeafCount: tree.LeafCount, Targets: tree.Targets})
		}
	}
	leafPlan.SegmentRequests, _ = buildRequests(segments)
	nodes, err := service.nodes.FetchProofNodes(ctx, leafPlan)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("rebuild reference proof: fetch stored leaves: %w", err)
	}
	leaves, rest, err := splitTargetLeaves(leafPlan.Addresses, nodes)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("rebuild reference proof: %w", err)
	}
	if len(rest) != 0 {
		return VerificationResult{}, fmt.Errorf("rebuild reference proof: %d unrequested nodes returned", len(rest))
	}
	reference := HMFProof{Plan: proof.Plan, Leaves: leaves, Nodes: proof.Nodes}
	trace, err := TraceHMFProof(reference, addresses)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("rebuild reference proof: %w", err)
	}
	if err := matchTrustedRoot(trace.GlobalRoot, trustedRoot); err != nil {
		return VerificationResult{}, fmt.Errorf("rebuild reference proof: %w", err)
	}
	return VerificationResult{CalculatedGlobalRoot: trace.GlobalRoot, Proof: reference, Trace: &trace}, nil
}

// splitTargetLeaves separates the requested Segment leaves from the
// authentication nodes, returning the leaves in plan address order.
//
// A reader that returns its nodes in canonical order (the Cassandra reader does) lets the leaves be
// found by one merge walk against the sorted plan addresses, with no per-node map. Any other order,
// a missing or duplicated leaf, or unsorted addresses fall back to the map-based split, which also
// produces the errors.
func splitTargetLeaves(addresses []PhysicalAddress, nodes []ProofNode) ([]RequestedLeaf, []ProofNode, error) {
	if leaves, rest, ok := splitSortedTargetLeaves(addresses, nodes); ok {
		return leaves, rest, nil
	}
	return splitTargetLeavesByMap(addresses, nodes)
}

// compareNodeRefs is the canonical node order: tree layer, region, shard, segment, level, index.
func compareNodeRefs(left, right NodeRef) int {
	if left.Tree.Layer != right.Tree.Layer {
		return cmp.Compare(left.Tree.Layer, right.Tree.Layer)
	}
	if left.Tree.RegionID != right.Tree.RegionID {
		return strings.Compare(left.Tree.RegionID, right.Tree.RegionID)
	}
	if left.Tree.ShardID != right.Tree.ShardID {
		return cmp.Compare(left.Tree.ShardID, right.Tree.ShardID)
	}
	if left.Tree.SegmentID != right.Tree.SegmentID {
		return cmp.Compare(left.Tree.SegmentID, right.Tree.SegmentID)
	}
	if left.Position.Level != right.Position.Level {
		return cmp.Compare(left.Position.Level, right.Position.Level)
	}
	return cmp.Compare(left.Position.Index, right.Position.Index)
}

func splitSortedTargetLeaves(addresses []PhysicalAddress, nodes []ProofNode) ([]RequestedLeaf, []ProofNode, bool) {
	for index := 1; index < len(addresses); index++ {
		if compareAddresses(addresses[index-1], addresses[index]) >= 0 {
			return nil, nil, false
		}
	}
	leaves := make([]RequestedLeaf, 0, len(addresses))
	rest := make([]ProofNode, 0, max(len(nodes)-len(addresses), 0))
	for index := range nodes {
		node := &nodes[index]
		if index > 0 && compareNodeRefs(nodes[index-1].Ref, node.Ref) >= 0 {
			return nil, nil, false
		}
		if next := len(leaves); next < len(addresses) && node.Ref.Tree.Layer == LayerSegment && node.Ref.Position.Level == 0 {
			address := addresses[next]
			target := PhysicalAddress{RegionID: node.Ref.Tree.RegionID, ShardID: node.Ref.Tree.ShardID,
				SegmentID: node.Ref.Tree.SegmentID, LeafID: node.Ref.Position.Index}
			switch order := compareAddresses(target, address); {
			case order == 0:
				leaves = append(leaves, RequestedLeaf{Address: address, Hash: node.Hash})
				continue
			case order > 0:
				return nil, nil, false // the address has no leaf node
			}
		}
		rest = append(rest, *node)
	}
	if len(leaves) != len(addresses) {
		return nil, nil, false
	}
	return leaves, rest, true
}

func splitTargetLeavesByMap(addresses []PhysicalAddress, nodes []ProofNode) ([]RequestedLeaf, []ProofNode, error) {
	targets := make(map[NodeRef]PhysicalAddress, len(addresses))
	for _, address := range addresses {
		key := SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
		ref := NodeRef{Tree: segmentTree(key), Position: NodePosition{Level: 0, Index: address.LeafID}}
		targets[ref] = address
	}

	leafHashes := make(map[PhysicalAddress][32]byte, len(targets))
	rest := make([]ProofNode, 0, len(nodes))
	for _, node := range nodes {
		if address, target := targets[node.Ref]; target {
			if _, duplicate := leafHashes[address]; duplicate {
				return nil, nil, fmt.Errorf("duplicate target leaf %+v", address)
			}
			leafHashes[address] = node.Hash
			continue
		}
		rest = append(rest, node)
	}
	leaves := make([]RequestedLeaf, 0, len(addresses))
	for _, address := range addresses {
		hash, exists := leafHashes[address]
		if !exists {
			return nil, nil, fmt.Errorf("target leaf missing for address %+v", address)
		}
		leaves = append(leaves, RequestedLeaf{Address: address, Hash: hash})
	}
	return leaves, rest, nil
}

func (service *Service) BuildAndCalculate(ctx context.Context,
	addresses []PhysicalAddress) (VerificationResult, error) {

	proof, err := service.BuildProof(ctx, addresses)
	if err != nil {
		return VerificationResult{}, err
	}
	root, err := VerifyHMFProof(proof, addresses)
	if err != nil {
		return VerificationResult{}, err
	}
	return VerificationResult{CalculatedGlobalRoot: root, Proof: proof}, nil
}

func (service *Service) BuildAndVerify(ctx context.Context, addresses []PhysicalAddress,
	trustedRoot [32]byte) (VerificationResult, error) {

	result, err := service.BuildAndCalculate(ctx, addresses)
	if err != nil {
		return VerificationResult{}, err
	}
	if err := matchTrustedRoot(result.CalculatedGlobalRoot, trustedRoot); err != nil {
		return VerificationResult{}, err
	}
	return result, nil
}
