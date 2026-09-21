package hpp

import (
	"context"
	"fmt"
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
func splitTargetLeaves(addresses []PhysicalAddress, nodes []ProofNode) ([]RequestedLeaf, []ProofNode, error) {
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
