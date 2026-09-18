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
	targets := make(map[NodeRef]PhysicalAddress, len(plan.Addresses))
	for _, address := range plan.Addresses {
		key := SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
		ref := NodeRef{Tree: segmentTree(key), Position: NodePosition{Level: 0, Index: address.LeafID}}
		targets[ref] = address
	}

	leafHashes := make(map[PhysicalAddress][32]byte, len(targets))
	proof := HMFProof{Plan: plan}
	for _, node := range nodes {
		if address, target := targets[node.Ref]; target {
			if _, duplicate := leafHashes[address]; duplicate {
				return HMFProof{}, fmt.Errorf("build HMF proof: duplicate target leaf %+v", address)
			}
			leafHashes[address] = node.Hash
			continue
		}
		proof.Nodes = append(proof.Nodes, node)
	}
	for _, address := range plan.Addresses {
		hash, exists := leafHashes[address]
		if !exists {
			return HMFProof{}, fmt.Errorf("build HMF proof: target leaf missing for address %+v", address)
		}
		proof.Leaves = append(proof.Leaves, RequestedLeaf{Address: address, Hash: hash})
	}
	return proof, nil
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
	if _, err := VerifyHMFProofAgainstRoot(result.Proof, addresses, trustedRoot); err != nil {
		return VerificationResult{}, err
	}
	return result, nil
}
