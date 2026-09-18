package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

const (
	benchmarkRegions          = 2
	benchmarkShardsPerRegion  = 4
	benchmarkSegmentsPerShard = 2
	benchmarkSegmentLeaves    = 1 << 15
)

type syntheticForest struct {
	metadata hpp.HierarchyMetadata
	trees    map[hpp.TreeRef]treeData
	root     [32]byte
	service  *hpp.Service
}

type treeData struct {
	levels [][][32]byte
}

func newSyntheticForest() (*syntheticForest, error) {
	forest := &syntheticForest{
		metadata: hpp.HierarchyMetadata{
			Segments: make(map[hpp.SegmentKey]hpp.SegmentMetadata),
			Shards:   make(map[hpp.ShardKey]hpp.UpperTreeMetadata),
			Regions:  make(map[string]hpp.UpperTreeMetadata),
			Global:   hpp.UpperTreeMetadata{LeafCount: benchmarkRegions},
		},
		trees: make(map[hpp.TreeRef]treeData),
	}

	regionRoots := make([][32]byte, benchmarkRegions)
	for regionIndex := 0; regionIndex < benchmarkRegions; regionIndex++ {
		regionID := fmt.Sprintf("R%d", regionIndex)
		shardRoots := make([][32]byte, benchmarkShardsPerRegion)
		for shardIndex := 0; shardIndex < benchmarkShardsPerRegion; shardIndex++ {
			shardID := int64(shardIndex)
			segmentRoots := make([][32]byte, benchmarkSegmentsPerShard)
			for segmentIndex := 0; segmentIndex < benchmarkSegmentsPerShard; segmentIndex++ {
				segmentID := int64(segmentIndex)
				leaves := make([][32]byte, benchmarkSegmentLeaves)
				for leafIndex := range leaves {
					leaves[leafIndex] = syntheticLeafHash(regionIndex, shardIndex, segmentIndex, leafIndex)
				}
				data := buildTree(leaves)
				tree := segmentTree(regionID, shardID, segmentID)
				forest.trees[tree] = data
				forest.metadata.Segments[hpp.SegmentKey{
					RegionID: regionID, ShardID: shardID, SegmentID: segmentID,
				}] = hpp.SegmentMetadata{
					LeafCount: benchmarkSegmentLeaves, ShardLeafIndex: segmentID, Sealed: true,
				}
				segmentRoots[segmentIndex] = hmf.CommitSegmentRoot(
					regionID, shardID, segmentID, benchmarkSegmentLeaves, data.root(),
				)
			}
			shardData := buildTree(segmentRoots)
			forest.trees[shardTree(regionID, shardID)] = shardData
			forest.metadata.Shards[hpp.ShardKey{RegionID: regionID, ShardID: shardID}] =
				hpp.UpperTreeMetadata{LeafCount: benchmarkSegmentsPerShard, ParentLeafIndex: shardID}
			shardRoots[shardIndex] = hmf.CommitShardRoot(
				regionID, shardID, benchmarkSegmentsPerShard, shardData.root(),
			)
		}
		regionData := buildTree(shardRoots)
		forest.trees[regionTree(regionID)] = regionData
		forest.metadata.Regions[regionID] = hpp.UpperTreeMetadata{
			LeafCount: benchmarkShardsPerRegion, ParentLeafIndex: int64(regionIndex),
		}
		regionRoots[regionIndex] = hmf.CommitRegionRoot(
			regionID, benchmarkShardsPerRegion, regionData.root(),
		)
	}
	globalData := buildTree(regionRoots)
	forest.trees[globalTree()] = globalData
	forest.root = hmf.CommitGlobalRoot(benchmarkRegions, globalData.root())

	service, err := hpp.NewService(syntheticMetadataReader{metadata: forest.metadata},
		syntheticNodeReader{trees: forest.trees})
	if err != nil {
		return nil, err
	}
	forest.service = service
	return forest, nil
}

func (forest *syntheticForest) addresses(placement string, count int) ([]hpp.PhysicalAddress, error) {
	capacity := benchmarkSegmentLeaves
	if placement == "scattered" {
		capacity *= benchmarkRegions * benchmarkShardsPerRegion * benchmarkSegmentsPerShard
	}
	if count <= 0 || count > capacity {
		return nil, fmt.Errorf("batch size %d exceeds %s capacity %d", count, placement, capacity)
	}
	result := make([]hpp.PhysicalAddress, 0, count)
	for index := 0; index < count; index++ {
		ordinal := 0
		leafOrdinal := index
		switch placement {
		case "clustered":
		case "scattered":
			ordinal = index % (benchmarkRegions * benchmarkShardsPerRegion * benchmarkSegmentsPerShard)
			leafOrdinal = index / (benchmarkRegions * benchmarkShardsPerRegion * benchmarkSegmentsPerShard)
		default:
			return nil, fmt.Errorf("unknown placement %q", placement)
		}
		segmentsPerRegion := benchmarkShardsPerRegion * benchmarkSegmentsPerShard
		regionIndex := ordinal / segmentsPerRegion
		withinRegion := ordinal % segmentsPerRegion
		shardIndex := withinRegion / benchmarkSegmentsPerShard
		segmentIndex := withinRegion % benchmarkSegmentsPerShard
		leafIndex := (leafOrdinal * 31) % benchmarkSegmentLeaves
		result = append(result, hpp.PhysicalAddress{
			RegionID: fmt.Sprintf("R%d", regionIndex), ShardID: int64(shardIndex),
			SegmentID: int64(segmentIndex), LeafID: int64(leafIndex),
		})
	}
	return result, nil
}

func buildTree(leaves [][32]byte) treeData {
	levels := make([][][32]byte, 0, 16)
	current := append([][32]byte(nil), leaves...)
	levels = append(levels, current)
	for len(current) > 1 {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for index := 0; index < len(current); index += 2 {
			hash := current[index]
			if index+1 < len(current) {
				hash = domain.HashPair("NODE", &current[index], &current[index+1])
			}
			next = append(next, hash)
		}
		levels = append(levels, next)
		current = next
	}
	return treeData{levels: levels}
}

func (tree treeData) root() [32]byte {
	return tree.levels[len(tree.levels)-1][0]
}

func (tree treeData) node(position hpp.NodePosition) ([32]byte, error) {
	if position.Level < 0 || int(position.Level) >= len(tree.levels) ||
		position.Index < 0 || position.Index >= int64(len(tree.levels[position.Level])) {
		return [32]byte{}, fmt.Errorf("node position %+v is outside synthetic tree", position)
	}
	return tree.levels[position.Level][position.Index], nil
}

func syntheticLeafHash(region, shard, segment, leaf int) [32]byte {
	var input [40]byte
	copy(input[:8], []byte("HMF-BENCH"))
	binary.BigEndian.PutUint64(input[8:16], uint64(region))
	binary.BigEndian.PutUint64(input[16:24], uint64(shard))
	binary.BigEndian.PutUint64(input[24:32], uint64(segment))
	binary.BigEndian.PutUint64(input[32:40], uint64(leaf))
	return sha256.Sum256(input[:])
}

type syntheticMetadataReader struct {
	metadata hpp.HierarchyMetadata
}

func (reader syntheticMetadataReader) LoadHierarchyMetadata(context.Context,
	[]hpp.PhysicalAddress) (hpp.HierarchyMetadata, error) {
	return reader.metadata, nil
}

type syntheticNodeReader struct {
	trees map[hpp.TreeRef]treeData
}

func (reader syntheticNodeReader) FetchProofNodes(_ context.Context,
	plan hpp.ProofPlan) ([]hpp.ProofNode, error) {
	result := make([]hpp.ProofNode, 0)
	for _, treePlan := range plan.Trees {
		data, exists := reader.trees[treePlan.Tree]
		if !exists {
			return nil, fmt.Errorf("synthetic tree %+v is missing", treePlan.Tree)
		}
		for _, position := range treePlan.Required {
			hash, err := data.node(position)
			if err != nil {
				return nil, err
			}
			result = append(result, hpp.ProofNode{
				Ref: hpp.NodeRef{Tree: treePlan.Tree, Position: position}, Hash: hash,
			})
		}
	}
	for _, address := range plan.Addresses {
		tree := segmentTree(address.RegionID, address.ShardID, address.SegmentID)
		position := hpp.NodePosition{Level: 0, Index: address.LeafID}
		hash, err := reader.trees[tree].node(position)
		if err != nil {
			return nil, err
		}
		result = append(result, hpp.ProofNode{
			Ref: hpp.NodeRef{Tree: tree, Position: position}, Hash: hash,
		})
	}
	return result, nil
}

func segmentTree(regionID string, shardID, segmentID int64) hpp.TreeRef {
	return hpp.TreeRef{Layer: hpp.LayerSegment, RegionID: regionID,
		ShardID: shardID, SegmentID: segmentID}
}

func shardTree(regionID string, shardID int64) hpp.TreeRef {
	return hpp.TreeRef{Layer: hpp.LayerShard, RegionID: regionID, ShardID: shardID}
}

func regionTree(regionID string) hpp.TreeRef {
	return hpp.TreeRef{Layer: hpp.LayerRegion, RegionID: regionID}
}

func globalTree() hpp.TreeRef {
	return hpp.TreeRef{Layer: hpp.LayerGlobal}
}
