package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

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

type forestShape struct {
	regions          int
	shardsPerRegion  int
	segmentsPerShard int
	segmentLeaves    int
}

var defaultBenchmarkShape = forestShape{
	regions: benchmarkRegions, shardsPerRegion: benchmarkShardsPerRegion,
	segmentsPerShard: benchmarkSegmentsPerShard, segmentLeaves: benchmarkSegmentLeaves,
}

var fairBenchmarkPlacements = []string{"clustered-2", "scattered"}

func fairClusteredSegmentCount(placement string) (int, bool) {
	switch placement {
	case "clustered-2":
		return 2, true
	case "clustered-3":
		return 3, true
	case "clustered-4":
		return 4, true
	default:
		return 0, false
	}
}

type syntheticForest struct {
	metadata hpp.HierarchyMetadata
	trees    map[hpp.TreeRef]treeData
	root     [32]byte
	service  *hpp.Service
	shape    forestShape
	// layout is set for the fair benchmark, whose regions differ in size.
	layout *fairLayout
}

// fairLayout places a region-grouped dataset into HMF. Region r owns the
// ordinals [starts[r], starts[r]+sizes[r]), split into shardsPerRegion
// contiguous shards of near-equal size (the first size%shards shards hold one
// extra record). Each shard's sealed segments hold segmentLeaves leaves,
// except a shorter final segment.
type fairLayout struct {
	starts          []int
	sizes           []int
	shardsPerRegion int
	segmentLeaves   int
}

func newFairLayout(regionSizes []int, shardsPerRegion, segmentLeaves int) (*fairLayout, error) {
	if len(regionSizes) == 0 || shardsPerRegion <= 0 || segmentLeaves <= 0 {
		return nil, fmt.Errorf("fair layout needs regions, a positive shard count, and a positive segment size")
	}
	layout := &fairLayout{
		sizes: append([]int(nil), regionSizes...), shardsPerRegion: shardsPerRegion, segmentLeaves: segmentLeaves,
	}
	next := 0
	for region, size := range regionSizes {
		if size < shardsPerRegion {
			return nil, fmt.Errorf("region R%d has %d records, fewer than %d shards", region, size, shardsPerRegion)
		}
		layout.starts = append(layout.starts, next)
		next += size
	}
	return layout, nil
}

// shard returns the region-relative offset and size of shard s of region r.
func (layout *fairLayout) shard(region, shard int) (offset, size int) {
	base, extra := layout.sizes[region]/layout.shardsPerRegion, layout.sizes[region]%layout.shardsPerRegion
	return shard*base + min(shard, extra), base + boolToInt(shard < extra)
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (layout *fairLayout) total() int {
	return layout.starts[len(layout.starts)-1] + layout.sizes[len(layout.sizes)-1]
}

func (layout *fairLayout) address(ordinal int) hpp.PhysicalAddress {
	region := sort.Search(len(layout.starts), func(index int) bool {
		return layout.starts[index] > ordinal
	}) - 1
	offset := ordinal - layout.starts[region]
	shard := sort.Search(layout.shardsPerRegion, func(index int) bool {
		start, _ := layout.shard(region, index)
		return start > offset
	}) - 1
	start, _ := layout.shard(region, shard)
	offset -= start
	return hpp.PhysicalAddress{
		RegionID: fmt.Sprintf("R%d", region), ShardID: int64(shard),
		SegmentID: int64(offset / layout.segmentLeaves), LeafID: int64(offset % layout.segmentLeaves),
	}
}

// ordinal inverts address: it is the dataset ordinal stored at a physical
// address, or false when the address lies outside the layout.
func (layout *fairLayout) ordinal(address hpp.PhysicalAddress) (int, bool) {
	region, err := strconv.Atoi(strings.TrimPrefix(address.RegionID, "R"))
	if err != nil || !strings.HasPrefix(address.RegionID, "R") ||
		region < 0 || region >= len(layout.sizes) {
		return 0, false
	}
	shard := int(address.ShardID)
	if shard < 0 || shard >= layout.shardsPerRegion {
		return 0, false
	}
	if address.LeafID < 0 || address.LeafID >= int64(layout.segmentLeaves) || address.SegmentID < 0 {
		return 0, false
	}
	start, size := layout.shard(region, shard)
	offset := int(address.SegmentID)*layout.segmentLeaves + int(address.LeafID)
	if offset >= size {
		return 0, false
	}
	return layout.starts[region] + start + offset, true
}

// newFairForest builds the anchored HMF forest for a region-grouped dataset
// laid out by layout; leafHashes[ordinal] is the leaf of that dataset record.
func newFairForest(layout *fairLayout, leafHashes [][32]byte) (*syntheticForest, error) {
	if len(leafHashes) != layout.total() {
		return nil, fmt.Errorf("got %d leaf hashes, want %d", len(leafHashes), layout.total())
	}
	regions := len(layout.sizes)
	forest := &syntheticForest{
		metadata: hpp.HierarchyMetadata{
			Segments: make(map[hpp.SegmentKey]hpp.SegmentMetadata),
			Shards:   make(map[hpp.ShardKey]hpp.UpperTreeMetadata),
			Regions:  make(map[string]hpp.UpperTreeMetadata),
			Global:   hpp.UpperTreeMetadata{LeafCount: int64(regions)},
		},
		trees:  make(map[hpp.TreeRef]treeData),
		layout: layout,
	}
	regionRoots := make([][32]byte, regions)
	shards := layout.shardsPerRegion
	for regionIndex := range regions {
		regionID := fmt.Sprintf("R%d", regionIndex)
		shardRoots := make([][32]byte, shards)
		for shardIndex := range shards {
			shardID := int64(shardIndex)
			shardOffset, shardSize := layout.shard(regionIndex, shardIndex)
			shardStart := layout.starts[regionIndex] + shardOffset
			segments := (shardSize + layout.segmentLeaves - 1) / layout.segmentLeaves
			segmentRoots := make([][32]byte, segments)
			for segmentIndex := range segments {
				first := shardStart + segmentIndex*layout.segmentLeaves
				last := min(first+layout.segmentLeaves, shardStart+shardSize)
				segmentID := int64(segmentIndex)
				data := buildTree(leafHashes[first:last])
				forest.trees[segmentTree(regionID, shardID, segmentID)] = data
				forest.metadata.Segments[hpp.SegmentKey{RegionID: regionID, ShardID: shardID, SegmentID: segmentID}] =
					hpp.SegmentMetadata{LeafCount: int64(last - first), ShardLeafIndex: segmentID, Sealed: true}
				segmentRoots[segmentIndex] = hmf.CommitSegmentRoot(
					regionID, shardID, segmentID, int64(last-first), data.root(),
				)
			}
			shardData := buildTree(segmentRoots)
			forest.trees[shardTree(regionID, shardID)] = shardData
			forest.metadata.Shards[hpp.ShardKey{RegionID: regionID, ShardID: shardID}] =
				hpp.UpperTreeMetadata{LeafCount: int64(segments), ParentLeafIndex: shardID}
			shardRoots[shardIndex] = hmf.CommitShardRoot(regionID, shardID, int64(segments), shardData.root())
		}
		regionData := buildTree(shardRoots)
		forest.trees[regionTree(regionID)] = regionData
		forest.metadata.Regions[regionID] = hpp.UpperTreeMetadata{
			LeafCount: int64(shards), ParentLeafIndex: int64(regionIndex),
		}
		regionRoots[regionIndex] = hmf.CommitRegionRoot(regionID, int64(shards), regionData.root())
	}
	globalData := buildTree(regionRoots)
	forest.trees[globalTree()] = globalData
	forest.root = hmf.CommitGlobalRoot(int64(regions), globalData.root())

	service, err := hpp.NewService(syntheticMetadataReader{metadata: forest.metadata},
		syntheticNodeReader{trees: forest.trees})
	if err != nil {
		return nil, err
	}
	forest.service = service
	return forest, nil
}

type treeData struct {
	levels [][][32]byte
}

func newSyntheticForest() (*syntheticForest, error) {
	return newSyntheticForestWithShape(defaultBenchmarkShape)
}

func newSyntheticForestWithShape(shape forestShape) (*syntheticForest, error) {
	return newSyntheticForestWithLeaves(shape, nil)
}

func newSyntheticForestWithLeaves(shape forestShape, leafHashes [][32]byte) (*syntheticForest, error) {
	if shape.regions <= 0 || shape.shardsPerRegion <= 0 ||
		shape.segmentsPerShard <= 0 || shape.segmentLeaves <= 0 {
		return nil, fmt.Errorf("all forest dimensions must be positive")
	}
	expectedLeaves := shape.regions * shape.shardsPerRegion * shape.segmentsPerShard * shape.segmentLeaves
	if leafHashes != nil && len(leafHashes) != expectedLeaves {
		return nil, fmt.Errorf("got %d leaf hashes, want %d", len(leafHashes), expectedLeaves)
	}
	forest := &syntheticForest{
		metadata: hpp.HierarchyMetadata{
			Segments: make(map[hpp.SegmentKey]hpp.SegmentMetadata),
			Shards:   make(map[hpp.ShardKey]hpp.UpperTreeMetadata),
			Regions:  make(map[string]hpp.UpperTreeMetadata),
			Global:   hpp.UpperTreeMetadata{LeafCount: int64(shape.regions)},
		},
		trees: make(map[hpp.TreeRef]treeData),
		shape: shape,
	}

	regionRoots := make([][32]byte, shape.regions)
	for regionIndex := 0; regionIndex < shape.regions; regionIndex++ {
		regionID := fmt.Sprintf("R%d", regionIndex)
		shardRoots := make([][32]byte, shape.shardsPerRegion)
		for shardIndex := 0; shardIndex < shape.shardsPerRegion; shardIndex++ {
			shardID := int64(shardIndex)
			segmentRoots := make([][32]byte, shape.segmentsPerShard)
			for segmentIndex := 0; segmentIndex < shape.segmentsPerShard; segmentIndex++ {
				segmentID := int64(segmentIndex)
				leaves := make([][32]byte, shape.segmentLeaves)
				for leafIndex := range leaves {
					if leafHashes == nil {
						leaves[leafIndex] = syntheticLeafHash(regionIndex, shardIndex, segmentIndex, leafIndex)
					} else {
						ordinal := (((regionIndex*shape.shardsPerRegion)+shardIndex)*shape.segmentsPerShard+segmentIndex)*shape.segmentLeaves + leafIndex
						leaves[leafIndex] = leafHashes[ordinal]
					}
				}
				data := buildTree(leaves)
				tree := segmentTree(regionID, shardID, segmentID)
				forest.trees[tree] = data
				forest.metadata.Segments[hpp.SegmentKey{
					RegionID: regionID, ShardID: shardID, SegmentID: segmentID,
				}] = hpp.SegmentMetadata{
					LeafCount: int64(shape.segmentLeaves), ShardLeafIndex: segmentID, Sealed: true,
				}
				segmentRoots[segmentIndex] = hmf.CommitSegmentRoot(
					regionID, shardID, segmentID, int64(shape.segmentLeaves), data.root(),
				)
			}
			shardData := buildTree(segmentRoots)
			forest.trees[shardTree(regionID, shardID)] = shardData
			forest.metadata.Shards[hpp.ShardKey{RegionID: regionID, ShardID: shardID}] =
				hpp.UpperTreeMetadata{LeafCount: int64(shape.segmentsPerShard), ParentLeafIndex: shardID}
			shardRoots[shardIndex] = hmf.CommitShardRoot(
				regionID, shardID, int64(shape.segmentsPerShard), shardData.root(),
			)
		}
		regionData := buildTree(shardRoots)
		forest.trees[regionTree(regionID)] = regionData
		forest.metadata.Regions[regionID] = hpp.UpperTreeMetadata{
			LeafCount: int64(shape.shardsPerRegion), ParentLeafIndex: int64(regionIndex),
		}
		regionRoots[regionIndex] = hmf.CommitRegionRoot(
			regionID, int64(shape.shardsPerRegion), regionData.root(),
		)
	}
	globalData := buildTree(regionRoots)
	forest.trees[globalTree()] = globalData
	forest.root = hmf.CommitGlobalRoot(int64(shape.regions), globalData.root())

	service, err := hpp.NewService(syntheticMetadataReader{metadata: forest.metadata},
		syntheticNodeReader{trees: forest.trees})
	if err != nil {
		return nil, err
	}
	forest.service = service
	return forest, nil
}

func (forest *syntheticForest) addresses(placement string, count int) ([]hpp.PhysicalAddress, error) {
	if forest.layout != nil {
		return forest.layout.addresses(placement, count)
	}
	totalSegments := forest.shape.regions * forest.shape.shardsPerRegion * forest.shape.segmentsPerShard
	capacity := forest.shape.segmentLeaves
	if placement == "scattered" {
		capacity *= totalSegments
	}
	if count <= 0 || count > capacity {
		return nil, fmt.Errorf("batch size %d exceeds %s capacity %d", count, placement, capacity)
	}
	result := make([]hpp.PhysicalAddress, 0, count)
	for index := 0; index < count; index++ {
		globalOrdinal := index
		switch placement {
		case "clustered":
		case "scattered":
			if count > 1 {
				globalOrdinal = index * (capacity - 1) / (count - 1)
			}
		default:
			return nil, fmt.Errorf("unknown placement %q", placement)
		}
		ordinal := globalOrdinal / forest.shape.segmentLeaves
		leafIndex := globalOrdinal % forest.shape.segmentLeaves
		segmentsPerRegion := forest.shape.shardsPerRegion * forest.shape.segmentsPerShard
		regionIndex := ordinal / segmentsPerRegion
		withinRegion := ordinal % segmentsPerRegion
		shardIndex := withinRegion / forest.shape.segmentsPerShard
		segmentIndex := withinRegion % forest.shape.segmentsPerShard
		result = append(result, hpp.PhysicalAddress{
			RegionID: fmt.Sprintf("R%d", regionIndex), ShardID: int64(shardIndex),
			SegmentID: int64(segmentIndex), LeafID: int64(leafIndex),
		})
	}
	return result, nil
}

// addresses applies the shared ordinal rules over the whole dataset. For
// count >= 16, clustered-k spreads the requested ordinals across exactly k
// complete adjacent segments in the first shard. A singleton always selects
// ordinal zero. Scattered spans the complete dataset.
func (layout *fairLayout) addresses(placement string, count int) ([]hpp.PhysicalAddress, error) {
	total := layout.total()
	if count <= 0 || count > total {
		return nil, fmt.Errorf("batch size %d exceeds dataset size %d", count, total)
	}
	clusteredSegments, isClustered := fairClusteredSegmentCount(placement)
	clusteredWindow := 0
	if isClustered && count > 1 {
		if count < 16 {
			return nil, fmt.Errorf("%s requires q=1 or q>=16, got %d", placement, count)
		}
		clusteredWindow = clusteredSegments * layout.segmentLeaves
		_, firstShardSize := layout.shard(0, 0)
		if clusteredWindow > firstShardSize {
			return nil, fmt.Errorf("%s needs %d records in the first shard, which has %d",
				placement, clusteredWindow, firstShardSize)
		}
		if count > clusteredWindow {
			return nil, fmt.Errorf("%s cannot select %d unique records from its %d-record window",
				placement, count, clusteredWindow)
		}
	}
	result := make([]hpp.PhysicalAddress, 0, count)
	for index := range count {
		ordinal := index
		switch placement {
		case "clustered":
		case "clustered-2", "clustered-3", "clustered-4":
			if count > 1 {
				ordinal = index * (clusteredWindow - 1) / (count - 1)
			}
		case "scattered":
			if count > 1 {
				ordinal = index * (total - 1) / (count - 1)
			}
		default:
			return nil, fmt.Errorf("unknown placement %q", placement)
		}
		result = append(result, layout.address(ordinal))
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
