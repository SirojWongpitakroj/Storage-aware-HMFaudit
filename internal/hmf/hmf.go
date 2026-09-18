package hmf

import (
	"fmt"
	"time"
)

type HMFConfig struct {
	RegionIDs          []string
	NumShardsPerRegion int
	MaxSegmentLeaves   int
}

// HMFUpdate contains every hierarchy node changed when a segment is sealed.
type HMFUpdate struct {
	SegmentTreeID    TreeID
	SegmentNodes     []MerkleNode
	SegmentRoot      [32]byte
	SegmentLeaves    int64
	SegmentHeight    int
	ShardLeafIndex   int64
	SegmentMaxLeaves int
	SegmentMaxAge    time.Duration
	SegmentCreatedAt time.Time
	SegmentStartedAt time.Time
	SegmentEndedAt   time.Time
	SegmentSealedAt  time.Time

	ShardTreeID    TreeID
	ShardNodes     []MerkleNode
	ShardRoot      [32]byte
	ShardLeaves    int64
	ShardHeight    int
	ShardFrontiers []MerkleNode

	RegionTreeID          TreeID
	RegionNodes           []MerkleNode
	RegionRoot            [32]byte
	RegionLeaves          int64
	RegionHeight          int
	RegionParentLeafIndex int64

	GlobalTreeID          TreeID
	GlobalNodes           []MerkleNode
	GlobalRoot            [32]byte
	GlobalLeaves          int64
	GlobalHeight          int
	GlobalParentLeafIndex int64
}

// HMF coordinates the in-memory trees that make up one hierarchy.
// Placement and persistence are owned by hm and storage packages.
type HMF struct {
	GlobalTree  *GlobalTree
	RegionTrees map[string]*RegionTree
	ShardTrees  map[TreeID]*ShardTree

	regionIndexes map[string]int
	shardIndexes  map[TreeID]int
}

func NewHMF(config HMFConfig) (*HMF, error) {
	if len(config.RegionIDs) == 0 {
		return nil, fmt.Errorf("new HMF: must have at least one region")
	}
	if config.MaxSegmentLeaves <= 0 {
		return nil, fmt.Errorf("new HMF: max segment leaves must be positive")
	}
	if config.NumShardsPerRegion <= 0 {
		return nil, fmt.Errorf("new HMF: number of shards per region must be positive")
	}

	forest := &HMF{
		GlobalTree:    NewGlobalTree(len(config.RegionIDs)),
		RegionTrees:   make(map[string]*RegionTree, len(config.RegionIDs)),
		ShardTrees:    make(map[TreeID]*ShardTree),                 //TreeID = {RegionID, ShardID}
		regionIndexes: make(map[string]int, len(config.RegionIDs)), //point to global-leaf pos
		shardIndexes:  make(map[TreeID]int),                        //point to region-leaf pos
	}

	//create regionTree for each regionsID
	for regionIndex, rid := range config.RegionIDs {
		if rid == "" {
			return nil, fmt.Errorf("new HMF: region ID cannot be empty")
		}
		if _, exists := forest.RegionTrees[rid]; exists {
			return nil, fmt.Errorf("new HMF: duplicate region ID %s", rid)
		}

		//create shard trees for each region tree
		forest.RegionTrees[rid] = NewRegionTree(rid, config.NumShardsPerRegion)
		forest.regionIndexes[rid] = regionIndex
		for shardIndex := 0; shardIndex < config.NumShardsPerRegion; shardIndex++ {
			shardID := int64(shardIndex)
			treeID := TreeID{
				Type:     TreeShard,
				RegionID: rid,
				ShardID:  shardID,
			}
			if _, exists := forest.ShardTrees[treeID]; exists {
				return nil, fmt.Errorf("new HMF: duplicate shard ID %d in region %s", shardID, rid)
			}
			forest.ShardTrees[treeID] = NewShardTree(rid, shardID)
			forest.shardIndexes[treeID] = shardIndex
		}
	}
	for _, regionID := range config.RegionIDs {
		shardRoots := make([][32]byte, config.NumShardsPerRegion)
		for shardIndex := range config.NumShardsPerRegion {
			shardRoots[shardIndex] = CommitShardRoot(regionID, int64(shardIndex), 0, [32]byte{})
		}
		if _, err := forest.RegionTrees[regionID].Build(shardRoots); err != nil {
			return nil, fmt.Errorf("new HMF: build initial region tree %s: %w", regionID, err)
		}
	}
	regionRoots := make([][32]byte, len(config.RegionIDs))
	for regionIndex, regionID := range config.RegionIDs {
		region := forest.RegionTrees[regionID]
		regionRoots[regionIndex] = CommitRegionRoot(regionID, region.LeafCount, region.Root)
	}
	if _, err := forest.GlobalTree.Build(regionRoots); err != nil {
		return nil, fmt.Errorf("new HMF: build initial global tree: %w", err)
	}

	return forest, nil
}

func (forest *HMF) Root() [32]byte {
	return CommitGlobalRoot(forest.GlobalTree.LeafCount, forest.GlobalTree.Root)
}

// AppendSealedSegment adds a sealed Segment root to its Shard and propagates
// the resulting root through the Region and Global trees.
func (forest *HMF) AppendSealedSegment(regionID string, shardID, segmentID,
	segmentLeafCount int64, segmentRoot [32]byte) (HMFUpdate, error) {
	if segmentID < 0 || segmentLeafCount <= 0 {
		return HMFUpdate{}, fmt.Errorf("append sealed segment: invalid segment ID or leaf count")
	}
	shardTreeID := TreeID{
		Type:     TreeShard,
		RegionID: regionID,
		ShardID:  shardID,
	}
	shardTree, exists := forest.ShardTrees[shardTreeID]
	if !exists {
		return HMFUpdate{}, fmt.Errorf("append sealed segment: shard %d does not exist in region %s", shardID, regionID)
	}

	shardLeafIndex := shardTree.LeafCount
	segmentCommitment := CommitSegmentRoot(regionID, shardID, segmentID, segmentLeafCount, segmentRoot)
	shardNodes, err := shardTree.Append(segmentCommitment)
	if err != nil {
		return HMFUpdate{}, err
	}

	regionTree, exists := forest.RegionTrees[regionID]
	if !exists {
		return HMFUpdate{}, fmt.Errorf("append sealed segment: region %s does not exist", regionID)
	}
	shardIndex := forest.shardIndexes[shardTreeID]
	shardCommitment := CommitShardRoot(regionID, shardID, shardTree.LeafCount, shardTree.Root)
	regionNodes, err := regionTree.updateShardRoot(shardIndex, shardCommitment)
	if err != nil {
		return HMFUpdate{}, err
	}

	regionIndex := forest.regionIndexes[regionID]
	regionCommitment := CommitRegionRoot(regionID, regionTree.LeafCount, regionTree.Root)
	globalNodes, err := forest.GlobalTree.UpdateRegionRoot(regionIndex, regionCommitment)
	if err != nil {
		return HMFUpdate{}, err
	}

	return HMFUpdate{
		ShardTreeID:           shardTreeID,
		ShardNodes:            shardNodes,
		ShardRoot:             shardCommitment,
		ShardLeaves:           shardTree.LeafCount,
		ShardHeight:           shardTree.Height,
		ShardFrontiers:        shardTree.Frontiers(),
		ShardLeafIndex:        shardLeafIndex,
		RegionTreeID:          regionTree.TreeID,
		RegionNodes:           regionNodes,
		RegionRoot:            regionCommitment,
		RegionLeaves:          regionTree.LeafCount,
		RegionHeight:          regionTree.Height,
		RegionParentLeafIndex: int64(shardIndex),
		GlobalTreeID:          forest.GlobalTree.TreeID,
		GlobalNodes:           globalNodes,
		GlobalRoot:            forest.Root(),
		GlobalLeaves:          forest.GlobalTree.LeafCount,
		GlobalHeight:          forest.GlobalTree.Height,
		GlobalParentLeafIndex: int64(regionIndex),
	}, nil
}
