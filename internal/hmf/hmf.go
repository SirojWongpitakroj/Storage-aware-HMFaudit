package hmf

import (
	"fmt"
)

type HMFConfig struct {
	RegionIDs          []string
	NumShardsPerRegion int
	MaxSegmentLeaves   int
}

// HMFUpdate contains every hierarchy node changed when a segment is sealed.
type HMFUpdate struct {
	SegmentTreeID TreeID
	SegmentNodes  []MerkleNode

	ShardTreeID TreeID
	ShardNodes  []MerkleNode

	RegionTreeID TreeID
	RegionNodes  []MerkleNode

	GlobalTreeID TreeID
	GlobalNodes  []MerkleNode
	GlobalRoot   [32]byte
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

	return forest, nil
}

func (forest *HMF) Root() [32]byte {
	return forest.GlobalTree.Root
}
