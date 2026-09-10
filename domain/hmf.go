package domain

import "time"

//5 Region Tree
//8 Shard Tree
// 10 Segment Tree

type HMF struct {
	Shards  [][]ShardTree
	Regions []RegionTree
	Global  GlobalTree
	epoch   time.Duration
}

func NewHMF(numRegions, numShards int) *HMF {
	forest := HMF{
		Shards:  make([][]ShardTree, numRegions),
		Regions: make([]RegionTree, numRegions),
		Global:  *NewGlobalTree(numRegions),
		epoch:   30 * time.Second,
	}

	for i := range forest.Shards {
		forest.Shards[i] = make([]ShardTree, numShards)
	}

	return &forest

}

func (forest *HMF) AppendSegmentRoot() {

}
