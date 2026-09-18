package hpp

import (
	"fmt"
	"sort"
)

const ShardNodesPerBucket int64 = 1 << 15

func normalizeAddresses(addresses []PhysicalAddress) ([]PhysicalAddress, error) {
	unique := make(map[PhysicalAddress]struct{}, len(addresses))
	for _, address := range addresses {
		if address.RegionID == "" {
			return nil, fmt.Errorf("HPP: region ID is required")
		}
		if address.ShardID < 0 || address.SegmentID < 0 || address.LeafID < 0 {
			return nil, fmt.Errorf("HPP: physical address IDs must be nonnegative: %+v", address)
		}
		unique[address] = struct{}{}
	}
	result := make([]PhysicalAddress, 0, len(unique))
	for address := range unique {
		result = append(result, address)
	}
	sort.Slice(result, func(left, right int) bool {
		return addressLess(result[left], result[right])
	})
	return result, nil
}

func addressLess(left, right PhysicalAddress) bool {
	if left.RegionID != right.RegionID {
		return left.RegionID < right.RegionID
	}
	if left.ShardID != right.ShardID {
		return left.ShardID < right.ShardID
	}
	if left.SegmentID != right.SegmentID {
		return left.SegmentID < right.SegmentID
	}
	return left.LeafID < right.LeafID
}

func segmentTree(key SegmentKey) TreeRef {
	return TreeRef{Layer: LayerSegment, RegionID: key.RegionID, ShardID: key.ShardID, SegmentID: key.SegmentID}
}

func shardTree(key ShardKey) TreeRef {
	return TreeRef{Layer: LayerShard, RegionID: key.RegionID, ShardID: key.ShardID}
}

func regionTree(regionID string) TreeRef {
	return TreeRef{Layer: LayerRegion, RegionID: regionID}
}

func globalTree() TreeRef {
	return TreeRef{Layer: LayerGlobal}
}

func treeRefLess(left, right TreeRef) bool {
	if left.Layer != right.Layer {
		return left.Layer < right.Layer
	}
	if left.RegionID != right.RegionID {
		return left.RegionID < right.RegionID
	}
	if left.ShardID != right.ShardID {
		return left.ShardID < right.ShardID
	}
	return left.SegmentID < right.SegmentID
}

func sortPositions(positions []NodePosition) {
	sort.Slice(positions, func(left, right int) bool {
		if positions[left].Level != positions[right].Level {
			return positions[left].Level < positions[right].Level
		}
		return positions[left].Index < positions[right].Index
	})
}

func shardBucketID(level int32, nodeIndex int64) int64 {
	if level < 15 {
		return nodeIndex >> (15 - level)
	}
	return nodeIndex << (level - 15)
}
