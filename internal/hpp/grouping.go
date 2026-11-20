package hpp

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

const ShardNodesPerBucket int64 = 1 << 15

// normalizeAddresses validates, sorts and de-duplicates the addresses (canonical order: region,
// shard, segment, leaf). It copies the input once and sorts that copy, with no per-address map.
func normalizeAddresses(addresses []PhysicalAddress) ([]PhysicalAddress, error) {
	result := make([]PhysicalAddress, len(addresses))
	for index, address := range addresses {
		if address.RegionID == "" {
			return nil, fmt.Errorf("HPP: region ID is required")
		}
		if address.ShardID < 0 || address.SegmentID < 0 || address.LeafID < 0 {
			return nil, fmt.Errorf("HPP: physical address IDs must be nonnegative: %+v", address)
		}
		result[index] = address
	}
	if !slices.IsSortedFunc(result, compareAddresses) {
		slices.SortFunc(result, compareAddresses)
	}
	return slices.CompactFunc(result, func(left, right PhysicalAddress) bool { return left == right }), nil
}

func compareAddresses(left, right PhysicalAddress) int {
	if left.RegionID != right.RegionID {
		return strings.Compare(left.RegionID, right.RegionID)
	}
	if left.ShardID != right.ShardID {
		return cmp.Compare(left.ShardID, right.ShardID)
	}
	if left.SegmentID != right.SegmentID {
		return cmp.Compare(left.SegmentID, right.SegmentID)
	}
	return cmp.Compare(left.LeafID, right.LeafID)
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

func shardBucketID(level int32, nodeIndex int64) int64 {
	if level < 15 {
		return nodeIndex >> (15 - level)
	}
	return nodeIndex << (level - 15)
}
