package main

import (
	"context"
	"fmt"
	"math/bits"
	"strconv"
	"time"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	cassandrastore "github.com/SirojWongpitakroj/hmf-audit/internal/storage/cassandra"
)

// fairLocatorTreeID identifies the single ALL tree seeded for the fair
// benchmark, matching the "ALL" tree ID the production checkpoint carries
// (all.LocatorTreeID).
const fairLocatorTreeID = locator.LocatorTreeID

const (
	fairLocatorTenantID              = "fair-benchmark"
	fairLocatorBackgroundServiceID   = "background"
	fairLocatorVerificationServiceID = "verification"
	fairLocatorLogicalRegionID       = "benchmark-logical"
	fairLocatorLogType               = "log"
	fairVerificationMaxCount         = 1 << 14

	fairLocatorOrder          = 128
	fairLocatorPagesPerBucket = 512
)

// fairEventTime gives each workload's logical rank a unique ALL time key.
func fairEventTime(ordinal int) time.Time {
	return time.Unix(int64(ordinal), 0).UTC()
}

// fairVerificationOrdinals assigns a logical prefix to distinct physical
// records. The first group spans two adjacent R0 segments; the second spreads
// across the R1..last physical suffix. Bit reversal makes every prefix of a power-of-
// two request size cover its physical window without repeating an address.
func fairVerificationOrdinals(layout *fairLayout, placement string, count int) ([]int, error) {
	if count <= 0 || count > fairVerificationMaxCount {
		return nil, fmt.Errorf("verification request count %d is outside 1..%d", count, fairVerificationMaxCount)
	}
	if len(layout.sizes) < 2 {
		return nil, fmt.Errorf("verification workloads need at least two regions")
	}
	clusterWindow := 2 * layout.segmentLeaves
	_, firstShardSize := layout.shard(0, 0)
	if clusterWindow > firstShardSize {
		return nil, fmt.Errorf("clustered-2 needs %d positions in the first shard, which has %d", clusterWindow, firstShardSize)
	}
	start, width := 0, clusterWindow
	switch placement {
	case "clustered-2":
	case "scattered":
		start = layout.starts[1]
		width = layout.total() - start
	default:
		return nil, fmt.Errorf("unknown verification placement %q", placement)
	}
	if count > width {
		return nil, fmt.Errorf("%s has %d positions, need %d", placement, width, count)
	}
	bitCount := bits.Len(uint(width - 1))
	result := make([]int, 0, count)
	for index := uint64(0); len(result) < count; index++ {
		offset := int(bits.Reverse64(index) >> (64 - bitCount))
		if offset < width {
			result = append(result, start+offset)
		}
	}
	return result, nil
}

// buildFairLocatorTree persists one locator entry per dataset record. The
// benchmark's two adjacent logical windows each contain q-max records in
// rank order under the same service and logical region. Only their physical
// locator values differ; all other records are background entries.
func buildFairLocatorTree(layout *fairLayout) (*locator.LocatorTree, error) {
	type assignment struct {
		rank int
	}
	selected := make(map[int]assignment, 2*fairVerificationMaxCount)
	for _, placement := range fairBenchmarkPlacements {
		logicalStart, err := fairLogicalStart(placement)
		if err != nil {
			return nil, err
		}
		ordinals, err := fairVerificationOrdinals(layout, placement, fairVerificationMaxCount)
		if err != nil {
			return nil, err
		}
		for rank, ordinal := range ordinals {
			if previous, exists := selected[ordinal]; exists {
				return nil, fmt.Errorf("physical ordinal %d has duplicate logical ranks %d and %d", ordinal, previous.rank, logicalStart+rank)
			}
			selected[ordinal] = assignment{rank: logicalStart + rank}
		}
	}
	tree := locator.NewLocatorTree(fairLocatorOrder)
	if fairSyntheticBulkLoad {
		// Setup only: bulk loading builds exactly the tree of one Insert per record (same pages and
		// root, see internal/all/locator_bulk_test.go) but hashes each page once, at the end.
		tree.BeginBulkLoad()
	}
	total := layout.total()
	for ordinal := 0; ordinal < total; ordinal++ {
		address := layout.address(ordinal)
		service, region, rank := fairLocatorBackgroundServiceID, address.RegionID, ordinal
		if selectedRecord, ok := selected[ordinal]; ok {
			service, region, rank = fairLocatorVerificationServiceID, fairLocatorLogicalRegionID, selectedRecord.rank
		}
		key := locator.LocatorKey{
			LogID:     fairHMFUUID(ordinal),
			EventTime: fairEventTime(rank),
			RegionID:  region,
			TenantID:  fairLocatorTenantID,
			ServiceID: service,
			LogType:   fairLocatorLogType,
		}
		value := &locator.LocatorValue{
			RegionID:  address.RegionID,
			ShardID:   fmt.Sprintf("%d", address.ShardID),
			SegmentID: fmt.Sprintf("%d", address.SegmentID),
			LeafID:    fmt.Sprintf("%d", address.LeafID),
		}
		tree.Insert(key, value, tree.RootPage)
	}
	if fairSyntheticBulkLoad {
		tree.FinishBulkLoad()
	}
	return tree, nil
}

// fairSyntheticBulkLoad turns the bulk-load shortcut of buildFairLocatorTree on (default) or off
// (the tests compare both).
var fairSyntheticBulkLoad = true

// persistFairLocatorTree streams the final pages in bounded batches and
// publishes the root only after every page has been stored.
func persistFairLocatorTree(ctx context.Context, writer *cassandrastore.ALLUpdateWriter,
	tree *locator.LocatorTree) error {

	return writer.PersistSnapshot(ctx, tree)
}

func fairLogicalStart(placement string) (int, error) {
	switch placement {
	case "clustered-2":
		return 0, nil
	case "scattered":
		return fairVerificationMaxCount, nil
	default:
		return 0, fmt.Errorf("unknown verification placement %q", placement)
	}
}

// fairLocatorQuery asks ALL for one contiguous logical prefix of a fixed-
// size window. Both cases use the same index dimensions and range width.
func fairLocatorQuery(placement string, count int) (locator.LocatorQuery, error) {
	if count <= 0 || count > fairVerificationMaxCount {
		return locator.LocatorQuery{}, fmt.Errorf("fair locator query: invalid count %d", count)
	}
	start, err := fairLogicalStart(placement)
	if err != nil {
		return locator.LocatorQuery{}, err
	}
	return locator.LocatorQuery{
		TenantID:  fairLocatorTenantID,
		ServiceID: fairLocatorVerificationServiceID,
		LogType:   fairLocatorLogType,
		RegionID:  fairLocatorLogicalRegionID,
		StartTime: fairEventTime(start),
		EndTime:   fairEventTime(start + count),
	}, nil
}

func fairPhysicalAddresses(layout *fairLayout, entries []locator.LocatorEntry) ([]hpp.PhysicalAddress, error) {
	addresses := make([]hpp.PhysicalAddress, 0, len(entries))
	seen := make(map[hpp.PhysicalAddress]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Value == nil {
			return nil, fmt.Errorf("ALL entry %v has no physical address", entry.Key.LogID)
		}
		shard, err := strconv.ParseInt(entry.Value.ShardID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("ALL shard %q: %w", entry.Value.ShardID, err)
		}
		segment, err := strconv.ParseInt(entry.Value.SegmentID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("ALL segment %q: %w", entry.Value.SegmentID, err)
		}
		leaf, err := strconv.ParseInt(entry.Value.LeafID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("ALL leaf %q: %w", entry.Value.LeafID, err)
		}
		address := hpp.PhysicalAddress{RegionID: entry.Value.RegionID, ShardID: shard, SegmentID: segment, LeafID: leaf}
		ordinal, valid := layout.ordinal(address)
		if !valid || entry.Key.LogID != fairHMFUUID(ordinal) || entry.Key.RegionID != fairLocatorLogicalRegionID {
			return nil, fmt.Errorf("ALL entry %v is not bound to physical address %+v", entry.Key.LogID, address)
		}
		if _, duplicate := seen[address]; duplicate {
			return nil, fmt.Errorf("ALL returned duplicate physical address %+v", address)
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	return addresses, nil
}
