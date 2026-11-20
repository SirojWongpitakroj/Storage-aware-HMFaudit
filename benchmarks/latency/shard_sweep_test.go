package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// Shard-count study, structural half. For each shard count S the same native queries are
// planned by the real HPP planner over the metadata of an S-shard layout of the same
// dataset, and the quantities that drive the request's cost are counted: how many shards,
// segments and Cassandra requests the proof needs, and how many nodes it fetches. No
// database is involved, so a sweep of many S takes seconds. It tells which S the real
// implementation (exp_shards.sh, which seeds and times each S) is worth measuring at; it
// does not replace that measurement.
//
//	FAIR_QUERY_DIR=systems/experiments/native-queries/<set> \
//	FAIR_SHARD_SWEEP=1,2,4,8,16,32 FAIR_SHARD_PLAN_OUT=plan.csv \
//	  go test ./benchmarks/latency -run TestFairHMFShardPlan -v
//
// FAIR_REGION0_RECORDS (default 2,500,000) is the size of each of the four regions.

// fairLayoutMetadata is the hierarchy metadata of a layout: leaf counts per segment, shard,
// region and the global tree. It is what newFairForest records, without building any tree.
func fairLayoutMetadata(layout *fairLayout) hpp.HierarchyMetadata {
	metadata := hpp.HierarchyMetadata{
		Segments: make(map[hpp.SegmentKey]hpp.SegmentMetadata),
		Shards:   make(map[hpp.ShardKey]hpp.UpperTreeMetadata),
		Regions:  make(map[string]hpp.UpperTreeMetadata),
		Global:   hpp.UpperTreeMetadata{LeafCount: int64(len(layout.sizes))},
	}
	for region := range layout.sizes {
		regionID := fmt.Sprintf("R%d", region)
		for shard := 0; shard < layout.shardsPerRegion; shard++ {
			_, shardSize := layout.shard(region, shard)
			segments := (shardSize + layout.segmentLeaves - 1) / layout.segmentLeaves
			for segment := 0; segment < segments; segment++ {
				count := min(layout.segmentLeaves, shardSize-segment*layout.segmentLeaves)
				metadata.Segments[hpp.SegmentKey{RegionID: regionID, ShardID: int64(shard), SegmentID: int64(segment)}] =
					hpp.SegmentMetadata{LeafCount: int64(count), ShardLeafIndex: int64(segment), Sealed: true}
			}
			metadata.Shards[hpp.ShardKey{RegionID: regionID, ShardID: int64(shard)}] =
				hpp.UpperTreeMetadata{LeafCount: int64(segments), ParentLeafIndex: int64(shard)}
		}
		metadata.Regions[regionID] = hpp.UpperTreeMetadata{
			LeafCount: int64(layout.shardsPerRegion), ParentLeafIndex: int64(region),
		}
	}
	return metadata
}

// fairShardPlanRow is the cost drivers of one query under one shard count.
type fairShardPlanRow struct {
	shards, segments                     int // shards and segments the q logs touch
	segmentRequests, upperRequests       int // Cassandra requests the plan issues
	segmentNodes, upperNodes, proofNodes int // nodes fetched per layer, and in the proof
}

func planFairShardQuery(layout *fairLayout, metadata hpp.HierarchyMetadata,
	query fairHMFNativeQuery) (fairShardPlanRow, error) {
	addresses := make([]hpp.PhysicalAddress, len(query.Ordinals))
	shards, segments := map[hpp.ShardKey]struct{}{}, map[hpp.SegmentKey]struct{}{}
	for index, ordinal := range query.Ordinals {
		address := layout.address(ordinal)
		addresses[index] = address
		shards[hpp.ShardKey{RegionID: address.RegionID, ShardID: address.ShardID}] = struct{}{}
		segments[hpp.SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}] = struct{}{}
	}
	plan, err := hpp.NewPlanner().Plan(addresses, metadata)
	if err != nil {
		return fairShardPlanRow{}, err
	}
	row := fairShardPlanRow{shards: len(shards), segments: len(segments),
		segmentRequests: len(plan.SegmentRequests), upperRequests: len(plan.UpperRequests)}
	for _, request := range plan.SegmentRequests {
		row.segmentNodes += len(request.NodeIndexes)
	}
	for _, request := range plan.UpperRequests {
		row.upperNodes += len(request.NodeIndexes)
	}
	for _, tree := range plan.Trees {
		row.proofNodes += len(tree.Required)
	}
	return row, nil
}

func parseFairShardSweep(t *testing.T, text string) []int {
	t.Helper()
	var counts []int
	for _, part := range strings.Split(text, ",") {
		count, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || count < 1 {
			t.Fatalf("FAIR_SHARD_SWEEP %q: shard counts must be positive integers", text)
		}
		counts = append(counts, count)
	}
	return counts
}

func TestFairHMFShardPlan(t *testing.T) {
	dir := fairNativeQueriesDir()
	if dir == "" {
		t.Skip("set FAIR_QUERY_DIR to a native query-set directory")
	}
	queries, err := fairHMFNativeQueries(dir)
	if err != nil {
		t.Fatal(err)
	}
	region := 2_500_000
	if text := os.Getenv("FAIR_REGION0_RECORDS"); text != "" {
		if region, err = strconv.Atoi(text); err != nil || region < 1 {
			t.Fatalf("FAIR_REGION0_RECORDS %q", text)
		}
	}
	counts := parseFairShardSweep(t, func() string {
		if text := os.Getenv("FAIR_SHARD_SWEEP"); text != "" {
			return text
		}
		return "1,2,4,8,16,32"
	}())
	var writer *csv.Writer
	if path := os.Getenv("FAIR_SHARD_PLAN_OUT"); path != "" {
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		writer = csv.NewWriter(file)
		defer writer.Flush()
		_ = writer.Write([]string{"shards_per_region", "shape", "q", "set", "shards_touched", "segments_touched",
			"segment_requests", "upper_requests", "segment_nodes", "upper_nodes", "proof_nodes"})
	}

	type cell struct {
		shards int
		shape  string
		q      int
	}
	sums := map[cell]*fairShardPlanRow{}
	samples := map[cell]int{}
	for _, shards := range counts {
		layout, err := newFairLayout([]int{region, region, region, region}, shards, 8192)
		if err != nil {
			t.Fatal(err)
		}
		metadata := fairLayoutMetadata(layout)
		for _, query := range queries {
			row, err := planFairShardQuery(layout, metadata, query)
			if err != nil {
				t.Fatalf("S=%d %s: %v", shards, query.name(), err)
			}
			if row.proofNodes == 0 || row.segments == 0 {
				t.Fatalf("S=%d %s: empty plan %+v", shards, query.name(), row)
			}
			key := cell{shards, query.Shape, query.Q}
			if sums[key] == nil {
				sums[key] = &fairShardPlanRow{}
			}
			total := sums[key]
			total.shards += row.shards
			total.segments += row.segments
			total.segmentRequests += row.segmentRequests
			total.upperRequests += row.upperRequests
			total.segmentNodes += row.segmentNodes
			total.upperNodes += row.upperNodes
			total.proofNodes += row.proofNodes
			samples[key]++
			if writer != nil {
				_ = writer.Write([]string{strconv.Itoa(shards), query.Shape, strconv.Itoa(query.Q), strconv.Itoa(query.Set),
					strconv.Itoa(row.shards), strconv.Itoa(row.segments), strconv.Itoa(row.segmentRequests),
					strconv.Itoa(row.upperRequests), strconv.Itoa(row.segmentNodes), strconv.Itoa(row.upperNodes),
					strconv.Itoa(row.proofNodes)})
			}
		}
	}

	var keys []cell
	for key := range sums {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.shape != b.shape {
			return a.shape < b.shape
		}
		if a.q != b.q {
			return a.q < b.q
		}
		return a.shards < b.shards
	})
	t.Logf("%-9s %6s %6s | %7s %8s %9s %9s %10s %9s %10s", "shape", "q", "S", "shards", "segments",
		"seg-reqs", "up-reqs", "seg-nodes", "up-nodes", "proof-nodes")
	for _, key := range keys {
		total, n := sums[key], float64(samples[key])
		t.Logf("%-9s %6d %6d | %7.1f %8.1f %9.1f %9.1f %10.1f %9.1f %10.1f", key.shape, key.q, key.shards,
			float64(total.shards)/n, float64(total.segments)/n, float64(total.segmentRequests)/n,
			float64(total.upperRequests)/n, float64(total.segmentNodes)/n, float64(total.upperNodes)/n,
			float64(total.proofNodes)/n)
	}
}

// The metadata derived from a layout must be the metadata of the forest built over it.
func TestFairLayoutMetadataMatchesForest(t *testing.T) {
	for _, shards := range []int{1, 3, 4} {
		layout, err := newFairLayout([]int{700, 700, 701}, shards, 64)
		if err != nil {
			t.Fatal(err)
		}
		forest, err := newFairForest(layout, make([][32]byte, layout.total()))
		if err != nil {
			t.Fatal(err)
		}
		got := fairLayoutMetadata(layout)
		want := forest.metadata
		if len(got.Segments) != len(want.Segments) || len(got.Shards) != len(want.Shards) ||
			len(got.Regions) != len(want.Regions) || got.Global != want.Global {
			t.Fatalf("S=%d: metadata sizes differ: %d/%d/%d vs %d/%d/%d", shards,
				len(got.Segments), len(got.Shards), len(got.Regions),
				len(want.Segments), len(want.Shards), len(want.Regions))
		}
		for key, value := range want.Segments {
			if got.Segments[key] != value {
				t.Fatalf("S=%d segment %+v: %+v, want %+v", shards, key, got.Segments[key], value)
			}
		}
		for key, value := range want.Shards {
			if got.Shards[key] != value {
				t.Fatalf("S=%d shard %+v: %+v, want %+v", shards, key, got.Shards[key], value)
			}
		}
		for key, value := range want.Regions {
			if got.Regions[key] != value {
				t.Fatalf("S=%d region %s: %+v, want %+v", shards, key, got.Regions[key], value)
			}
		}
	}
}
