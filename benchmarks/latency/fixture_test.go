package main

import (
	"context"
	"errors"
	"testing"
	"time"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

func TestFairSeedWriteRetriesTransientTimeout(t *testing.T) {
	attempts := 0
	err := fairRetrySeedWrite(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return gocql.ErrTimeoutNoResponse
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("retry result = %v after %d attempts, want success after 3", err, attempts)
	}
}

func TestFairSeedWriteDoesNotRetryPermanentError(t *testing.T) {
	attempts := 0
	err := fairRetrySeedWrite(context.Background(), func() error {
		attempts++
		return errors.New("permanent")
	})
	if err == nil || attempts != 1 {
		t.Fatalf("permanent error = %v after %d attempts, want one failure", err, attempts)
	}
}

func TestSyntheticBenchmarkScenarioIsValid(t *testing.T) {
	forest, err := newSyntheticForest()
	if err != nil {
		t.Fatalf("build synthetic forest: %v", err)
	}
	scenario, err := prepareScenario(context.Background(), forest, "scattered", 16)
	if err != nil {
		t.Fatalf("prepare scenario: %v", err)
	}
	if len(scenario.localization.Proof.Suspects) != 1 ||
		scenario.localization.Proof.Suspects[0].Classification != localization.LeafMismatch {
		t.Fatalf("localization suspects = %+v, want one leaf mismatch",
			scenario.localization.Proof.Suspects)
	}
	if err := localization.VerifyProof(scenario.localization.Proof,
		scenario.addresses, scenario.trustedRoot); err != nil {
		t.Fatalf("verify localization proof: %v", err)
	}
}

func TestFairBenchmarkPlacementMapping(t *testing.T) {
	layout, err := newFairLayout([]int{4096, 4096, 4096, 4096, 4096, 4096, 4096, 4096}, 1, 4096)
	if err != nil {
		t.Fatal(err)
	}
	forest := &syntheticForest{layout: layout}
	clustered, err := forest.addresses("clustered", 3)
	if err != nil {
		t.Fatal(err)
	}
	for index, address := range clustered {
		if address.RegionID != "R0" || address.LeafID != int64(index) {
			t.Fatalf("clustered[%d] = %+v", index, address)
		}
	}

	// Scattered stays inside region 0, like clustered: ALL only ever resolves
	// one contiguous time window within one exact region, so a placement that
	// jumped across regions would have no single real ALL query behind it.
	scattered, err := forest.addresses("scattered", 3)
	if err != nil {
		t.Fatal(err)
	}
	if scattered[0].RegionID != "R0" || scattered[0].LeafID != 0 ||
		scattered[1].RegionID != "R0" || scattered[1].LeafID != 2047 ||
		scattered[2].RegionID != "R0" || scattered[2].LeafID != 4095 {
		t.Fatalf("scattered addresses = %+v", scattered)
	}
}

func TestFairClusteredVariantsSpanExactAdjacentSegments(t *testing.T) {
	for _, segmentLeaves := range []int{512, 4096, 32768} {
		layout, err := newFairLayout([]int{5 * segmentLeaves}, 1, segmentLeaves)
		if err != nil {
			t.Fatal(err)
		}
		forest := &syntheticForest{layout: layout}
		for _, test := range []struct {
			placement string
			segments  int
		}{
			{"clustered-2", 2},
			{"clustered-3", 3},
			{"clustered-4", 4},
		} {
			for _, count := range []int{16, 64, 256, 1024} {
				addresses, err := forest.addresses(test.placement, count)
				if err != nil {
					t.Fatal(err)
				}
				seenSegments := make(map[int64]bool)
				seenLeaves := make(map[hpp.PhysicalAddress]bool)
				for _, address := range addresses {
					if address.RegionID != "R0" || address.ShardID != 0 {
						t.Fatalf("%s left the first shard: %+v", test.placement, address)
					}
					seenSegments[address.SegmentID] = true
					seenLeaves[address] = true
				}
				if len(seenLeaves) != count {
					t.Fatalf("%s q=%d selected %d unique records", test.placement, count, len(seenLeaves))
				}
				if len(seenSegments) != test.segments {
					t.Fatalf("%s q=%d touched segments %v, want exactly %d",
						test.placement, count, seenSegments, test.segments)
				}
				for segment := range test.segments {
					if !seenSegments[int64(segment)] {
						t.Fatalf("%s did not touch adjacent segment %d: %v",
							test.placement, segment, seenSegments)
					}
				}
			}
			single, err := forest.addresses(test.placement, 1)
			if err != nil {
				t.Fatal(err)
			}
			if len(single) != 1 || single[0] != layout.address(0) {
				t.Fatalf("%s q=1 = %+v, want ordinal zero", test.placement, single)
			}
		}
	}
}

func TestFairLayoutSplitsUnevenRegionsIntoSegments(t *testing.T) {
	layout, err := newFairLayout([]int{10, 3}, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]hpp.PhysicalAddress{
		0:  {RegionID: "R0", SegmentID: 0, LeafID: 0},
		5:  {RegionID: "R0", SegmentID: 1, LeafID: 1},
		9:  {RegionID: "R0", SegmentID: 2, LeafID: 1},
		10: {RegionID: "R1", SegmentID: 0, LeafID: 0},
		12: {RegionID: "R1", SegmentID: 0, LeafID: 2},
	}
	for ordinal, address := range want {
		if got := layout.address(ordinal); got != address {
			t.Fatalf("address(%d) = %+v, want %+v", ordinal, got, address)
		}
	}
	leaves := make([][32]byte, layout.total())
	for index := range leaves {
		leaves[index] = syntheticLeafHash(0, 0, 0, index)
	}
	forest, err := newFairForest(layout, leaves)
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := forest.addresses("scattered", 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forest.service.BuildAndVerify(context.Background(), addresses, forest.root); err != nil {
		t.Fatalf("verify proof over uneven segments: %v", err)
	}
	if segment := forest.metadata.Segments[hpp.SegmentKey{RegionID: "R0", SegmentID: 2}]; segment.LeafCount != 2 {
		t.Fatalf("final R0 segment has %d leaves, want 2", segment.LeafCount)
	}
}

func TestFairLayoutSplitsRegionsIntoShards(t *testing.T) {
	// Region R0 has 11 records over 3 shards: sizes 4, 4, 3; 2-leaf segments.
	layout, err := newFairLayout([]int{11, 6}, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]hpp.PhysicalAddress{
		0:  {RegionID: "R0", ShardID: 0, SegmentID: 0, LeafID: 0},
		3:  {RegionID: "R0", ShardID: 0, SegmentID: 1, LeafID: 1},
		4:  {RegionID: "R0", ShardID: 1, SegmentID: 0, LeafID: 0},
		8:  {RegionID: "R0", ShardID: 2, SegmentID: 0, LeafID: 0},
		10: {RegionID: "R0", ShardID: 2, SegmentID: 1, LeafID: 0},
		11: {RegionID: "R1", ShardID: 0, SegmentID: 0, LeafID: 0},
		16: {RegionID: "R1", ShardID: 2, SegmentID: 0, LeafID: 1},
	}
	for ordinal, address := range want {
		if got := layout.address(ordinal); got != address {
			t.Fatalf("address(%d) = %+v, want %+v", ordinal, got, address)
		}
	}
	leaves := make([][32]byte, layout.total())
	for index := range leaves {
		leaves[index] = syntheticLeafHash(0, 0, 0, index)
	}
	forest, err := newFairForest(layout, leaves)
	if err != nil {
		t.Fatal(err)
	}
	for _, placement := range []string{"clustered", "scattered"} {
		addresses, err := forest.addresses(placement, 7)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := forest.service.BuildAndVerify(context.Background(), addresses, forest.root); err != nil {
			t.Fatalf("verify %s proof across shards: %v", placement, err)
		}
	}
	if shard := forest.metadata.Regions["R0"]; shard.LeafCount != 3 {
		t.Fatalf("region R0 has %d shards, want 3", shard.LeafCount)
	}
}

// TestFairLayoutOrdinalInvertsAddress checks the mapping requests use to find
// a record's PostgreSQL ID from its physical address.
func TestFairLayoutOrdinalInvertsAddress(t *testing.T) {
	layout, err := newFairLayout([]int{9, 4, 7}, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	for ordinal := range layout.total() {
		got, ok := layout.ordinal(layout.address(ordinal))
		if !ok || got != ordinal {
			t.Fatalf("ordinal(address(%d)) = %d, %v", ordinal, got, ok)
		}
	}
	for _, address := range []hpp.PhysicalAddress{
		{RegionID: "R3", ShardID: 0, SegmentID: 0, LeafID: 0},
		{RegionID: "x", ShardID: 0, SegmentID: 0, LeafID: 0},
		{RegionID: "R0", ShardID: 2, SegmentID: 0, LeafID: 0},
		{RegionID: "R1", ShardID: 0, SegmentID: 1, LeafID: 0},
		{RegionID: "R0", ShardID: 0, SegmentID: 0, LeafID: 3},
	} {
		if ordinal, ok := layout.ordinal(address); ok {
			t.Fatalf("ordinal(%+v) = %d, want not ok", address, ordinal)
		}
	}
}

func TestFairALLQueryReturnsOnlyRequestedPhysicalAddresses(t *testing.T) {
	const segmentLeaves = 8192
	layout, err := newFairLayout([]int{2 * segmentLeaves, 2 * segmentLeaves, 2 * segmentLeaves}, 1, segmentLeaves)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := buildFairLocatorTree(layout)
	if err != nil {
		t.Fatal(err)
	}
	if tree.LeafCount != int64(layout.total()) {
		t.Fatalf("ALL contains %d records, want %d", tree.LeafCount, layout.total())
	}
	clusterQuery, err := fairLocatorQuery("clustered-2", 16)
	if err != nil {
		t.Fatal(err)
	}
	scatterQuery, err := fairLocatorQuery("scattered", 16)
	if err != nil {
		t.Fatal(err)
	}
	if clusterQuery.TenantID != scatterQuery.TenantID ||
		clusterQuery.ServiceID != scatterQuery.ServiceID ||
		clusterQuery.LogType != scatterQuery.LogType ||
		clusterQuery.RegionID != scatterQuery.RegionID ||
		scatterQuery.StartTime.Sub(clusterQuery.StartTime) != fairVerificationMaxCount*time.Second ||
		clusterQuery.EndTime.Sub(clusterQuery.StartTime) != scatterQuery.EndTime.Sub(scatterQuery.StartTime) {
		t.Fatalf("ALL query shapes differ: clustered=%+v scattered=%+v", clusterQuery, scatterQuery)
	}
	for _, placement := range fairBenchmarkPlacements {
		for _, count := range []int{1, 16, 256, fairVerificationMaxCount} {
			query, err := fairLocatorQuery(placement, count)
			if err != nil {
				t.Fatal(err)
			}
			result, err := tree.Resolve(query)
			if err != nil {
				t.Fatalf("ALL %s/q=%d: %v", placement, count, err)
			}
			if err := locator.VerifyLocatorQueryResult(query, result, tree.RootHash); err != nil {
				t.Fatalf("ALL proof %s/q=%d: %v", placement, count, err)
			}
			if len(result.Entries) != count {
				t.Fatalf("ALL %s/q=%d returned %d entries", placement, count, len(result.Entries))
			}
			addresses, err := fairPhysicalAddresses(layout, result.Entries)
			if err != nil {
				t.Fatal(err)
			}
			want, err := fairVerificationOrdinals(layout, placement, count)
			if err != nil {
				t.Fatal(err)
			}
			if count >= 16 {
				wantPrefix := []int{0, 8192, 4096, 12288}
				if placement == "scattered" {
					wantPrefix = []int{16384, 32768, 24576, 40960}
				}
				for i, ordinal := range wantPrefix {
					if want[i] != ordinal {
						t.Fatalf("%s/q=%d ordinal %d = %d, want %d", placement, count, i, want[i], ordinal)
					}
				}
			}
			for index, address := range addresses {
				if address != layout.address(want[index]) {
					t.Fatalf("ALL %s/q=%d address %d = %+v, want ordinal %d",
						placement, count, index, address, want[index])
				}
			}
			if count > 1 {
				type segmentKey struct {
					region  string
					shard   int64
					segment int64
				}
				segments := make(map[segmentKey]struct{})
				for _, address := range addresses {
					if placement == "clustered-2" && address.RegionID != "R0" ||
						placement == "scattered" && address.RegionID == "R0" {
						t.Fatalf("%s/q=%d returned address in %s", placement, count, address.RegionID)
					}
					segments[segmentKey{address.RegionID, address.ShardID, address.SegmentID}] = struct{}{}
				}
				if placement == "clustered-2" && len(segments) != 2 {
					t.Fatalf("clustered-2/q=%d touched %d segments", count, len(segments))
				}
				if placement == "scattered" && len(segments) < 4 {
					t.Fatalf("scattered/q=%d touched %d segments", count, len(segments))
				}
			}
		}
	}
}
