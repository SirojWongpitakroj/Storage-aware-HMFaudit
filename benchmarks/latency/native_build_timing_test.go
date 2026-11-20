package main

import (
	"os"
	"testing"
	"time"
)

// TestFairNativeLocatorBuildTiming times the in-memory half of the ALL setup (no database):
// reading the dataset's metadata and building the locator tree. It needs the dataset the run
// would use and about 9 GB of memory at 10M records, so it only runs on request:
//
//	FAIR_BUILD_TIMING=1 FAIR_DATASET_PATH=<jsonl> FAIR_REGION0_RECORDS=2500000 \
//	  FAIR_HMF_SHARDS_PER_REGION=4 go test ./benchmarks/latency -run TestFairNativeLocatorBuildTiming -v
func TestFairNativeLocatorBuildTiming(t *testing.T) {
	path := os.Getenv("FAIR_DATASET_PATH")
	if os.Getenv("FAIR_BUILD_TIMING") != "1" || path == "" {
		t.Skip("set FAIR_BUILD_TIMING=1 and FAIR_DATASET_PATH to time the native ALL tree build")
	}
	region := 2_500_000
	layout, err := newFairLayout([]int{region, region, region, region}, 4, 8192)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	meta, err := loadFairNativeMetadata(path, layout.total())
	if err != nil {
		t.Fatal(err)
	}
	loaded := time.Since(start)
	start = time.Now()
	tree, err := buildNativeLocatorTree(layout, meta)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d records: read metadata %v, build tree %v (bulk load %v), %d leaves, root %x", layout.total(),
		loaded.Round(time.Second), time.Since(start).Round(time.Second), fairNativeBulkLoad, tree.LeafCount, tree.RootHash[:6])
}
