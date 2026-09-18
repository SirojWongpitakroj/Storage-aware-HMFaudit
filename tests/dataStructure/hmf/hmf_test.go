package tests

import (
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
)

func TestNewHMF(t *testing.T) {
	forest, err := hmf.NewHMF(hmf.HMFConfig{
		RegionIDs:          []string{"R0", "R1"},
		NumShardsPerRegion: 2,
		MaxSegmentLeaves:   4,
	})
	if err != nil {
		t.Fatalf("new HMF: %v", err)
	}

	if len(forest.RegionTrees) != 2 || len(forest.ShardTrees) != 4 {
		t.Fatalf("unexpected HMF tree count: regions=%d shards=%d", len(forest.RegionTrees), len(forest.ShardTrees))
	}

}

func TestHMFInitializesCanonicalUpperTreesAndReturnsProofSiblings(t *testing.T) {
	forest, err := hmf.NewHMF(hmf.HMFConfig{
		RegionIDs:          []string{"R0", "R1"},
		NumShardsPerRegion: 4,
		MaxSegmentLeaves:   4,
	})
	if err != nil {
		t.Fatalf("new HMF: %v", err)
	}

	emptyShardRoots := make([][32]byte, 4)
	emptyRegionRoot := merkleRoot(emptyShardRoots)
	if forest.RegionTrees["R0"].Root != emptyRegionRoot || forest.RegionTrees["R1"].Root != emptyRegionRoot {
		t.Fatal("region trees were not initialized with canonical empty-subtree hashes")
	}
	wantInitialGlobal := merkleRoot([][32]byte{emptyRegionRoot, emptyRegionRoot})
	if forest.Root() != wantInitialGlobal {
		t.Fatalf("initial global root = %x, want %x", forest.Root(), wantInitialGlobal)
	}

	segmentRoot := testHash("sealed-segment")
	update, err := forest.AppendSealedSegment("R0", 2, segmentRoot)
	if err != nil {
		t.Fatalf("append sealed segment: %v", err)
	}
	regionLeaves := make([][32]byte, 4)
	regionLeaves[2] = segmentRoot
	wantRegionRoot := merkleRoot(regionLeaves)
	wantGlobalRoot := merkleRoot([][32]byte{wantRegionRoot, emptyRegionRoot})
	if update.RegionRoot != wantRegionRoot || update.GlobalRoot != wantGlobalRoot {
		t.Fatalf("updated roots = %x/%x, want %x/%x",
			update.RegionRoot, update.GlobalRoot, wantRegionRoot, wantGlobalRoot)
	}

	regionPositions := make(map[[2]int64]bool)
	for _, node := range update.RegionNodes {
		regionPositions[[2]int64{int64(node.Level), node.Index}] = true
	}
	for _, position := range [][2]int64{{0, 3}, {1, 0}} {
		if !regionPositions[position] {
			t.Fatalf("region update omitted proof sibling at level/index %v", position)
		}
	}
	globalSiblingFound := false
	for _, node := range update.GlobalNodes {
		if node.Level == 0 && node.Index == 1 {
			globalSiblingFound = true
		}
	}
	if !globalSiblingFound {
		t.Fatal("global update omitted untouched region sibling")
	}
}
