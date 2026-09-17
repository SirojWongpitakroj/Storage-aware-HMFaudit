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
