package tests

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hm"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
)

func TestManagerRotatesFullSegment(t *testing.T) {
	forest, err := hmf.NewHMF(hmf.HMFConfig{
		RegionIDs:          []string{"R0"},
		NumShardsPerRegion: 1,
		MaxSegmentLeaves:   1,
	})
	if err != nil {
		t.Fatalf("new HMF: %v", err)
	}

	manager, err := hm.NewManager(forest, 1, time.Hour)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	now := time.Now().UTC()
	first := sha256.Sum256([]byte("first"))
	second := sha256.Sum256([]byte("second"))
	if err := manager.Submit("R0", 0, first, now); err != nil {
		t.Fatalf("submit first digest: %v", err)
	}
	if err := manager.Submit("R0", 0, second, now.Add(time.Second)); err != nil {
		t.Fatalf("submit second digest: %v", err)
	}

	select {
	case update := <-manager.Updates():
		if len(update.SegmentNodes) != 1 {
			t.Fatalf("segment node count = %d, want 1", len(update.SegmentNodes))
		}
		if update.GlobalRoot != forest.Root() {
			t.Fatal("update global root does not match forest root")
		}
	case <-time.After(time.Second):
		t.Fatal("manager did not emit an HMF update after rotation")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.StopWorker(ctx, "R0", 0); err != nil {
		t.Fatalf("stop worker: %v", err)
	}
}
