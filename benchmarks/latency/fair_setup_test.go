package main

import (
	"os"
	"runtime"
	"strconv"
	"testing"
)

// raiseFairSetupProcs lets setup use every CPU and returns a function that
// restores the previous GOMAXPROCS. Call it as `defer raiseFairSetupProcs()()`
// at the start of fixture seeding: seeding is outside every timer, while the
// timed requests keep the benchmark's GOMAXPROCS. FAIR_SETUP_GOMAXPROCS
// overrides the CPU count (a positive integer); an invalid value is ignored.
func raiseFairSetupProcs() func() {
	procs := runtime.NumCPU()
	if value := os.Getenv("FAIR_SETUP_GOMAXPROCS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			procs = parsed
		}
	}
	previous := runtime.GOMAXPROCS(procs)
	return func() { runtime.GOMAXPROCS(previous) }
}

func TestRaiseFairSetupProcsRestoresPrevious(t *testing.T) {
	before := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(before)
	t.Setenv("FAIR_SETUP_GOMAXPROCS", "3")
	restore := raiseFairSetupProcs()
	if got := runtime.GOMAXPROCS(0); got != 3 {
		t.Fatalf("setup GOMAXPROCS = %d, want 3", got)
	}
	restore()
	if got := runtime.GOMAXPROCS(0); got != 1 {
		t.Fatalf("GOMAXPROCS after restore = %d, want 1", got)
	}
}

func TestFairHMFSeedConcurrencyDefaultAndOverride(t *testing.T) {
	t.Setenv("FAIR_HMF_SEED_CONCURRENCY", "")
	if got := fairHMFSeedConcurrency(); got != fairHMFDefaultSeedConcurrency {
		t.Fatalf("default = %d, want %d", got, fairHMFDefaultSeedConcurrency)
	}
	t.Setenv("FAIR_HMF_SEED_CONCURRENCY", "16")
	if got := fairHMFSeedConcurrency(); got != 16 {
		t.Fatalf("override = %d, want 16", got)
	}
	t.Setenv("FAIR_HMF_SEED_CONCURRENCY", "0")
	if got := fairHMFSeedConcurrency(); got != fairHMFDefaultSeedConcurrency {
		t.Fatalf("invalid value gave %d, want the default", got)
	}
}
