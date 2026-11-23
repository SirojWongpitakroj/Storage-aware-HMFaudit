package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/benchmarks/exp2b"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
)

// Experiment 2B: ACHP versus fixed-depth localization under increasing corruption
// density (m = 1, 4, 16, 64 of q = 1024 audited records), clustered and scattered.
//
//	FAIR_EXP2B_DRY_RUN=1 FAIR_EXP2B_OUT=<dir> go test ./benchmarks/latency -run '^TestExp2BDryRun$' -v
//	    manifests at full scale plus an in-memory smoke run; no database, no cloud.
//	FAIR_EXP2B=1 FAIR_PERSISTENCE=1 FAIR_EXP2B_OUT=<dir> ... go test ./benchmarks/latency -run '^TestExp2BCloud$' -timeout 0
//	    the real measurement against Cassandra and PostgreSQL (see
//	    systems/experiments/scripts/exp2b_localization.sh). It is never started by `go test` alone.

// smallExp2BParams scales the experiment down for the in-memory runs.
func smallExp2BParams(queries int) exp2b.Params {
	params := exp2b.DefaultParams()
	params.QueryCount = queries
	params.Q, params.DenseSegments, params.DensePerSegment, params.SparsePerSegment = 512, 4, 64, 16
	params.CorruptionCounts = []int{1, 4, 16}
	params.Warmups, params.Repetitions = 1, 2
	return params
}

var smallRegionSizes = []int{10240, 10240} // 40 segments of 256 leaves each

func runInMemoryExp2B(t *testing.T, params exp2b.Params, wrap func(*memoryExp2BEnv) exp2b.Environment) (
	[]exp2b.RawRow, *exp2b.Layout, exp2b.QueryManifest) {
	t.Helper()
	env, err := newMemoryExp2BEnv(smallRegionSizes, 256)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := exp2bLayout(env.layout)
	if err != nil {
		t.Fatal(err)
	}
	queries, corruption, _, err := exp2b.LoadOrGenerate(t.TempDir(), params, layout)
	if err != nil {
		t.Fatal(err)
	}
	algorithms, err := env.algorithms()
	if err != nil {
		t.Fatal(err)
	}
	var environment exp2b.Environment = env
	if wrap != nil {
		environment = wrap(env)
	}
	rows, err := exp2b.Run(context.Background(), queries, corruption, environment,
		exp2b.Config{Algorithms: algorithms, VerifyProofs: true})
	if err != nil {
		t.Fatal(err)
	}
	return rows, layout, queries
}

func TestExp2BInMemoryEndToEnd(t *testing.T) {
	params := smallExp2BParams(2)
	rows, _, _ := runInMemoryExp2B(t, params, nil)
	// 2 queries x (m=1 common + m=4 and m=16, two localities each) x 2 measured x 2 algorithms.
	if want := 2 * (1 + 2*2) * 2 * 2; len(rows) != want {
		t.Fatalf("%d measured rows, want %d (warm-ups must not be recorded)", len(rows), want)
	}
	byAlgorithm := map[string]int{}
	for _, row := range rows {
		byAlgorithm[row.Algorithm]++
		if row.Status != exp2b.StatusOK {
			t.Fatalf("%s %s m=%d %s: status %s (%s), correct=%v fp=%d missed=%d nonleaf=%d unresolved=%d fallback=%q",
				row.Algorithm, row.QueryID, row.CorruptionCount, row.Locality, row.Status, row.Error,
				row.Correct, row.FalsePositives, row.Missed, row.NonLeaf, row.Unresolved, row.FallbackReason)
		}
		if row.QueryLocality == "" || row.ActualLocality == "" || row.CorruptedAddresses == "" || row.RecordsPerSegment == "" {
			t.Fatalf("%s row lacks locality metadata: %+v", row.Algorithm, row)
		}
		switch row.Locality {
		case exp2b.LocalityClustered:
			if row.DistinctSegments != 1 || row.DistinctShards != 1 || row.DistinctRegions != 1 {
				t.Fatalf("clustered row spans %d segments", row.DistinctSegments)
			}
		case exp2b.LocalityScattered:
			if row.DistinctSegments != row.CorruptionCount {
				t.Fatalf("scattered row m=%d spans %d segments", row.CorruptionCount, row.DistinctSegments)
			}
		}
		if row.ConfirmedLeaves != row.CorruptionCount {
			t.Fatalf("%s confirmed %d of %d corrupted leaves", row.Algorithm, row.ConfirmedLeaves, row.CorruptionCount)
		}
		// A latency of 0 is possible on Windows, whose clock ticks coarsely; the cloud runner's is finer.
		if row.LatencyMS < 0 || row.PartitionReads <= 0 || row.NodesRetrieved <= 0 || row.EvidenceBytes != int64(row.NodesRetrieved)*32 {
			t.Fatalf("%s row has implausible counters: %+v", row.Algorithm, row)
		}
		switch row.Algorithm {
		case "ACHP":
			if row.ExecutedStrategy != string(localization.StrategyACHP) || row.Fallback || row.PlanningMS < 0 {
				t.Fatalf("ACHP row executed %s (fallback %v, planning %v)", row.ExecutedStrategy, row.Fallback, row.PlanningMS)
			}
		case "FIXED":
			if row.ExecutedStrategy != string(localization.StrategyFixedDepth) || row.PlanningMS >= 0 {
				t.Fatalf("fixed-depth row executed %s with planning %v", row.ExecutedStrategy, row.PlanningMS)
			}
		}
		if !row.ProofVerified {
			t.Fatalf("%s proof did not verify against the trusted root", row.Algorithm)
		}
	}
	if byAlgorithm["ACHP"] != byAlgorithm["FIXED"] || byAlgorithm["ACHP"] == 0 {
		t.Fatalf("rows per algorithm = %v", byAlgorithm)
	}
}

func TestExp2BEveryAlgorithmGetsTheSameCorruption(t *testing.T) {
	rows, _, _ := runInMemoryExp2B(t, smallExp2BParams(1), nil)
	type key struct {
		query    string
		count    int
		locality string
		rep      int
	}
	seen := map[key]map[string]string{}
	for _, row := range rows {
		k := key{row.QueryID, row.CorruptionCount, row.Locality, row.Repetition}
		if seen[k] == nil {
			seen[k] = map[string]string{}
		}
		seen[k][row.Algorithm] = fmt.Sprint(row.CorruptedOrdinals, row.Seed)
	}
	for k, byAlgorithm := range seen {
		if len(byAlgorithm) != 2 || byAlgorithm["ACHP"] != byAlgorithm["FIXED"] {
			t.Fatalf("%+v: algorithms saw different corruption: %v", k, byAlgorithm)
		}
	}
}

// slowEnv delays what the protocol says is outside the timed operation.
type slowEnv struct {
	*memoryExp2BEnv
	delay time.Duration
}

func (env slowEnv) Inject(ctx context.Context, ordinals []int) error {
	time.Sleep(env.delay)
	return env.memoryExp2BEnv.Inject(ctx, ordinals)
}

func (env slowEnv) FailedProof(ctx context.Context, addresses []hpp.PhysicalAddress) (hpp.HMFProof, [32]byte, error) {
	time.Sleep(env.delay)
	return env.memoryExp2BEnv.FailedProof(ctx, addresses)
}

func (env slowEnv) Restore(ctx context.Context) error {
	time.Sleep(env.delay)
	return env.memoryExp2BEnv.Restore(ctx)
}

func TestExp2BTimedOperationExcludesInjectionVerificationAndRestore(t *testing.T) {
	params := smallExp2BParams(1)
	params.CorruptionCounts, params.Warmups, params.Repetitions = []int{4}, 0, 2
	const delay = 200 * time.Millisecond
	rows, _, _ := runInMemoryExp2B(t, params, func(env *memoryExp2BEnv) exp2b.Environment {
		return slowEnv{memoryExp2BEnv: env, delay: delay}
	})
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	for _, row := range rows {
		if row.Status != exp2b.StatusOK {
			t.Fatalf("row status %s: %s", row.Status, row.Error)
		}
		// Injection, the failed proof and restoration each sleep 200 ms; any of them
		// inside the timer would push the latency past that on its own.
		if time.Duration(row.LatencyMS*float64(time.Millisecond)) >= delay {
			t.Fatalf("%s latency %.1f ms includes work outside Localize", row.Algorithm, row.LatencyMS)
		}
	}
}

func TestExp2BDetectsAWrongCorruptionSet(t *testing.T) {
	params := smallExp2BParams(1)
	params.CorruptionCounts, params.Warmups, params.Repetitions = []int{4}, 0, 3
	env, err := newMemoryExp2BEnv(smallRegionSizes, 256)
	if err != nil {
		t.Fatal(err)
	}
	layout, _ := exp2bLayout(env.layout)
	queries, corruption, _, err := exp2b.LoadOrGenerate(t.TempDir(), params, layout)
	if err != nil {
		t.Fatal(err)
	}
	// The environment corrupts one extra requested record the manifest does not list.
	env.extra = []int{queries.Queries[0].Ordinals[0]}
	algorithms, _ := env.algorithms()
	rows, err := exp2b.Run(context.Background(), queries, corruption, env,
		exp2b.Config{Algorithms: algorithms, VerifyProofs: true})
	if err != nil {
		t.Fatal(err)
	}
	incorrect := 0
	for _, row := range rows {
		if row.FalsePositives > 0 {
			incorrect++
			if row.Status != exp2b.StatusIncorrect || row.Correct {
				t.Fatalf("a false positive was classified %s, correct=%v", row.Status, row.Correct)
			}
		} else if row.Status != exp2b.StatusOK {
			t.Fatalf("unexpected status %s: %s", row.Status, row.Error)
		}
	}
	if incorrect == 0 {
		t.Fatal("the extra corrupted record was never reported as a false positive")
	}
}

// plainReference hides the frontier capability, so ACHP must fall back.
type plainReference struct{ service *hpp.Service }

func (reference plainReference) BuildAndVerify(ctx context.Context, addresses []hpp.PhysicalAddress,
	trusted [32]byte) (hpp.VerificationResult, error) {
	return reference.service.BuildAndVerify(ctx, addresses, trusted)
}

func (reference plainReference) ReferenceFromProof(ctx context.Context, proof hpp.HMFProof,
	addresses []hpp.PhysicalAddress, trusted [32]byte) (hpp.VerificationResult, error) {
	return reference.service.ReferenceFromProof(ctx, proof, addresses, trusted)
}

func TestExp2BRecordsACHPFallbackAndNeverCountsItAsACHP(t *testing.T) {
	params := smallExp2BParams(1)
	params.CorruptionCounts, params.Warmups, params.Repetitions = []int{4}, 0, 2
	env, err := newMemoryExp2BEnv(smallRegionSizes, 256)
	if err != nil {
		t.Fatal(err)
	}
	layout, _ := exp2bLayout(env.layout)
	queries, corruption, _, err := exp2b.LoadOrGenerate(t.TempDir(), params, layout)
	if err != nil {
		t.Fatal(err)
	}
	algorithms, _ := env.algorithms()
	measured := algorithms[0].Reader
	service, err := hpp.NewService(measured, measured)
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := localization.NewService(plainReference{service: service}, localization.WithStrategy(localization.StrategyACHP))
	if err != nil {
		t.Fatal(err)
	}
	algorithms[0].Service = fallback
	rows, err := exp2b.Run(context.Background(), queries, corruption, env,
		exp2b.Config{Algorithms: algorithms[:1], VerifyProofs: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if !row.Fallback || row.FallbackReason == "" || row.Status != exp2b.StatusFallback ||
			row.ExecutedStrategy != string(localization.StrategyFixedDepth) || row.RequestedStrategy != string(localization.StrategyACHP) {
			t.Fatalf("a fixed-depth fallback was not recorded as one: %+v", row)
		}
	}
	summary := exp2b.Summarize(rows)
	for _, line := range summary {
		valid, fallbacks := line[slices.Index(exp2b.SummaryHeader, "valid")], line[slices.Index(exp2b.SummaryHeader, "fallback_count")]
		if valid != "0" || fallbacks == "0" || line[slices.Index(exp2b.SummaryHeader, "p50_latency_ms")] != "" {
			t.Fatalf("fallback rows leaked into ACHP's statistics: %v", line)
		}
	}
}

func TestExp2BRawCSVCarriesEveryRowAndHeader(t *testing.T) {
	rows, _, _ := runInMemoryExp2B(t, smallExp2BParams(1), nil)
	var out strings.Builder
	writer, err := exp2b.NewRawWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			t.Fatal(err)
		}
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(rows)+1 || !strings.HasPrefix(lines[0], "algorithm,") {
		t.Fatalf("raw.csv has %d lines for %d rows", len(lines), len(rows))
	}
}

func exp2bOutputDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("FAIR_EXP2B_OUT")
	if dir == "" {
		t.Fatal("FAIR_EXP2B_OUT must name the Experiment 2B output directory")
	}
	return dir
}

func exp2bRegionSizes(t *testing.T) []int {
	t.Helper()
	value := os.Getenv("FAIR_EXP2B_REGIONS")
	if value == "" {
		return []int{2500000, 2500000, 2500000, 2500000}
	}
	var sizes []int
	for _, field := range strings.Split(value, ",") {
		size, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || size <= 0 {
			t.Fatalf("invalid FAIR_EXP2B_REGIONS %q", value)
		}
		sizes = append(sizes, size)
	}
	return sizes
}

func writeExp2BResults(t *testing.T, dir string, config exp2b.RunConfig, rows []exp2b.RawRow) {
	t.Helper()
	summary, err := os.Create(filepath.Join(dir, exp2b.SummaryFile))
	if err != nil {
		t.Fatal(err)
	}
	defer summary.Close()
	if err := exp2b.WriteSummary(summary, rows); err != nil {
		t.Fatal(err)
	}
	if err := exp2b.WriteJSON(filepath.Join(dir, exp2b.RunConfigFile), config); err != nil {
		t.Fatal(err)
	}
}

// TestExp2BDryRun is the lightweight dry run: it draws and validates the
// full-scale manifests for the configured layout geometry (nothing is hashed or
// stored), then runs the complete harness on a small in-memory forest into
// <out>/dry-run. It needs no database and takes seconds.
func TestExp2BDryRun(t *testing.T) {
	if os.Getenv("FAIR_EXP2B_DRY_RUN") != "1" {
		t.Skip("set FAIR_EXP2B_DRY_RUN=1 and FAIR_EXP2B_OUT")
	}
	out := exp2bOutputDir(t)
	segmentLeaves := fairHMFLayoutSetting(t, "FAIR_HMF_SEGMENT_LEAVES", 1<<13)
	fair, err := newFairLayout(exp2bRegionSizes(t), fairHMFLayoutSetting(t, "FAIR_HMF_SHARDS_PER_REGION", 1), segmentLeaves)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := exp2bLayout(fair)
	if err != nil {
		t.Fatal(err)
	}
	queries, corruption, generated, err := exp2b.LoadOrGenerate(out, exp2b.DefaultParams(), layout)
	if err != nil {
		t.Fatalf("full-scale manifests: %v", err)
	}
	t.Logf("manifests in %s (generated=%v): %d queries x %d records, %d corruption cases, layout %d records in %d segments",
		out, generated, len(queries.Queries), queries.Params.Q, len(corruption.Cases), layout.Total(), layout.SegmentCount())

	smokeDir := filepath.Join(out, "dry-run")
	env, err := newMemoryExp2BEnv(smallRegionSizes, 256)
	if err != nil {
		t.Fatal(err)
	}
	smallLayout, err := exp2bLayout(env.layout)
	if err != nil {
		t.Fatal(err)
	}
	smallQueries, smallCorruption, _, err := exp2b.LoadOrGenerate(smokeDir, smallExp2BParams(2), smallLayout)
	if err != nil {
		t.Fatal(err)
	}
	algorithms, err := env.algorithms()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(smokeDir, "results"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.Create(filepath.Join(smokeDir, exp2b.RawFile))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	writer, err := exp2b.NewRawWriter(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := exp2b.Run(context.Background(), smallQueries, smallCorruption, env, exp2b.Config{
		Algorithms: algorithms, VerifyProofs: true, Sink: writer.Write, Progress: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	config := exp2bRunConfig("in-memory", smallQueries.Params, smallQueries, smallLayout, []string{"ACHP", "FIXED"}, 0, true)
	config.Notes = append(config.Notes, "DRY RUN: small in-memory forest; these numbers say nothing about the cloud system.")
	writeExp2BResults(t, smokeDir, config, rows)
	t.Logf("dry run wrote %d rows to %s", len(rows), smokeDir)
}

// TestExp2BCloud is the real Experiment 2B measurement. It seeds (or reuses, per
// the shared fixture) Cassandra and PostgreSQL like every other fair benchmark,
// draws or loads the persisted manifests, and measures ACHP and fixed-depth HMF
// on identical corruption. It never runs unless FAIR_EXP2B=1.
func TestExp2BCloud(t *testing.T) {
	if os.Getenv("FAIR_EXP2B") != "1" {
		t.Skip("set FAIR_EXP2B=1 (and the fair benchmark environment) to run Experiment 2B against the cloud")
	}
	out := exp2bOutputDir(t)
	fixture := sharedFairHMFFixture(t)
	// The fixture does not keep the forest after seeding, only its layout.
	layout, err := exp2bLayout(fixture.forest.layout)
	if err != nil {
		t.Fatal(err)
	}
	params := exp2b.DefaultParams()
	if value := os.Getenv("FAIR_EXP2B_SEED"); value != "" {
		seed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			t.Fatalf("invalid FAIR_EXP2B_SEED %q", value)
		}
		params.MasterSeed = seed
	}
	queries, corruption, generated, err := exp2b.LoadOrGenerate(out, params, layout)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("manifests (generated=%v): %d queries, %d corruption cases", generated, len(queries.Queries), len(corruption.Cases))

	env := persistentExp2BEnv{fixture: fixture}
	algorithms, err := env.algorithms()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(out, "results"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.Create(filepath.Join(out, exp2b.RawFile))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	writer, err := exp2b.NewRawWriter(raw)
	if err != nil {
		t.Fatal(err)
	}
	config := exp2bRunConfig("cloud", params, queries, layout, []string{"ACHP", "FIXED"}, fixture.hppConcurrency, true)
	// run_config.json is written first so an interrupted run is still described.
	if err := exp2b.WriteJSON(filepath.Join(out, exp2b.RunConfigFile), config); err != nil {
		t.Fatal(err)
	}
	var rows []exp2b.RawRow
	rows, err = exp2b.Run(context.Background(), queries, corruption, env, exp2b.Config{
		Algorithms: algorithms, VerifyProofs: true, Sink: writer.Write, Progress: t.Logf,
	})
	// Whatever was measured is summarized, even when the run stopped early.
	writeExp2BResults(t, out, config, rows)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Experiment 2B wrote %d rows to %s", len(rows), out)
}
