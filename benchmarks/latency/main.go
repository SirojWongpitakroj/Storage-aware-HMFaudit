package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
)

const benchmarkK = localization.DefaultJumpLevels

type benchmarkConfig struct {
	iterations int
	warmup     int
	sampleTime time.Duration
	batchSizes []int
	output     string
	gomaxprocs int
}

type scenario struct {
	placement       string
	batchSize       int
	addresses       []hpp.PhysicalAddress
	reference       hpp.VerificationResult
	failed          hpp.HMFProof
	auditorRoot     [32]byte
	localizer       *localization.Service
	localization    localization.Result
	localizationReq localization.Request
}

type verifiedReference struct {
	result hpp.VerificationResult
}

func (reference verifiedReference) BuildAndVerify(_ context.Context,
	addresses []hpp.PhysicalAddress, trustedRoot [32]byte) (hpp.VerificationResult, error) {
	if _, err := hpp.VerifyHMFProofAgainstRoot(reference.result.Proof, addresses, trustedRoot); err != nil {
		return hpp.VerificationResult{}, err
	}
	return reference.result, nil
}

type measurement struct {
	operation string
	latency   time.Duration
}

var benchmarkSink [32]byte

func main() {
	config, err := parseFlags()
	if err != nil {
		fatal(err)
	}
	runtime.GOMAXPROCS(config.gomaxprocs)

	started := time.Now().UTC()
	fmt.Printf("building deterministic synthetic HMF (%d Segment leaves, k=%d)...\n",
		benchmarkSegmentLeaves, benchmarkK)
	forest, err := newSyntheticForest()
	if err != nil {
		fatal(fmt.Errorf("build synthetic forest: %w", err))
	}

	if err := os.MkdirAll(filepath.Dir(config.output), 0o755); err != nil {
		fatal(fmt.Errorf("create results directory: %w", err))
	}
	file, err := os.Create(config.output)
	if err != nil {
		fatal(fmt.Errorf("create result file: %w", err))
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err := writer.Write([]string{
		"run_started_utc", "go_version", "gomaxprocs", "k", "operation", "placement",
		"batch_size", "iteration", "latency_ns", "proof_leaves", "proof_nodes",
		"pruning_rounds", "suspects", "operations_per_sample",
	}); err != nil {
		fatal(err)
	}

	for _, placement := range []string{"clustered", "scattered"} {
		for _, batchSize := range config.batchSizes {
			scenario, err := prepareScenario(context.Background(), forest, placement, batchSize)
			if err != nil {
				fatal(fmt.Errorf("prepare %s batch %d: %w", placement, batchSize, err))
			}
			fmt.Printf("measuring placement=%s batch=%d...\n", placement, batchSize)
			if err := runScenario(context.Background(), writer, started, config, scenario); err != nil {
				fatal(fmt.Errorf("run %s batch %d: %w", placement, batchSize, err))
			}
			writer.Flush()
			if err := writer.Error(); err != nil {
				fatal(fmt.Errorf("write measurements: %w", err))
			}
			runtime.GC()
		}
	}
	fmt.Printf("raw latency samples written to %s\n", config.output)
}

func parseFlags() (benchmarkConfig, error) {
	iterations := flag.Int("iterations", 200, "measured iterations per operation and scenario")
	warmup := flag.Int("warmup", 20, "warm-up iterations per operation and scenario")
	sampleTime := flag.Duration("sample-duration", 20*time.Millisecond,
		"minimum timing window used for each latency sample")
	batches := flag.String("batch-sizes", "1,16,64,256,1024", "comma-separated batch sizes")
	output := flag.String("out", "benchmarks/results/latency_raw.csv", "raw CSV output path")
	gomaxprocs := flag.Int("gomaxprocs", 1, "GOMAXPROCS used during measurements")
	flag.Parse()
	if *iterations <= 0 || *warmup < 0 || *sampleTime <= 0 || *gomaxprocs <= 0 {
		return benchmarkConfig{}, fmt.Errorf("iterations, sample-duration, and gomaxprocs must be positive; warmup must not be negative")
	}
	var batchSizes []int
	seen := make(map[int]struct{})
	for _, value := range strings.Split(*batches, ",") {
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || parsed <= 0 {
			return benchmarkConfig{}, fmt.Errorf("invalid batch size %q", value)
		}
		if _, duplicate := seen[parsed]; !duplicate {
			seen[parsed] = struct{}{}
			batchSizes = append(batchSizes, parsed)
		}
	}
	sort.Ints(batchSizes)
	return benchmarkConfig{iterations: *iterations, warmup: *warmup, sampleTime: *sampleTime,
		batchSizes: batchSizes, output: *output, gomaxprocs: *gomaxprocs}, nil
}

func prepareScenario(ctx context.Context, forest *syntheticForest,
	placement string, batchSize int) (*scenario, error) {
	addresses, err := forest.addresses(placement, batchSize)
	if err != nil {
		return nil, err
	}
	reference, err := forest.service.BuildAndVerify(ctx, addresses, forest.root)
	if err != nil {
		return nil, fmt.Errorf("build reference proof: %w", err)
	}
	failed := cloneHMFProof(reference.Proof)
	tamperedIndex := len(failed.Leaves) / 2
	failed.Leaves[tamperedIndex].Hash[0] ^= 0xff
	auditorRoot, err := hpp.VerifyHMFProof(failed, addresses)
	if err != nil {
		return nil, fmt.Errorf("calculate failed auditor root: %w", err)
	}
	localizer, err := localization.NewService(verifiedReference{result: reference})
	if err != nil {
		return nil, err
	}
	request := localization.Request{
		Addresses: addresses, AuditorGlobalRoot: auditorRoot, FailedProof: failed,
		AnchoredGlobalRoot: forest.root, K: benchmarkK,
	}
	localized, err := localizer.Localize(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("prepare localization proof: %w", err)
	}
	if err := localization.VerifyProof(localized.Proof, addresses, forest.root); err != nil {
		return nil, fmt.Errorf("verify prepared localization proof: %w", err)
	}
	return &scenario{
		placement: placement, batchSize: batchSize, addresses: addresses, reference: reference,
		failed: failed, auditorRoot: auditorRoot, localizer: localizer,
		localization: localized, localizationReq: request,
	}, nil
}

func runScenario(ctx context.Context, writer *csv.Writer, runStarted time.Time,
	config benchmarkConfig, scenario *scenario) error {
	operations := []string{"hmf_verification", "tamper_localization", "localization_proof_verification"}
	for iteration := 0; iteration < config.warmup; iteration++ {
		for _, operation := range operations {
			if err := execute(ctx, scenario, operation); err != nil {
				return err
			}
		}
	}
	repetitions := make(map[string]int, len(operations))
	for _, operation := range operations {
		count, err := calibrate(ctx, scenario, operation, config.sampleTime)
		if err != nil {
			return err
		}
		repetitions[operation] = count
	}

	latencies := make(map[string][]time.Duration, len(operations))
	for iteration := 0; iteration < config.iterations; iteration++ {
		// Rotate operation order so one operation is not always measured first.
		for offset := range operations {
			operation := operations[(iteration+offset)%len(operations)]
			measurement, err := measure(ctx, scenario, operation, repetitions[operation])
			if err != nil {
				return err
			}
			latencies[operation] = append(latencies[operation], measurement.latency)
			if err := writer.Write([]string{
				runStarted.Format(time.RFC3339Nano), runtime.Version(), strconv.Itoa(config.gomaxprocs),
				strconv.Itoa(int(benchmarkK)), operation, scenario.placement,
				strconv.Itoa(scenario.batchSize), strconv.Itoa(iteration),
				strconv.FormatInt(measurement.latency.Nanoseconds(), 10),
				strconv.Itoa(len(scenario.reference.Proof.Leaves)),
				strconv.Itoa(len(scenario.reference.Proof.Nodes)),
				strconv.Itoa(len(scenario.localization.Proof.Rounds)),
				strconv.Itoa(len(scenario.localization.Proof.Suspects)),
				strconv.Itoa(repetitions[operation]),
			}); err != nil {
				return err
			}
		}
	}
	for _, operation := range operations {
		values := latencies[operation]
		fmt.Printf("  %-31s p50=%-10s p95=%-10s p99=%s\n", operation,
			percentile(values, 0.50), percentile(values, 0.95), percentile(values, 0.99))
	}
	return nil
}

func calibrate(ctx context.Context, scenario *scenario, operation string,
	target time.Duration) (int, error) {
	repetitions := 1
	for {
		started := time.Now()
		for iteration := 0; iteration < repetitions; iteration++ {
			if err := execute(ctx, scenario, operation); err != nil {
				return 0, err
			}
		}
		elapsed := time.Since(started)
		if elapsed >= target {
			return repetitions, nil
		}
		if elapsed <= 0 {
			repetitions *= 10
			continue
		}
		scale := int(math.Ceil(float64(target) / float64(elapsed)))
		if scale < 2 {
			scale = 2
		}
		if scale > 10 {
			scale = 10
		}
		repetitions *= scale
	}
}

func measure(ctx context.Context, scenario *scenario, operation string,
	repetitions int) (measurement, error) {
	started := time.Now()
	for iteration := 0; iteration < repetitions; iteration++ {
		if err := execute(ctx, scenario, operation); err != nil {
			return measurement{}, err
		}
	}
	return measurement{operation: operation,
		latency: time.Since(started) / time.Duration(repetitions)}, nil
}

func execute(ctx context.Context, scenario *scenario, operation string) error {
	switch operation {
	case "hmf_verification":
		root, err := hpp.VerifyHMFProofAgainstRoot(
			scenario.reference.Proof, scenario.addresses, scenario.reference.CalculatedGlobalRoot,
		)
		if err != nil {
			return err
		}
		benchmarkSink = root
	case "tamper_localization":
		result, err := scenario.localizer.Localize(ctx, scenario.localizationReq)
		if err != nil {
			return err
		}
		benchmarkSink = result.CalculatedReferenceRoot
	case "localization_proof_verification":
		if err := localization.VerifyProof(scenario.localization.Proof,
			scenario.addresses, scenario.reference.CalculatedGlobalRoot); err != nil {
			return err
		}
		benchmarkSink = scenario.localization.Proof.ReferenceGlobalRoot
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	return nil
}

func percentile(values []time.Duration, quantile float64) time.Duration {
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	if len(ordered) == 0 {
		return 0
	}
	index := int(math.Ceil(quantile*float64(len(ordered)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(ordered) {
		index = len(ordered) - 1
	}
	return ordered[index]
}

func cloneHMFProof(input hpp.HMFProof) hpp.HMFProof {
	result := input
	result.Leaves = append([]hpp.RequestedLeaf(nil), input.Leaves...)
	result.Nodes = append([]hpp.ProofNode(nil), input.Nodes...)
	return result
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "benchmark:", err)
	os.Exit(1)
}
