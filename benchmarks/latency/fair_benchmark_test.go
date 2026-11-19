package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

var fairHMFResult [32]byte

// fairHMFValidRange records, per native query, the authenticated ALL range size
// once the query has been checked against the dataset.
var fairHMFValidRange = map[string]int{}

var fairHMFRequestCounts = []int{1, 16, 64, 256, 1024, 4096}
var fairLocalizationTamperCounts = []int{1, 2, 4, 8, 16, 32, 64, 128, 256}

const fairLocalizationFixedBatchSize = 1 << 12

type fairHMFRecord struct {
	RawLog   string `json:"raw_log"`
	RegionID string `json:"region_id"`
	SourceID string `json:"source_id"`
	TenantID string `json:"tenant_id"`
}

// BenchmarkFairHMFVerificationCore times HMF-Audit's complete verification
// instance on the native query set: one native ALL query (proof-verified over
// the whole range, a named tenant filtered afterwards) returns q physical
// addresses, then the HPP proof is built from Cassandra/PostgreSQL and
// verified against the anchored root. Five queries per (shape, q).
func BenchmarkFairHMFVerificationCore(b *testing.B) {
	dir := fairNativeQueriesDir()
	if dir == "" {
		b.Fatal("FAIR_NATIVE_QUERIES_DIR is required: HMF-Audit verification runs the native query set")
	}
	queries, err := loadFairHMFNativeQueries(dir, fairHMFRequestCounts)
	if err != nil {
		b.Fatal(err)
	}
	fixture := sharedFairHMFFixture(b)
	forest := fixture.forest
	for _, native := range queries {
		b.Run(native.name(), func(b *testing.B) {
			// The ALL result must be exactly what the dataset says the query
			// selects: the same range size and the same q records. Checked once
			// per query and process (go test re-enters this function for every
			// repetition), outside every timer.
			if fairHMFValidRange[native.name()] == 0 {
				wantRange, wantMatched := fixture.attributes.expected(forest.layout, native.Query)
				if len(wantMatched) != native.Q {
					b.Fatalf("%s: the dataset has %d matching logs, want %d", native.name(), len(wantMatched), native.Q)
				}
				resolved, rangeEntries, err := fixture.resolveLocator(context.Background(), native)
				if err != nil {
					b.Fatal(err)
				}
				if rangeEntries != wantRange {
					b.Fatalf("%s: ALL range has %d entries, the dataset %d", native.name(), rangeEntries, wantRange)
				}
				for _, address := range resolved {
					ordinal, ok := forest.layout.ordinal(address)
					if !ok || !wantMatched[ordinal] {
						b.Fatalf("%s: ALL returned %+v, which the query does not select", native.name(), address)
					}
				}
				fairHMFValidRange[native.name()] = rangeEntries
			}
			rangeEntries := fairHMFValidRange[native.name()]
			reference, err := fixture.verifyWorkload(context.Background(), native)
			if err != nil {
				b.Fatal(err)
			}
			warmup := fairHMFWarmupCount(b)
			for range warmup {
				result, err := fixture.verifyWorkload(context.Background(), native)
				if err != nil {
					b.Fatal(err)
				}
				fairHMFResult = result.CalculatedGlobalRoot
			}
			b.ResetTimer()
			b.ReportMetric(float64(native.Q), "records/op")
			b.ReportMetric(float64(len(reference.Proof.Leaves)), "proof-leaves/op")
			b.ReportMetric(float64(len(reference.Proof.Nodes)), "proof-nodes/op")
			b.ReportMetric(1, "postgres-batches/op")
			b.ReportMetric(1, "all-queries/op")
			b.ReportMetric(float64(rangeEntries), "all-entries/op")
			b.ReportMetric(float64(native.Q), "all-result-entries/op")
			b.ReportMetric(fairNativeWorkloadVersion, "workload-version/op")
			b.ReportMetric(1, "cassandra-proof-builds/op")
			b.ReportMetric(float64(fixture.hppConcurrency), "hpp-concurrency/op")
			b.ReportMetric(float64(warmup), "warmup-ops")
			for range b.N {
				result, err := fixture.verifyWorkload(context.Background(), native)
				if err != nil {
					b.Fatal(err)
				}
				fairHMFResult = result.CalculatedGlobalRoot
			}
		})
	}
}

func BenchmarkFairHMFLocalizationAfterMismatch(b *testing.B) {
	fixture := sharedFairHMFFixture(b)
	forest := fixture.forest
	for _, placement := range fairBenchmarkPlacements {
		for _, batchSize := range fairHMFRequestCounts {
			b.Run(fmt.Sprintf("%s/q=%d", placement, batchSize), func(b *testing.B) {
				addresses, err := forest.addresses(placement, batchSize)
				if err != nil {
					b.Fatal(err)
				}
				if err := fixture.setTampered(context.Background(), addresses[len(addresses)/2]); err != nil {
					b.Fatal(err)
				}
				localized, err := fixture.localize(context.Background(), addresses)
				if err != nil {
					b.Fatal(err)
				}
				warmup := fairHMFWarmupCount(b)
				for range warmup {
					result, err := fixture.localize(context.Background(), addresses)
					if err != nil {
						b.Fatal(err)
					}
					fairHMFResult = result.CalculatedReferenceRoot
				}
				b.ResetTimer()
				b.ReportMetric(float64(batchSize), "records/op")
				b.ReportMetric(float64(len(localized.Proof.Rounds)), "pruning-rounds/op")
				b.ReportMetric(float64(len(localized.Proof.Suspects)), "suspects/op")
				b.ReportMetric(1, "tampered-records/op")
				b.ReportMetric(1, "postgres-batches/op")
				b.ReportMetric(1, "cassandra-proof-builds/op")
				b.ReportMetric(1, "cassandra-reference-leaf-fetches/op")
				b.ReportMetric(float64(fixture.hppConcurrency), "hpp-concurrency/op")
				b.ReportMetric(float64(warmup), "warmup-ops")
				for range b.N {
					result, err := fixture.localize(context.Background(), addresses)
					if err != nil {
						b.Fatal(err)
					}
					fairHMFResult = result.CalculatedReferenceRoot
				}
			})
		}
	}
	if err := fixture.clearTamper(context.Background()); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkFairHMFTamperCountLocalization holds the requested batch at 2^14
// and varies the number of persistently tampered requested logs from 1 to 256.
func BenchmarkFairHMFTamperCountLocalization(b *testing.B) {
	fixture := sharedFairHMFFixture(b)
	forest := fixture.forest
	for _, placement := range fairBenchmarkPlacements {
		addresses, err := forest.addresses(placement, fairLocalizationFixedBatchSize)
		if err != nil {
			b.Fatal(err)
		}
		for _, tamperCount := range fairLocalizationTamperCounts {
			b.Run(fmt.Sprintf("%s/q=%d/tampered=%d", placement,
				fairLocalizationFixedBatchSize, tamperCount), func(b *testing.B) {
				tampered, err := fairTamperedAddresses(addresses, tamperCount)
				if err != nil {
					b.Fatal(err)
				}
				if err := fixture.setTamperedMany(context.Background(), tampered); err != nil {
					b.Fatal(err)
				}
				localized, err := fixture.localize(context.Background(), addresses)
				if err != nil {
					b.Fatal(err)
				}
				remaining := make(map[hpp.PhysicalAddress]struct{}, len(tampered))
				for _, address := range tampered {
					remaining[address] = struct{}{}
				}
				for _, suspect := range localized.Proof.Suspects {
					if suspect.Address == nil {
						b.Fatalf("localized non-leaf suspect %+v", suspect)
					}
					if _, ok := remaining[*suspect.Address]; !ok {
						b.Fatalf("localized unexpected or duplicate suspect %+v", *suspect.Address)
					}
					delete(remaining, *suspect.Address)
				}
				if len(remaining) != 0 {
					b.Fatalf("localization missed %d of %d tampered logs", len(remaining), tamperCount)
				}
				warmup := fairHMFWarmupCount(b)
				for range warmup {
					result, err := fixture.localize(context.Background(), addresses)
					if err != nil {
						b.Fatal(err)
					}
					fairHMFResult = result.CalculatedReferenceRoot
				}
				b.ResetTimer()
				b.ReportMetric(float64(fairLocalizationFixedBatchSize), "records/op")
				b.ReportMetric(float64(tamperCount), "tampered-records/op")
				b.ReportMetric(float64(len(localized.Proof.Rounds)), "pruning-rounds/op")
				b.ReportMetric(float64(len(localized.Proof.Suspects)), "suspects/op")
				b.ReportMetric(1, "postgres-batches/op")
				b.ReportMetric(1, "cassandra-proof-builds/op")
				b.ReportMetric(1, "cassandra-reference-leaf-fetches/op")
				b.ReportMetric(float64(fixture.hppConcurrency), "hpp-concurrency/op")
				b.ReportMetric(float64(warmup), "warmup-ops")
				for range b.N {
					result, err := fixture.localize(context.Background(), addresses)
					if err != nil {
						b.Fatal(err)
					}
					fairHMFResult = result.CalculatedReferenceRoot
				}
			})
		}
	}
	if err := fixture.clearTamper(context.Background()); err != nil {
		b.Fatal(err)
	}
}

// fairTamperedAddresses selects the center of each equal-width stratum. One
// tamper remains the existing midpoint rule; larger sets are evenly spread.
func fairTamperedAddresses(addresses []hpp.PhysicalAddress,
	tamperCount int) ([]hpp.PhysicalAddress, error) {
	if tamperCount <= 0 || tamperCount > len(addresses) {
		return nil, fmt.Errorf("tamper count %d must be between 1 and batch size %d",
			tamperCount, len(addresses))
	}
	result := make([]hpp.PhysicalAddress, tamperCount)
	for index := range tamperCount {
		offset := (2*index + 1) * len(addresses) / (2 * tamperCount)
		result[index] = addresses[offset]
	}
	return result, nil
}

func fairHMFWarmupCount(b testing.TB) int {
	b.Helper()
	value := os.Getenv("FAIR_WARMUP")
	if value == "" {
		return 0
	}
	count, err := strconv.Atoi(value)
	if err != nil || count < 0 {
		b.Fatalf("invalid FAIR_WARMUP %q", value)
	}
	return count
}
