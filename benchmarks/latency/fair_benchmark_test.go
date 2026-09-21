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

var fairHMFRequestCounts = []int{1, 16, 64, 256, 1024, 4096, 16384}
var fairLocalizationTamperCounts = []int{1, 2, 4, 8, 16, 32, 64, 128, 256}

const fairLocalizationFixedBatchSize = 1 << 14

type fairHMFRecord struct {
	RawLog   string `json:"raw_log"`
	RegionID string `json:"region_id"`
	SourceID string `json:"source_id"`
	TenantID string `json:"tenant_id"`
}

func BenchmarkFairHMFVerificationCore(b *testing.B) {
	fixture := sharedFairHMFFixture(b)
	forest := fixture.forest
	for _, placement := range fairBenchmarkPlacements {
		for _, batchSize := range fairHMFRequestCounts {
			b.Run(fmt.Sprintf("%s/q=%d", placement, batchSize), func(b *testing.B) {
				addresses, err := forest.addresses(placement, batchSize)
				if err != nil {
					b.Fatal(err)
				}
				reference, err := fixture.verify(context.Background(), addresses)
				if err != nil {
					b.Fatal(err)
				}
				warmup := fairHMFWarmupCount(b)
				for range warmup {
					result, err := fixture.verify(context.Background(), addresses)
					if err != nil {
						b.Fatal(err)
					}
					fairHMFResult = result.CalculatedGlobalRoot
				}
				b.ResetTimer()
				b.ReportMetric(float64(batchSize), "records/op")
				b.ReportMetric(float64(len(reference.Proof.Leaves)), "proof-leaves/op")
				b.ReportMetric(float64(len(reference.Proof.Nodes)), "proof-nodes/op")
				b.ReportMetric(1, "postgres-batches/op")
				b.ReportMetric(1, "cassandra-proof-builds/op")
				b.ReportMetric(float64(fixture.hppConcurrency), "hpp-concurrency/op")
				b.ReportMetric(float64(warmup), "warmup-ops")
				for range b.N {
					result, err := fixture.verify(context.Background(), addresses)
					if err != nil {
						b.Fatal(err)
					}
					fairHMFResult = result.CalculatedGlobalRoot
				}
			})
		}
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
				if len(localized.Proof.Suspects) != tamperCount {
					b.Fatalf("localized %d suspects, want %d", len(localized.Proof.Suspects), tamperCount)
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
