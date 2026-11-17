package main

// Component-ablation benchmark. Measures the individual latency contribution
// of three HMF-Audit optimizations -- shared-path/batch-aware proof planning,
// proof-node deduplication, and Cassandra partition-aware retrieval -- by
// running four pipeline variants (FULL, NO_SHARED_PLANNING, NO_DEDUP,
// NO_PARTITION_AWARE) over the exact same persisted 10M-record fixture,
// finalized checkpoint, and requested address batches used by
// BenchmarkFairHMFVerificationCore. It does not invoke tamper localization.
//
// Each variant isolates exactly one optimization relative to FULL, holding
// the other two on:
//   - NO_SHARED_PLANNING: shared/joint planning off, dedup on, retrieval
//     partition-aware (hpp.PlanIndependent(dedup=true)).
//   - NO_DEDUP: shared/joint planning ON (it reuses the canonical plan's own
//     minimal required-node set and per-node occurrence counts), dedup off,
//     retrieval partition-aware (hpp.ExpandRequiredWithOccurrences). A node
//     needed by more than one address is requested once per requesting
//     address instead of once, but the requested node SET is always exactly
//     canonical's minimal set -- never a genuinely unnecessary node, the way
//     NO_SHARED_PLANNING can produce. Because it reuses canonical's own
//     Required/RequiredOccurrences (both computed by the single joint
//     merge-walk in hpp.planTree that produces canonical itself), it costs no
//     extra tree traversal beyond FULL's own planning: no address's path is
//     ever re-derived, so this variant's planning-time delta over FULL
//     reflects dedup's toggle alone, not a second, independent-per-address
//     planning pass.
//   - NO_PARTITION_AWARE: shared/joint planning on, dedup on, retrieval
//     ungrouped (reader.FetchProofNodesUngrouped over the canonical plan).
//
// This factorial design lets NO_DEDUP vs FULL isolate dedup's cost alone,
// and NO_SHARED_PLANNING vs FULL isolate joint planning's benefit alone --
// unlike an earlier version of this benchmark, where NO_DEDUP was also
// derived from PlanIndependent and therefore always lacked shared planning
// too, and unlike a later, corrected-but-still-confounded version, whose
// NO_DEDUP variant (hpp.PlanSharedSansDedup) reused canonical's Required set
// but still re-derived every address's path independently to reconstruct
// occurrence counts, paying NO_SHARED_PLANNING's own per-address planning
// cost a second time.
//
// Run with: FAIR_PERSISTENCE=1 FAIR_ABLATION=1 go test ./benchmarks/latency \
//   -run TestFairHMFAblation -v -timeout 0
// (plus the same FAIR_* environment variables run-fair-benchmarks.ps1 sets).

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	cassandrastore "github.com/SirojWongpitakroj/hmf-audit/internal/storage/cassandra"
)

type ablationVariant string

const (
	variantFull             ablationVariant = "FULL"
	variantNoSharedPlanning ablationVariant = "NO_SHARED_PLANNING"
	variantNoDedup          ablationVariant = "NO_DEDUP"
	variantNoPartitionAware ablationVariant = "NO_PARTITION_AWARE"
)

var ablationVariants = []ablationVariant{variantFull, variantNoSharedPlanning, variantNoDedup, variantNoPartitionAware}

const (
	defaultAblationWarmup   = 5
	defaultAblationMeasured = 30
)

// ablationBatchSizes returns the protocol's q values (256, 1024, 4096,
// 16384), overridable via FAIR_ABLATION_BATCH_SIZES (comma-separated) for
// fast iteration against a small dataset during development.
func ablationBatchSizes(t *testing.T) []int {
	t.Helper()
	value := os.Getenv("FAIR_ABLATION_BATCH_SIZES")
	if value == "" {
		return []int{256, 1024, 4096, 16384}
	}
	var sizes []int
	for _, part := range splitCommaInts(t, value) {
		sizes = append(sizes, part)
	}
	return sizes
}

func splitCommaInts(t *testing.T, value string) []int {
	t.Helper()
	var result []int
	start := 0
	for i := 0; i <= len(value); i++ {
		if i == len(value) || value[i] == ',' {
			field := value[start:i]
			start = i + 1
			if field == "" {
				continue
			}
			parsed, err := strconv.Atoi(field)
			if err != nil {
				t.Fatalf("invalid FAIR_ABLATION_BATCH_SIZES entry %q: %v", field, err)
			}
			result = append(result, parsed)
		}
	}
	return result
}

func ablationRoundCount(t *testing.T, envName string, fallback int) int {
	t.Helper()
	value := os.Getenv(envName)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		t.Fatalf("invalid %s %q", envName, value)
	}
	return parsed
}

// ablationExecution is one end-to-end run of one variant: ALL resolution
// through finalized Global-Root verification, matching the timer boundaries
// of the existing verification benchmark (BenchmarkFairHMFVerificationCore).
type ablationExecution struct {
	latency time.Duration

	addresses []hpp.PhysicalAddress
	batchHash string
	requested map[hpp.NodeRef]struct{}
	leaves    map[hpp.PhysicalAddress][32]byte

	logicalProofNodes int
	uniqueProofNodes  int
	proofBytes        int

	cassandraReads         int64
	cassandraPartitions    int64
	cassandraRequestedKeys int64
	cassandraUniqueRows    int64
	postgresReads          int

	planning     time.Duration
	cassandraDur time.Duration
	postgresDur  time.Duration
	verification time.Duration

	verificationSuccess bool
	calculatedRoot      [32]byte
}

// runAblationOnce executes one variant's full pipeline once. For
// NO_SHARED_PLANNING, the retrieval requests come from hpp.PlanIndependent
// (which can request a superset of the canonical minimal node set -- see
// that function's doc comment). For NO_DEDUP, the retrieval requests come
// from hpp.ExpandRequiredWithOccurrences, which reuses canonical's own
// minimal required-node set and per-node occurrence counts (shared planning
// stays on, and no address's path is re-derived) but requests a node once per
// requesting address instead of once (dedup off) -- see that function's doc
// comment. The final verified proof always uses Planner.Plan's canonical
// Trees/ParentLinks/Required, exactly as any real system must to return a
// valid, non-bloated multiproof. For NO_PARTITION_AWARE, retrieval uses
// FetchProofNodesUngrouped over the same canonical SegmentRequests/
// UpperRequests FULL uses, so its requested node identities equal FULL's by
// construction (Check 6); only the retrieval method differs.
func runAblationOnce(ctx context.Context, fixture *persistentFairHMFFixture,
	reader *cassandrastore.HPPReader, variant ablationVariant,
	placement string, q int) (ablationExecution, error) {

	started := time.Now()
	addresses, err := fixture.resolveLocator(ctx, placement, q)
	if err != nil {
		return ablationExecution{}, fmt.Errorf("resolve locator: %w", err)
	}
	batchHash := computeBatchHash(addresses)

	planStart := time.Now()
	metadata, err := reader.LoadHierarchyMetadata(ctx, addresses)
	if err != nil {
		return ablationExecution{}, fmt.Errorf("load hierarchy metadata: %w", err)
	}

	canonical, err := hpp.NewPlanner().Plan(addresses, metadata)
	if err != nil {
		return ablationExecution{}, fmt.Errorf("canonical plan: %w", err)
	}

	var fetchSegmentRequests []hpp.SegmentRequest
	var fetchUpperRequests []hpp.UpperRequest
	switch variant {
	case variantFull, variantNoPartitionAware:
		fetchSegmentRequests, fetchUpperRequests = canonical.SegmentRequests, canonical.UpperRequests
	case variantNoSharedPlanning:
		result, err := hpp.PlanIndependent(addresses, metadata, true)
		if err != nil {
			return ablationExecution{}, fmt.Errorf("plan independent (dedup): %w", err)
		}
		fetchSegmentRequests, fetchUpperRequests = result.SegmentRequests, result.UpperRequests
	case variantNoDedup:
		result, err := hpp.ExpandRequiredWithOccurrences(canonical)
		if err != nil {
			return ablationExecution{}, fmt.Errorf("expand required with occurrences: %w", err)
		}
		fetchSegmentRequests, fetchUpperRequests = result.SegmentRequests, result.UpperRequests
	default:
		return ablationExecution{}, fmt.Errorf("unknown ablation variant %q", variant)
	}
	planningElapsed := time.Since(planStart)

	// Computed uniformly from the actual retrieval requests for every
	// variant (rather than trusting hpp.PlanIndependent's own counters,
	// which deliberately exclude target-leaf positions for its internal
	// sufficiency proof) so logical/unique counts are directly comparable
	// across FULL, NO_SHARED_PLANNING, NO_DEDUP, and NO_PARTITION_AWARE.
	logicalOccurrences := countRequestedNodes(fetchSegmentRequests, fetchUpperRequests)
	uniqueNodes := len(requestedNodeRefSet(fetchSegmentRequests, fetchUpperRequests))

	fetchPlan := hpp.ProofPlan{SegmentRequests: fetchSegmentRequests, UpperRequests: fetchUpperRequests}
	stats := &cassandrastore.ReadStats{}
	reader.Stats = stats

	// PostgreSQL log retrieval runs concurrently with Cassandra proof-node
	// retrieval, matching production's proofWithCurrentLogs, for every
	// variant equally.
	type logResult struct {
		hashes  map[hpp.PhysicalAddress][32]byte
		elapsed time.Duration
		err     error
	}
	logsChan := make(chan logResult, 1)
	go func() {
		pgStart := time.Now()
		hashes, err := fixture.currentLogHashes(ctx, addresses)
		logsChan <- logResult{hashes: hashes, elapsed: time.Since(pgStart), err: err}
	}()

	cassandraStart := time.Now()
	var fetchedNodes []hpp.ProofNode
	if variant == variantNoPartitionAware {
		fetchedNodes, err = reader.FetchProofNodesUngrouped(ctx, fetchPlan)
	} else {
		fetchedNodes, err = reader.FetchProofNodes(ctx, fetchPlan)
	}
	cassandraElapsed := time.Since(cassandraStart)
	if err != nil {
		return ablationExecution{}, fmt.Errorf("fetch proof nodes (%s): %w", variant, err)
	}

	logs := <-logsChan
	if logs.err != nil {
		return ablationExecution{}, fmt.Errorf("fetch current log hashes: %w", logs.err)
	}

	nodeMap := make(map[hpp.NodeRef][32]byte, len(fetchedNodes))
	requestedRefs := make(map[hpp.NodeRef]struct{}, len(fetchedNodes))
	for _, node := range fetchedNodes {
		nodeMap[node.Ref] = node.Hash
		requestedRefs[node.Ref] = struct{}{}
	}

	proof := hpp.HMFProof{Plan: hpp.ProofPlan{Addresses: canonical.Addresses, Trees: canonical.Trees, ParentLinks: canonical.ParentLinks}}
	for _, tree := range canonical.Trees {
		for _, position := range tree.Required {
			ref := hpp.NodeRef{Tree: tree.Tree, Position: position}
			hash, exists := nodeMap[ref]
			if !exists {
				return ablationExecution{}, fmt.Errorf("%s: canonically-required node %+v was not fetched", variant, ref)
			}
			proof.Nodes = append(proof.Nodes, hpp.ProofNode{Ref: ref, Hash: hash})
		}
	}
	for _, address := range canonical.Addresses {
		hash, exists := logs.hashes[address]
		if !exists {
			return ablationExecution{}, fmt.Errorf("%s: current log hash missing for address %+v", variant, address)
		}
		proof.Leaves = append(proof.Leaves, hpp.RequestedLeaf{Address: address, Hash: hash})
	}

	verifyStart := time.Now()
	calculatedRoot, verifyErr := hpp.VerifyHMFProofAgainstRoot(proof, addresses, fixture.trustedRoot)
	verifyElapsed := time.Since(verifyStart)

	reads, partitions, requestedKeys, uniqueRows := stats.Snapshot()
	return ablationExecution{
		latency:                time.Since(started),
		addresses:              addresses,
		batchHash:              batchHash,
		requested:              requestedRefs,
		leaves:                 logs.hashes,
		logicalProofNodes:      logicalOccurrences,
		uniqueProofNodes:       uniqueNodes,
		proofBytes:             32 * (len(proof.Nodes) + len(proof.Leaves)),
		cassandraReads:         reads,
		cassandraPartitions:    partitions,
		cassandraRequestedKeys: requestedKeys,
		cassandraUniqueRows:    uniqueRows,
		postgresReads:          len(addresses),
		planning:               planningElapsed,
		cassandraDur:           cassandraElapsed,
		postgresDur:            logs.elapsed,
		verification:           verifyElapsed,
		verificationSuccess:    verifyErr == nil && calculatedRoot == fixture.trustedRoot,
		calculatedRoot:         calculatedRoot,
	}, nil
}

// computeBatchHash returns a deterministic fingerprint of one resolved
// request batch, in resolution order. Every ablation variant for the same
// (placement, q) cell resolves the same deterministic ALL query, so all four
// variants' batch hashes must be identical -- validateCell asserts this
// explicitly, in addition to (not instead of) the address-by-address
// comparison addressesEqual already performs.
func computeBatchHash(addresses []hpp.PhysicalAddress) string {
	hasher := sha256.New()
	for _, address := range addresses {
		fmt.Fprintf(hasher, "%s|%d|%d|%d\n", address.RegionID, address.ShardID, address.SegmentID, address.LeafID)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func countRequestedNodes(segments []hpp.SegmentRequest, uppers []hpp.UpperRequest) int {
	total := 0
	for _, request := range segments {
		total += len(request.NodeIndexes)
	}
	for _, request := range uppers {
		total += len(request.NodeIndexes)
	}
	return total
}

func requestedNodeRefSet(segments []hpp.SegmentRequest, uppers []hpp.UpperRequest) map[hpp.NodeRef]struct{} {
	set := make(map[hpp.NodeRef]struct{}, countRequestedNodes(segments, uppers))
	for _, request := range segments {
		for _, index := range request.NodeIndexes {
			set[hpp.NodeRef{Tree: request.Tree, Position: hpp.NodePosition{Level: request.Level, Index: index}}] = struct{}{}
		}
	}
	for _, request := range uppers {
		for _, index := range request.NodeIndexes {
			set[hpp.NodeRef{Tree: request.Tree, Position: hpp.NodePosition{Level: request.Level, Index: index}}] = struct{}{}
		}
	}
	return set
}

func rotateVariants(order []ablationVariant, shift int) []ablationVariant {
	result := make([]ablationVariant, len(order))
	for i := range order {
		result[i] = order[(i+shift)%len(order)]
	}
	return result
}

func addressesEqual(left, right []hpp.PhysicalAddress) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// validateCell runs the ablation protocol's Checks 1-4, 6, and 9 once per
// (placement, q) cell before any measured execution: identical requested
// addresses (Check 1), identical resulting PostgreSQL records (Check 3),
// identical finalized root across variants (Check 4), and identical unique
// authentication-node identities between FULL and each of NO_PARTITION_AWARE
// (Check 6) and NO_DEDUP (Check 9 -- confirms NO_DEDUP truly keeps shared
// planning on, per hpp.ExpandRequiredWithOccurrences). Check 2 (identical authenticated
// ALL result) follows directly from Check 1, since every variant resolves
// through the same ALL query against the same unchanging locator tree.
func validateCell(t *testing.T, ctx context.Context, fixture *persistentFairHMFFixture,
	reader *cassandrastore.HPPReader, placement string, q int) map[ablationVariant]ablationExecution {
	t.Helper()

	results := make(map[ablationVariant]ablationExecution, len(ablationVariants))
	for _, variant := range ablationVariants {
		result, err := runAblationOnce(ctx, fixture, reader, variant, placement, q)
		if err != nil {
			t.Fatalf("%s/q=%d: validate %s: %v", placement, q, variant, err)
		}
		if !result.verificationSuccess {
			t.Fatalf("CHECK 5 failed: %s/q=%d: %s did not verify (root=%x, want %x)",
				placement, q, variant, result.calculatedRoot, fixture.trustedRoot)
		}
		results[variant] = result
	}

	full := results[variantFull]
	for _, variant := range ablationVariants[1:] {
		other := results[variant]
		if !addressesEqual(full.addresses, other.addresses) {
			t.Fatalf("CHECK 1 failed: %s/q=%d: %s requested different addresses than FULL", placement, q, variant)
		}
		if full.batchHash != other.batchHash {
			t.Fatalf("CHECK A failed: %s/q=%d: %s batch_hash=%s, want FULL's %s",
				placement, q, variant, other.batchHash, full.batchHash)
		}
		if len(full.leaves) != len(other.leaves) {
			t.Fatalf("CHECK 3 failed: %s/q=%d: %s fetched %d PostgreSQL records, FULL fetched %d",
				placement, q, variant, len(other.leaves), len(full.leaves))
		}
		for address, hash := range full.leaves {
			if other.leaves[address] != hash {
				t.Fatalf("CHECK 3 failed: %s/q=%d: %s fetched a different record for address %+v",
					placement, q, variant, address)
			}
		}
		if full.calculatedRoot != other.calculatedRoot {
			t.Fatalf("CHECK 4 failed: %s/q=%d: %s calculated root %x, FULL calculated %x",
				placement, q, variant, other.calculatedRoot, full.calculatedRoot)
		}
	}

	noPartition := results[variantNoPartitionAware]
	if len(full.requested) != len(noPartition.requested) {
		t.Fatalf("CHECK 6 failed: %s/q=%d: FULL requested %d unique nodes, NO_PARTITION_AWARE requested %d",
			placement, q, len(full.requested), len(noPartition.requested))
	}
	for ref := range full.requested {
		if _, exists := noPartition.requested[ref]; !exists {
			t.Fatalf("CHECK 6 failed: %s/q=%d: NO_PARTITION_AWARE did not request node %+v that FULL requested",
				placement, q, ref)
		}
	}

	noDedup := results[variantNoDedup]
	if noDedup.logicalProofNodes < noDedup.uniqueProofNodes {
		t.Fatalf("CHECK 8 failed: %s/q=%d: NO_DEDUP logical occurrences (%d) < unique nodes (%d)",
			placement, q, noDedup.logicalProofNodes, noDedup.uniqueProofNodes)
	}
	if len(full.requested) != len(noDedup.requested) {
		t.Fatalf("CHECK 9 failed: %s/q=%d: FULL requested %d unique nodes, NO_DEDUP requested %d",
			placement, q, len(full.requested), len(noDedup.requested))
	}
	for ref := range full.requested {
		if _, exists := noDedup.requested[ref]; !exists {
			t.Fatalf("CHECK 9 failed: %s/q=%d: NO_DEDUP did not request node %+v that FULL requested",
				placement, q, ref)
		}
	}

	noShared := results[variantNoSharedPlanning]
	matchNote := "matches FULL exactly"
	if noShared.uniqueProofNodes != full.uniqueProofNodes {
		matchNote = fmt.Sprintf("differs from FULL by %+d nodes (independent-per-address derivation cannot recognize "+
			"an ancestor/descendant relationship between two addresses' required paths the way joint planning does; "+
			"see hpp.PlanIndependent's doc comment) -- CHECK 7 expects this is possible, not necessarily equal",
			noShared.uniqueProofNodes-full.uniqueProofNodes)
	}
	t.Logf("%s/q=%d: validated. unique nodes FULL=%d NO_SHARED=%d (%s) NO_DEDUP=%d(logical=%d) NO_PARTITION=%d",
		placement, q, full.uniqueProofNodes, noShared.uniqueProofNodes, matchNote,
		noDedup.uniqueProofNodes, noDedup.logicalProofNodes, noPartition.uniqueProofNodes)
	return results
}

func TestFairHMFAblation(t *testing.T) {
	if os.Getenv("FAIR_PERSISTENCE") != "1" {
		t.Skip("FAIR_PERSISTENCE=1 is required; use systems/run-fair-benchmarks.ps1's environment")
	}
	if os.Getenv("FAIR_ABLATION") != "1" {
		t.Skip("set FAIR_ABLATION=1 to run the component-ablation benchmark")
	}
	fixture := sharedFairHMFFixture(t)
	reader, err := cassandrastore.NewHPPReader(fixture.cassandra, fixture.hppConcurrency)
	if err != nil {
		t.Fatal(err)
	}

	sessionID, err := newAblationSessionID()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ablation session_id=%s", sessionID)

	outputDir := os.Getenv("FAIR_ABLATION_OUTPUT_DIR")
	if outputDir == "" {
		outputDir = "benchmarks/results"
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rawPath := filepath.Join(outputDir, "ablation_latency_raw.csv")
	file, err := os.Create(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err := writer.Write([]string{
		"session_id", "variant", "distribution", "q", "run", "is_warmup", "batch_hash", "latency_ms",
		"logical_proof_nodes", "unique_proof_nodes", "duplicate_proof_nodes", "proof_bytes",
		"cassandra_reads", "cassandra_partitions",
		"cassandra_requested_key_occurrences", "cassandra_unique_rows_returned",
		"postgres_reads",
		"planning_ms", "cassandra_ms", "postgres_ms", "verification_ms", "verification_success",
	}); err != nil {
		t.Fatal(err)
	}

	warmupRounds := ablationRoundCount(t, "FAIR_ABLATION_WARMUP", defaultAblationWarmup)
	measuredRounds := ablationRoundCount(t, "FAIR_ABLATION_MEASURED", defaultAblationMeasured)

	ctx := context.Background()
	for _, placement := range fairBenchmarkPlacements {
		for _, q := range ablationBatchSizes(t) {
			validateCell(t, ctx, fixture, reader, placement, q)

			measuredIndex := map[ablationVariant]int{}
			rounds := warmupRounds + measuredRounds
			for round := 0; round < rounds; round++ {
				isWarmup := round < warmupRounds
				for _, variant := range rotateVariants(ablationVariants, round%len(ablationVariants)) {
					result, err := runAblationOnce(ctx, fixture, reader, variant, placement, q)
					if err != nil {
						t.Fatalf("%s/q=%d round=%d: %s: %v", placement, q, round, variant, err)
					}
					if !isWarmup && !result.verificationSuccess {
						t.Fatalf("CHECK 5 failed: %s/q=%d: %s measured run did not verify", placement, q, variant)
					}
					run := -1
					if !isWarmup {
						run = measuredIndex[variant]
						measuredIndex[variant] = run + 1
					}
					if err := writeAblationRow(writer, sessionID, variant, placement, q, run, isWarmup, result); err != nil {
						t.Fatal(err)
					}
				}
			}
			writer.Flush()
			if err := writer.Error(); err != nil {
				t.Fatal(err)
			}
			t.Logf("%s/q=%d: %d measured executions per variant complete", placement, q, measuredRounds)
		}
	}
	t.Logf("ablation raw results written to %s", rawPath)
}

func writeAblationRow(writer *csv.Writer, sessionID string, variant ablationVariant, placement string, q, run int,
	isWarmup bool, result ablationExecution) error {

	return writer.Write([]string{
		sessionID,
		string(variant),
		placement,
		strconv.Itoa(q),
		strconv.Itoa(run),
		strconv.FormatBool(isWarmup),
		result.batchHash,
		formatMillis(result.latency),
		strconv.Itoa(result.logicalProofNodes),
		strconv.Itoa(result.uniqueProofNodes),
		strconv.Itoa(result.logicalProofNodes - result.uniqueProofNodes),
		strconv.Itoa(result.proofBytes),
		strconv.FormatInt(result.cassandraReads, 10),
		strconv.FormatInt(result.cassandraPartitions, 10),
		strconv.FormatInt(result.cassandraRequestedKeys, 10),
		strconv.FormatInt(result.cassandraUniqueRows, 10),
		strconv.Itoa(result.postgresReads),
		formatMillis(result.planning),
		formatMillis(result.cassandraDur),
		formatMillis(result.postgresDur),
		formatMillis(result.verification),
		strconv.FormatBool(result.verificationSuccess),
	})
}

// newAblationSessionID returns a fresh random identifier distinguishing one
// TestFairHMFAblation run from another, written into every CSV row so a
// later analysis can tell whether two rows came from the same benchmark
// session (relevant to comparing this ablation's FULL control against
// Experiment 1's own, session-dependent FULL numbers).
func newAblationSessionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := cryptorand.Read(buf); err != nil {
		return "", fmt.Errorf("generate ablation session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func formatMillis(d time.Duration) string {
	return fmt.Sprintf("%.6f", float64(d.Nanoseconds())/1e6)
}
