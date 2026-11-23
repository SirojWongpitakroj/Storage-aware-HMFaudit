package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/benchmarks/exp2b"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
	cassandrastore "github.com/SirojWongpitakroj/hmf-audit/internal/storage/cassandra"
)

// exp2bLayout exposes a fairLayout's segments to the Experiment 2B manifests, in
// ascending ordinal order.
func exp2bLayout(layout *fairLayout) (*exp2b.Layout, error) {
	var spans []exp2b.SegmentSpan
	for region := range layout.sizes {
		for shard := range layout.shardsPerRegion {
			offset, size := layout.shard(region, shard)
			for segment := 0; segment*layout.segmentLeaves < size; segment++ {
				leaves := min(layout.segmentLeaves, size-segment*layout.segmentLeaves)
				spans = append(spans, exp2b.SegmentSpan{
					Region: fmt.Sprintf("R%d", region), Shard: int64(shard), Segment: int64(segment),
					First: layout.starts[region] + offset + segment*layout.segmentLeaves, Leaves: leaves,
				})
			}
		}
	}
	return exp2b.NewLayout(spans)
}

func exp2bAddresses(layout *fairLayout, ordinals []int) ([]hpp.PhysicalAddress, error) {
	addresses := make([]hpp.PhysicalAddress, len(ordinals))
	for index, ordinal := range ordinals {
		if ordinal < 0 || ordinal >= layout.total() {
			return nil, fmt.Errorf("ordinal %d is outside the %d-record layout", ordinal, layout.total())
		}
		addresses[index] = layout.address(ordinal)
	}
	return addresses, nil
}

// exp2bFixedKappa is the fixed-depth jump size the production service accepts.
// Experiment 2B specifies kappa = 16, but Service.Localize and VerifyProof both
// require the request's K to be 0 or DefaultJumpLevels (63); the comparison is
// kept honest by running the existing fixed-depth strategy as it is and
// recording the requested and the effective kappa in run_config.json.
const (
	exp2bFixedKappaRequested int32 = 16
	exp2bFixedKappaEffective       = localization.DefaultJumpLevels
)

// exp2bAlgorithm builds one measured algorithm over a reference store.
func exp2bAlgorithm(name string, strategy localization.Strategy, metadata hpp.MetadataReader,
	nodes hpp.ProofNodeReader) (exp2b.Algorithm, error) {
	measured := &exp2b.MeasuredReader{Metadata: metadata, Nodes: nodes}
	service, err := hpp.NewService(measured, measured)
	if err != nil {
		return exp2b.Algorithm{}, err
	}
	localizer, err := localization.NewService(service,
		localization.WithStrategy(strategy), localization.WithACHPConfig(localization.DefaultACHPConfig()))
	if err != nil {
		return exp2b.Algorithm{}, err
	}
	return exp2b.Algorithm{Name: name, Requested: strategy, Service: localizer, Reader: measured}, nil
}

// requestNodeReader answers plans in either of the two forms the services send:
// the legacy plan (trees and addresses) and explicit node requests (ACHP).
type requestNodeReader struct{ trees map[hpp.TreeRef]treeData }

func (reader requestNodeReader) FetchProofNodes(ctx context.Context, plan hpp.ProofPlan) ([]hpp.ProofNode, error) {
	if len(plan.Trees) > 0 || len(plan.Addresses) > 0 {
		return syntheticNodeReader{trees: reader.trees}.FetchProofNodes(ctx, plan)
	}
	var nodes []hpp.ProofNode
	add := func(tree hpp.TreeRef, level int32, indexes []int64) error {
		data, ok := reader.trees[tree]
		if !ok {
			return fmt.Errorf("synthetic tree %+v is missing", tree)
		}
		for _, index := range indexes {
			position := hpp.NodePosition{Level: level, Index: index}
			hash, err := data.node(position)
			if err != nil {
				return err
			}
			nodes = append(nodes, hpp.ProofNode{Ref: hpp.NodeRef{Tree: tree, Position: position}, Hash: hash})
		}
		return nil
	}
	for _, request := range plan.SegmentRequests {
		if err := add(request.Tree, request.Level, request.NodeIndexes); err != nil {
			return nil, err
		}
	}
	for _, request := range plan.UpperRequests {
		if err := add(request.Tree, request.Level, request.NodeIndexes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// memoryExp2BEnv is the dry-run environment: an in-memory forest whose reference
// store is the forest itself and whose auditor evidence differs from it in
// exactly the injected leaves.
type memoryExp2BEnv struct {
	forest   *syntheticForest
	layout   *fairLayout
	injected map[hpp.PhysicalAddress]struct{}
	// extra, when set, corrupts these ordinals in addition to the requested ones
	// (a deliberately wrong environment, for the correctness tests).
	extra []int
}

func newMemoryExp2BEnv(regionSizes []int, segmentLeaves int) (*memoryExp2BEnv, error) {
	layout, err := newFairLayout(regionSizes, 1, segmentLeaves)
	if err != nil {
		return nil, err
	}
	leaves := make([][32]byte, layout.total())
	for ordinal := range leaves {
		var input [16]byte
		copy(input[:8], "EXP2B")
		binary.BigEndian.PutUint64(input[8:], uint64(ordinal))
		leaves[ordinal] = sha256.Sum256(input[:])
	}
	forest, err := newFairForest(layout, leaves)
	if err != nil {
		return nil, err
	}
	return &memoryExp2BEnv{forest: forest, layout: layout}, nil
}

func (env *memoryExp2BEnv) Addresses(ordinals []int) ([]hpp.PhysicalAddress, error) {
	return exp2bAddresses(env.layout, ordinals)
}

func (env *memoryExp2BEnv) Inject(_ context.Context, ordinals []int) error {
	addresses, err := env.Addresses(append(append([]int(nil), ordinals...), env.extra...))
	if err != nil {
		return err
	}
	env.injected = make(map[hpp.PhysicalAddress]struct{}, len(addresses))
	for _, address := range addresses {
		env.injected[address] = struct{}{}
	}
	return nil
}

func (env *memoryExp2BEnv) Restore(context.Context) error {
	env.injected = nil
	return nil
}

func (env *memoryExp2BEnv) FailedProof(ctx context.Context, addresses []hpp.PhysicalAddress) (hpp.HMFProof, [32]byte, error) {
	proof, err := env.forest.service.BuildProof(ctx, addresses)
	if err != nil {
		return hpp.HMFProof{}, [32]byte{}, err
	}
	for index := range proof.Leaves {
		if _, corrupted := env.injected[proof.Leaves[index].Address]; corrupted {
			proof.Leaves[index].Hash[0] ^= 0xff
		}
	}
	root, err := hpp.VerifyHMFProof(proof, addresses)
	return proof, root, err
}

func (env *memoryExp2BEnv) TrustedRoot() [32]byte { return env.forest.root }

// algorithms returns the compared strategies over the forest.
func (env *memoryExp2BEnv) algorithms() ([]exp2b.Algorithm, error) {
	reader := requestNodeReader{trees: env.forest.trees}
	metadata := syntheticMetadataReader{metadata: env.forest.metadata}
	var algorithms []exp2b.Algorithm
	for _, spec := range []struct {
		name     string
		strategy localization.Strategy
	}{{"ACHP", localization.StrategyACHP}, {"FIXED", localization.StrategyFixedDepth}} {
		algorithm, err := exp2bAlgorithm(spec.name, spec.strategy, metadata, reader)
		if err != nil {
			return nil, err
		}
		algorithms = append(algorithms, algorithm)
	}
	return algorithms, nil
}

// persistentExp2BEnv is the cloud environment: corruption is a persistent change to
// the auditor's PostgreSQL ciphertext, the failed proof is the auditor's evidence
// from PostgreSQL and Cassandra, and localization reads the reference from
// Cassandra.
type persistentExp2BEnv struct {
	fixture *persistentFairHMFFixture
}

func (env persistentExp2BEnv) Addresses(ordinals []int) ([]hpp.PhysicalAddress, error) {
	return exp2bAddresses(env.fixture.forest.layout, ordinals)
}

func (env persistentExp2BEnv) Inject(ctx context.Context, ordinals []int) error {
	addresses, err := env.Addresses(ordinals)
	if err != nil {
		return err
	}
	return env.fixture.setTamperedMany(ctx, addresses)
}

func (env persistentExp2BEnv) Restore(ctx context.Context) error { return env.fixture.clearTamper(ctx) }

func (env persistentExp2BEnv) FailedProof(ctx context.Context, addresses []hpp.PhysicalAddress) (hpp.HMFProof, [32]byte, error) {
	return env.fixture.currentProof(ctx, addresses)
}

func (env persistentExp2BEnv) TrustedRoot() [32]byte { return env.fixture.trustedRoot }

func (env persistentExp2BEnv) algorithms() ([]exp2b.Algorithm, error) {
	var algorithms []exp2b.Algorithm
	for _, spec := range []struct {
		name     string
		strategy localization.Strategy
	}{{"ACHP", localization.StrategyACHP}, {"FIXED", localization.StrategyFixedDepth}} {
		// One Cassandra reader per algorithm: its ReadStats and the counting
		// wrapper then belong to that algorithm alone.
		reader, err := cassandrastore.NewHPPReader(env.fixture.cassandra, env.fixture.hppConcurrency)
		if err != nil {
			return nil, err
		}
		algorithm, err := exp2bAlgorithm(spec.name, spec.strategy, reader, reader)
		if err != nil {
			return nil, err
		}
		algorithm.ResetObserved = func() { reader.Stats = &cassandrastore.ReadStats{} }
		algorithm.ObservedReads = func() int64 {
			reads, _, _, _ := reader.Stats.Snapshot()
			return reads
		}
		algorithms = append(algorithms, algorithm)
	}
	return algorithms, nil
}

// exp2bGitCommit is the commit of the code under test: FAIR_GIT_COMMIT when the
// runner sets it, otherwise the checkout's HEAD.
func exp2bGitCommit() string {
	if commit := os.Getenv("FAIR_GIT_COMMIT"); commit != "" {
		return commit
	}
	output, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

// exp2bRunConfig fills run_config.json.
func exp2bRunConfig(mode string, params exp2b.Params, queries exp2b.QueryManifest, layout *exp2b.Layout,
	algorithms []string, hppConcurrency int, verify bool) exp2b.RunConfig {
	env := map[string]string{}
	for _, name := range []string{"FAIR_CLOUD", "FAIR_HMF_HPP_CONCURRENCY", "FAIR_HMF_SHARDS_PER_REGION",
		"FAIR_HMF_SEGMENT_LEAVES", "GOMAXPROCS", "FAIR_CASSANDRA_HOST", "FAIR_QUERY_SET"} {
		if value := os.Getenv(name); value != "" {
			env[name] = value
		}
	}
	return exp2b.RunConfig{
		Experiment: "exp2b", Mode: mode, GitCommit: exp2bGitCommit(), GoVersion: runtime.Version(),
		GOMAXPROCS: runtime.GOMAXPROCS(0), StartedAt: time.Now().UTC().Format(time.RFC3339),
		Params: params, Algorithms: algorithms,
		Excluded: []string{"EVSEB"}, ExcludedReason: "EVSEB's localization is one operation that loads the stored tree " +
			"from PostgreSQL and the Cassandra DHT, recomputes the root and localizes; it has no post-mismatch phase " +
			"to time separately and no Cassandra partition reads or retrieval rounds to compare. It identifies " +
			"every corrupted record (the candidates it does not verify), but it is not implemented against " +
			"these manifests, so 2B reports no EVSEB rows",
		FixedKappa: exp2bFixedKappaEffective, FixedKappaWanted: exp2bFixedKappaRequested,
		KappaNote: "the production fixed-depth localization accepts only K = 63 (one round from each tree's root to " +
			"its leaves); kappa = 16 is rejected by Service.Localize and VerifyProof, so the existing fixed-depth " +
			"strategy ran unchanged",
		ACHP: exp2b.CoefficientsOf(localization.DefaultACHPConfig()), HPPConcurrency: hppConcurrency,
		VerifyProofs: verify, LayoutSHA256: layout.Hash(), QueriesSHA256: queries.Hash(),
		Dataset: os.Getenv("FAIR_DATASET_PATH"), Environment: env,
		Notes: []string{
			"Timed operation: Service.Localize only. Query construction, corruption injection, the failed proof " +
				"(initial batch verification), proof replay and restoration are outside it.",
			"The fixed-depth reference-proof retrieval is inside Localize and is counted in the reads.",
			"partition_reads counts partition queries from the request plans (failed calls included); " +
				"cassandra_reads_observed is the Cassandra reader's own count of successful partition queries; " +
				"driver-internal retries are not observable.",
			"evidence_bytes counts 32 bytes per retrieved node.",
			"The queries are the manifest's ordinals; ALL query resolution and the blockchain checkpoint " +
				"fetch are excluded, the trusted root is the fixture's anchored root.",
			"Algorithm order rotates from case to case; no caches are flushed between runs.",
		},
	}
}
