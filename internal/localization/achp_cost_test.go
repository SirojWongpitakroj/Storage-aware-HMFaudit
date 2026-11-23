package localization

import (
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// skewedSegment is one 64-leaf segment tree whose requested leaves are dense in
// the left half (32 of them) and sparse in the right (one).
func skewedSegment(t testing.TB) (*structure, task) {
	t.Helper()
	spec := forestSpec{regions: 1, shardsPerRegion: 1,
		segments: func(int, int) int { return 1 },
		leaves:   func(int, int, int) int { return 64 }}
	f := buildForest(t, spec)
	addresses := append([]hpp.PhysicalAddress(nil), f.addresses[:32]...)
	addresses = append(addresses, f.addresses[40])
	sc := newScenario(t, f, addresses, addresses[5:6])
	s := mustStructure(t, sc)
	tree := hpp.TreeRef{Layer: hpp.LayerSegment, RegionID: "R0"}
	return s, task{tree: tree, node: s.trees[tree].top(), rootCommit: true}
}

func modelFor(s *structure, mutate func(*ACHPConfig)) (*costModel, *candidateGenerator) {
	config := DefaultACHPConfig()
	if mutate != nil {
		mutate(&config)
	}
	model := newCostModel(config, newEstimator(config), s)
	return model, &candidateGenerator{structure: s, model: model, limit: config.MaxCandidates}
}

// branchDepths counts the expanded nodes under each child of the task's node.
func branchDepths(plan taskPlan) (left, right int) {
	topLevel := plan.task.node.Level
	for _, position := range plan.expanded {
		if position.Level == topLevel {
			continue
		}
		if position.Index>>uint(position.Level-(topLevel-1)) == 0 {
			left++
		} else {
			right++
		}
	}
	return left, right
}

func TestFrontiersDescendDifferentDepthsInDifferentBranches(t *testing.T) {
	s, root := skewedSegment(t)
	info := s.trees[root.tree]
	_, generator := modelFor(s, nil)
	plan := generator.greedy([]task{root}).plans[0]
	left, right := branchDepths(plan)
	if left <= right || right > 1 {
		t.Fatalf("expanded %d nodes in the dense branch and %d in the sparse one; want the dense branch descended much further", left, right)
	}
	// The frontier is valid: it is derived from the expanded set.
	frontier, ok := info.frontierOf(root.node, plan.expanded)
	if !ok || !reflect.DeepEqual(frontier, plan.frontier) {
		t.Fatalf("frontier %v is not derived from the expanded set %v", plan.frontier, plan.expanded)
	}
}

func TestCostlierRoundsDescendDeeper(t *testing.T) {
	s, root := skewedSegment(t)
	depth := func(mutate func(*ACHPConfig)) int {
		model, generator := modelFor(s, mutate)
		best, _, ok := selectFrontier(generator.generate([]task{root}), model)
		if !ok {
			t.Fatal("no frontier selected")
		}
		return len(best.plans[0].expanded)
	}
	free := depth(func(c *ACHPConfig) { c.Costs.NetworkRTT = 0; c.Costs.PartitionAccess = 0 })
	slow := depth(func(c *ACHPConfig) { c.Costs.NetworkRTT = time.Second })
	if free >= slow {
		t.Fatalf("expanded %d nodes with free rounds and %d with one-second rounds; slow rounds must descend further", free, slow)
	}
}

func TestFrontierGenerationIsDeterministicAndBounded(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 80, 3, 1)
	sc := newScenario(t, f, addresses, addresses[:1])
	s := mustStructure(t, sc)
	var tasks []task
	for _, tree := range s.order {
		if tree.Layer == hpp.LayerSegment && s.trees[tree].descendable(s.trees[tree].top()) {
			tasks = append(tasks, task{tree: tree, node: s.trees[tree].top(), rootCommit: true})
		}
	}
	sortTasks(tasks)
	signatures := func(limit int) []string {
		_, generator := modelFor(s, func(c *ACHPConfig) { c.MaxCandidates = limit })
		var result []string
		for _, joint := range generator.generate(tasks) {
			result = append(result, joint.label+"|"+joint.signature())
		}
		return result
	}
	full := signatures(64)
	if !reflect.DeepEqual(full, signatures(64)) {
		t.Fatal("candidate enumeration is not deterministic")
	}
	if len(full) < 4 {
		t.Fatalf("only %d candidates for %d tasks", len(full), len(tasks))
	}
	seen := map[string]bool{}
	for _, entry := range full {
		signature := entry[strings.Index(entry, "|")+1:]
		if seen[signature] {
			t.Fatalf("duplicate candidate frontier %q", entry)
		}
		seen[signature] = true
	}
	for _, limit := range []int{1, 2, 5} {
		got := signatures(limit)
		if len(got) != limit || !reflect.DeepEqual(got, full[:limit]) {
			t.Fatalf("limit %d returned %d candidates, want the first %d in the same order", limit, len(got), limit)
		}
	}
	if !strings.HasPrefix(full[0], "greedy") {
		t.Fatalf("first candidate is %q, want the cost-guided frontier", full[0])
	}
}

func TestSelectionIsCostMinimalAndBreaksTiesDeterministically(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 60, 4, 2)
	sc := newScenario(t, f, addresses, addresses[:1])
	s := mustStructure(t, sc)
	var tasks []task
	for _, tree := range s.order {
		if tree.Layer == hpp.LayerRegion {
			tasks = append(tasks, task{tree: tree, node: s.trees[tree].top(), rootCommit: true})
		}
	}
	sortTasks(tasks)

	model, generator := modelFor(s, nil)
	candidates := generator.generate(tasks)
	best, cost, _ := selectFrontier(candidates, model)
	for _, candidate := range candidates {
		if other := model.estimate(candidate); other.Total < cost.Total {
			t.Fatalf("selected %s at %g although %s costs %g", best.label, cost.Total, candidate.label, other.Total)
		}
	}

	// With every cost zero all candidates tie: the fewest nodes win, then the
	// smaller signature, whatever order the candidates arrive in.
	flat, flatGenerator := modelFor(s, func(c *ACHPConfig) {
		c.Costs = CostCoefficients{Concurrency: 1, NetworkBytesPerSecond: 1}
	})
	tied := flatGenerator.generate(tasks)
	first, _, _ := selectFrontier(tied, flat)
	reversed := slices.Clone(tied)
	slices.Reverse(reversed)
	second, _, _ := selectFrontier(reversed, flat)
	if first.signature() != second.signature() {
		t.Fatalf("tie-break depends on candidate order: %s vs %s", first.label, second.label)
	}
	for _, candidate := range tied {
		if candidate.nodeCount(s) < first.nodeCount(s) {
			t.Fatalf("tie-break chose %d nodes although %s has %d", first.nodeCount(s), candidate.label, candidate.nodeCount(s))
		}
	}
	if _, _, ok := selectFrontier(nil, flat); ok {
		t.Fatal("a frontier was selected from no candidates")
	}
}

func TestPartitionAwareCostEstimation(t *testing.T) {
	config := DefaultACHPConfig()
	config.Costs.PartitionAccess = 10 * time.Millisecond
	config.Costs.RowRead = time.Millisecond
	partition := func(id int64) hpp.PartitionKey {
		return hpp.PartitionKey{Table: "upper", ScopeType: "SHARD", ScopeID: "R0:S0", BucketID: id}
	}
	io := func(concurrency int, rows map[hpp.PartitionKey]int) float64 {
		config.Costs.Concurrency = concurrency
		return newCostModel(config, newEstimator(config), &structure{}).partitionIO(rows)
	}
	near := func(got, want float64) bool { return math.Abs(got-want) < 1e-9 }

	one := map[hpp.PartitionKey]int{partition(0): 8}
	if got := io(4, one); !near(got, 0.010+8*0.001) {
		t.Fatalf("one partition of 8 rows costs %g, want one access plus eight rows", got)
	}
	four := map[hpp.PartitionKey]int{partition(0): 2, partition(1): 2, partition(2): 2, partition(3): 2}
	if got := io(1, four); !near(got, 4*(0.010+2*0.001)) {
		t.Fatalf("four partitions read serially cost %g, want four accesses and eight rows", got)
	}
	if got := io(4, four); !near(got, 0.010+2*0.001) {
		t.Fatalf("four partitions read in parallel cost %g, want the cost of one", got)
	}
	if got := io(2, four); !near(got, 2*(0.010+2*0.001)) {
		t.Fatalf("four partitions on two readers cost %g, want two waves", got)
	}
	// Longest-first scheduling: the 20-row partition runs alone while the two
	// small ones share the other reader.
	uneven := map[hpp.PartitionKey]int{partition(0): 20, partition(1): 1, partition(2): 1}
	if got := io(2, uneven); !near(got, 0.010+20*0.001) {
		t.Fatalf("uneven partitions cost %g, want the cost of the largest", got)
	}
	// The same rows cost more once split over more partitions than readers.
	if io(1, four) <= io(1, one) {
		t.Fatal("spreading rows over more partitions did not cost more")
	}
	// A larger retrieval scale scales I/O and network, never verification.
	config.Costs.Concurrency = 4
	model := newCostModel(config, newEstimator(config), &structure{})
	base, network, verify := model.partitionIO(one), model.networkCost(8), model.verificationCost(8, 8)
	model.estimator.retrievalScale = 3
	if !near(model.partitionIO(one), 3*base) || !near(model.networkCost(8), 3*network) ||
		!near(model.verificationCost(8, 8), verify) {
		t.Fatal("retrieval scale does not multiply exactly the retrieval terms")
	}
}

// The partition a node belongs to is the partition the reader queries, so two
// nodes of one segment (or one shard bucket) cost one access between them.
func TestPartitionMappingUsesHPPGrouping(t *testing.T) {
	segment := hpp.TreeRef{Layer: hpp.LayerSegment, RegionID: "R0", ShardID: 1, SegmentID: 2}
	a := hpp.PartitionOf(hpp.NodeRef{Tree: segment, Position: hpp.NodePosition{Level: 0, Index: 3}})
	b := hpp.PartitionOf(hpp.NodeRef{Tree: segment, Position: hpp.NodePosition{Level: 4, Index: 0}})
	other := hpp.PartitionOf(hpp.NodeRef{Tree: hpp.TreeRef{Layer: hpp.LayerSegment, RegionID: "R0", ShardID: 1, SegmentID: 3},
		Position: hpp.NodePosition{Level: 0, Index: 3}})
	if a != b || a == other {
		t.Fatal("segment nodes are not grouped by tree")
	}
	shard := hpp.TreeRef{Layer: hpp.LayerShard, RegionID: "R0", ShardID: 1}
	low := hpp.PartitionOf(hpp.NodeRef{Tree: shard, Position: hpp.NodePosition{Level: 0, Index: 5}})
	high := hpp.PartitionOf(hpp.NodeRef{Tree: shard, Position: hpp.NodePosition{Level: 0, Index: hpp.ShardNodesPerBucket + 5}})
	if low == high {
		t.Fatal("shard nodes of different buckets share a partition")
	}
}

func TestMismatchEstimateTracksObservations(t *testing.T) {
	config := DefaultACHPConfig()
	config.MismatchPrior = 1e-6 // small enough that conditional ≈ n/nRoot
	est := newEstimator(config)
	if got := est.conditional(8, 64); math.Abs(got-0.125) > 1e-3 {
		t.Fatalf("conditional(8,64) = %g, want ≈ 1/8", got)
	}
	if est.conditional(64, 64) != 1 || est.conditional(0, 64) != 0 || est.conditional(5, 0) != 0 {
		t.Fatal("conditional probability is wrong at its limits")
	}
	if !(est.conditional(1, 64) < est.conditional(8, 64) && est.conditional(8, 64) < est.conditional(32, 64)) {
		t.Fatal("conditional probability is not increasing in the leaves covered")
	}
	high := newEstimator(ACHPConfig{MismatchPrior: 0.5, PriorStrength: 1, Costs: config.Costs})
	if got := high.conditional(1, 64); math.Abs(got-0.5) > 1e-6 {
		t.Fatalf("with p0 = 0.5, conditional(1,64) = %g, want ≈ 0.5", got)
	}

	before := est.leafRate()
	est.observeRound(5000, 0, nil)
	cleaner := est.leafRate()
	est.observeRound(5000, 20, []int64{40, 40, 40})
	dirtier := est.leafRate()
	if !(cleaner < before) {
		t.Fatalf("observing 5000 clean leaves moved the rate %g -> %g, want a decrease", before, cleaner)
	}
	if !(dirtier > cleaner) {
		t.Fatalf("observing confirmed corruption moved the rate %g -> %g, want an increase", cleaner, dirtier)
	}

	// Retrieval calibration follows the observed/predicted ratio, within bounds.
	calibrated := newEstimator(config)
	calibrated.observeRetrieval(time.Millisecond, 4*time.Millisecond)
	if !(calibrated.retrievalScale > 1) {
		t.Fatalf("slower-than-predicted retrieval left the scale at %g", calibrated.retrievalScale)
	}
	for i := 0; i < 40; i++ {
		calibrated.observeRetrieval(time.Nanosecond, time.Hour)
	}
	if calibrated.retrievalScale > 16 {
		t.Fatalf("scale %g exceeds the clamp", calibrated.retrievalScale)
	}
	frozen := newEstimator(config)
	frozen.config.Costs.AdaptationRate = 0
	frozen.observeRetrieval(time.Millisecond, time.Second)
	zero := newEstimator(config)
	zero.observeRetrieval(0, time.Second)
	zero.observeRetrieval(time.Second, 0)
	if frozen.retrievalScale != 1 || zero.retrievalScale != 1 {
		t.Fatal("calibration moved although it was disabled or had nothing to compare")
	}
}

// Every round records the candidates costed and the cost of the frontier it
// retrieved, so a run can be inspected afterwards.
func TestRoundsRecordTheirCostEstimates(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 60, 4, 2)
	sc := newScenario(t, f, addresses, addresses[7:8])
	result := localizeOK(t, deterministicService(t, sc.hpp, nil), sc, StrategyACHP)
	rounds := result.Proof.ACHP.Rounds
	if len(rounds) < 3 {
		t.Fatalf("only %d rounds", len(rounds))
	}
	for index, round := range rounds {
		if round.Candidates < 1 || round.Chosen.Total <= 0 {
			t.Fatalf("round %d recorded %d candidates at cost %g", index+1, round.Candidates, round.Chosen.Total)
		}
		parts := round.Chosen.IO + round.Chosen.Network + round.Chosen.Verification + round.Chosen.Future
		if math.Abs(parts-round.Chosen.Total) > 1e-12 {
			t.Fatalf("round %d total %g is not the sum of its terms %g", index+1, round.Chosen.Total, parts)
		}
	}
}
