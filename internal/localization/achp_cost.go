package localization

import (
	"math"
	"sort"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// estimator keeps the mismatch and retrieval-cost estimates ACHP replans with.
// Every update comes from authenticated observations, and it only changes which
// frontier is costed cheapest, never which nodes are pruned.
type estimator struct {
	config ACHPConfig
	// cleanLeaves counts requested leaves proven to match (beneath pruned
	// nodes); confirmed counts leaves proven corrupted; pendingWeight and
	// pending describe the suspect branches still open, each of which holds at
	// least one corrupted leaf among its requested leaves.
	cleanLeaves   float64
	confirmed     float64
	pending       float64
	pendingWeight float64
	// retrievalScale multiplies the I/O and network estimates. It follows the
	// ratio of observed to predicted retrieval time.
	retrievalScale float64
}

func newEstimator(config ACHPConfig) *estimator {
	return &estimator{config: config, retrievalScale: 1}
}

// leafRate is the per-leaf corruption rate: p0, weighted by PriorStrength
// pseudo-leaves, updated by what the pruning has observed so far.
func (e *estimator) leafRate() float64 {
	prior, strength := e.config.MismatchPrior, e.config.PriorStrength
	rate := (prior*strength + e.confirmed + e.pending) /
		(strength + e.cleanLeaves + e.confirmed + e.pendingWeight)
	return math.Min(math.Max(rate, 1e-12), 1-1e-12)
}

// atLeastOne is the probability that a subtree of n requested leaves holds a
// corrupted leaf when each is corrupted independently with the given rate.
func atLeastOne(rate float64, n int64) float64 {
	return -math.Expm1(float64(n) * math.Log1p(-rate))
}

// conditional estimates p̂_u: the probability that a node covering nNode
// requested leaves differs, given that the suspect node it was reached from
// (covering nRoot leaves) does. For a small rate it tends to nNode/nRoot, the
// single-corruption answer; for a large one it tends to 1.
func (e *estimator) conditional(nNode, nRoot int64) float64 {
	if nNode <= 0 || nRoot <= 0 {
		return 0
	}
	if nNode >= nRoot {
		return 1
	}
	rate := e.leafRate()
	denominator := atLeastOne(rate, nRoot)
	if denominator <= 0 {
		return float64(nNode) / float64(nRoot)
	}
	return math.Min(math.Max(atLeastOne(rate, nNode)/denominator, 0), 1)
}

// observeRound folds one round's authenticated judgements into the mismatch
// estimate. pending describes the branches that stay open.
func (e *estimator) observeRound(clean, confirmed int64, pendingWeights []int64) {
	e.cleanLeaves += float64(clean)
	e.confirmed += float64(confirmed)
	e.pending, e.pendingWeight = float64(len(pendingWeights)), 0
	for _, weight := range pendingWeights {
		e.pendingWeight += float64(weight)
	}
}

// observeRetrieval re-scales the retrieval estimate from one measured round.
// predicted is the round's I/O plus network estimate at scale one.
func (e *estimator) observeRetrieval(predicted, observed time.Duration) {
	rate := e.config.Costs.AdaptationRate
	if rate <= 0 || predicted <= 0 || observed <= 0 {
		return
	}
	ratio := math.Min(math.Max(float64(observed)/float64(predicted), 1.0/16), 16)
	e.retrievalScale = (1-rate)*e.retrievalScale + rate*ratio
}

// subtreeCounts sizes the full-depth expansion of an on-path interior node.
type subtreeCounts struct {
	expanded int64 // interior nodes expanded, the node included
	frontier int64 // nodes fetched
}

// costModel prices frontiers: Ĉ(F) = Ĉ_IO + Ĉ_net + Ĉ_ver + Σ p̂_u·V̂(u).
type costModel struct {
	costs     CostCoefficients
	estimator *estimator
	structure *structure
	counts    map[hpp.NodeRef]subtreeCounts
	// remaining and childSums memoise V̂; they depend on the retrieval scale
	// and so are discarded whenever the estimator changes.
	remaining map[hpp.NodeRef]remainder
	childSums map[hpp.NodeRef]remainder
}

// remainder is V̂(u) split into its two parts: the retrieval and verification
// work still to do beneath a node known to differ, and the number of further
// sequential retrieval rounds that work needs. Splitting them lets the model
// charge a round's fixed latency once however many suspects share the round.
type remainder struct {
	work   float64
	rounds float64
}

func (r remainder) scaled(factor float64) remainder {
	return remainder{work: r.work * factor, rounds: r.rounds * factor}
}

func (r remainder) plus(other remainder) remainder {
	return remainder{work: r.work + other.work, rounds: r.rounds + other.rounds}
}

func newCostModel(config ACHPConfig, est *estimator, s *structure) *costModel {
	return &costModel{
		costs: config.Costs, estimator: est, structure: s,
		counts:    make(map[hpp.NodeRef]subtreeCounts),
		remaining: make(map[hpp.NodeRef]remainder), childSums: make(map[hpp.NodeRef]remainder),
	}
}

// reset discards the estimator-dependent memo tables.
func (m *costModel) reset() {
	m.remaining = make(map[hpp.NodeRef]remainder)
	m.childSums = make(map[hpp.NodeRef]remainder)
}

// fixedRound is the latency every retrieval round pays whatever it fetches: one
// round trip and one partition access.
func (m *costModel) fixedRound() float64 {
	return m.estimator.retrievalScale * (seconds(m.costs.NetworkRTT) + seconds(m.costs.PartitionAccess))
}

// roundWork prices the work of a retrieval round beyond its fixed latency.
func (m *costModel) roundWork(rows, partitions, hashes int64) float64 {
	return math.Max(0, m.roundCost(rows, partitions, hashes)-m.fixedRound())
}

func seconds(value time.Duration) float64 { return value.Seconds() }

// rowCost is the marginal retrieval cost of one more row in a partition that
// is already being read: its read and its transfer.
func (m *costModel) rowCost() float64 {
	return m.estimator.retrievalScale *
		(seconds(m.costs.RowRead) + m.costs.NodeWireBytes/m.costs.NetworkBytesPerSecond)
}

// expandCost is the marginal cost of expanding one node whose childCount
// children join the frontier: their rows, one interior hash, their comparison.
func (m *costModel) expandCost(childCount int) float64 {
	return float64(childCount)*(m.rowCost()+seconds(m.costs.CompareCost)) + seconds(m.costs.HashCost)
}

// partitionIO prices the grouped reads of one round: each partition is one
// access plus its rows, and the partitions are scheduled onto Concurrency
// parallel reads, longest first, so the cost is the resulting makespan.
func (m *costModel) partitionIO(rows map[hpp.PartitionKey]int) float64 {
	if len(rows) == 0 {
		return 0
	}
	durations := make([]float64, 0, len(rows))
	for _, count := range rows {
		durations = append(durations, seconds(m.costs.PartitionAccess)+float64(count)*seconds(m.costs.RowRead))
	}
	sort.Sort(sort.Reverse(sort.Float64Slice(durations)))
	workers := m.costs.Concurrency
	if workers > len(durations) {
		workers = len(durations)
	}
	loads := make([]float64, workers)
	for _, duration := range durations {
		lightest := 0
		for worker := 1; worker < workers; worker++ {
			if loads[worker] < loads[lightest] {
				lightest = worker
			}
		}
		loads[lightest] += duration
	}
	makespan := 0.0
	for _, load := range loads {
		makespan = math.Max(makespan, load)
	}
	return makespan * m.estimator.retrievalScale
}

// networkCost is one round trip plus the transfer of the fetched nodes.
func (m *costModel) networkCost(nodes int) float64 {
	return m.estimator.retrievalScale *
		(seconds(m.costs.NetworkRTT) + float64(nodes)*m.costs.NodeWireBytes/m.costs.NetworkBytesPerSecond)
}

func (m *costModel) verificationCost(hashes, comparisons int) float64 {
	return float64(hashes)*seconds(m.costs.HashCost) + float64(comparisons)*seconds(m.costs.CompareCost)
}

// roundCost prices one retrieval round of rows nodes spread evenly over
// partitions partitions, without any future term. It is the building block of
// V̂.
func (m *costModel) roundCost(rows, partitions, hashes int64) float64 {
	if rows <= 0 {
		return 0
	}
	if partitions < 1 {
		partitions = 1
	}
	if partitions > rows {
		partitions = rows
	}
	waves := (partitions + int64(m.costs.Concurrency) - 1) / int64(m.costs.Concurrency)
	perPartition := seconds(m.costs.PartitionAccess) + float64(rows)/float64(partitions)*seconds(m.costs.RowRead)
	return m.estimator.retrievalScale*float64(waves)*perPartition + m.networkCost(int(rows)) +
		m.verificationCost(int(hashes), int(rows))
}

// fullCounts sizes the full-depth expansion of an on-path interior node: every
// on-path interior node beneath it is expanded and every other child fetched.
func (m *costModel) fullCounts(info *treeInfo, position hpp.NodePosition) subtreeCounts {
	ref := hpp.NodeRef{Tree: info.tree, Position: position}
	if cached, ok := m.counts[ref]; ok {
		return cached
	}
	result := subtreeCounts{expanded: 1}
	for _, child := range info.children(position) {
		if info.descendable(child) {
			below := m.fullCounts(info, child)
			result.expanded += below.expanded
			result.frontier += below.frontier
		} else {
			result.frontier++
		}
	}
	m.counts[ref] = result
	return result
}

// partitionsFor estimates the partitions a full expansion reads. Segment,
// region and global nodes live in one partition per tree; a shard tree spans
// one partition per ShardNodesPerBucket leaves.
func partitionsFor(info *treeInfo, rows int64) int64 {
	if info.tree.Layer != hpp.LayerShard {
		return 1
	}
	buckets := (info.leafCount + hpp.ShardNodesPerBucket - 1) / hpp.ShardNodesPerBucket
	if buckets > rows {
		buckets = rows
	}
	if buckets < 1 {
		buckets = 1
	}
	return buckets
}

// remainingCost is V̂(u): the estimated cost of finishing the localization
// inside a node that is known to differ. It prices one full-depth expansion
// beneath the node and, in an upper tree, the expected cost of descending into
// the child tree that holds the difference. The result is split into work and
// sequential rounds; V̂(u) = work + rounds·fixedRound.
func (m *costModel) remainingCost(info *treeInfo, position hpp.NodePosition) remainder {
	ref := hpp.NodeRef{Tree: info.tree, Position: position}
	if cached, ok := m.remaining[ref]; ok {
		return cached
	}
	var value remainder
	if info.descendable(position) {
		counts := m.fullCounts(info, position)
		value = remainder{work: m.roundWork(counts.frontier, partitionsFor(info, counts.frontier), counts.expanded), rounds: 1}
		if info.tree.Layer != hpp.LayerSegment {
			if weight := info.weight[position]; weight > 0 {
				value = value.plus(m.childSum(info, position).scaled(1 / float64(weight)))
			}
		}
	} else if info.onPath(position) && position.Level == 0 {
		value = m.childTreeRemainder(info, position.Index)
	}
	m.remaining[ref] = value
	return value
}

// total is V̂(u) as a single figure.
func (m *costModel) total(r remainder) float64 { return r.work + r.rounds*m.fixedRound() }

// childSum is Σ w(L)·V̂(child tree of L) over the on-path leaves L beneath
// position; dividing by w(position) turns the weights into the single-
// corruption probabilities of descending into each child.
func (m *costModel) childSum(info *treeInfo, position hpp.NodePosition) remainder {
	ref := hpp.NodeRef{Tree: info.tree, Position: position}
	if cached, ok := m.childSums[ref]; ok {
		return cached
	}
	var sum remainder
	if position.Level == 0 {
		sum = m.childTreeRemainder(info, position.Index).scaled(float64(info.weight[position]))
	} else {
		for _, child := range info.children(position) {
			if info.onPath(child) {
				sum = sum.plus(m.childSum(info, child))
			}
		}
	}
	m.childSums[ref] = sum
	return sum
}

// childTreeRemainder is the remainder of localizing inside the tree committed
// by an upper tree's leaf: its top node is fetched in the same round as the
// first expansion beneath it.
func (m *costModel) childTreeRemainder(info *treeInfo, leafIndex int64) remainder {
	child, ok := info.childTree[leafIndex]
	if !ok {
		return remainder{}
	}
	childInfo, ok := m.structure.trees[child]
	if !ok {
		return remainder{}
	}
	top := childInfo.top()
	if !childInfo.descendable(top) {
		return remainder{work: m.roundWork(1, 1, 0), rounds: 1}
	}
	value := m.remainingCost(childInfo, top)
	value.work += m.rowCost()
	return value
}

// futureTerms is the contribution of a frontier node u, reached from a suspect
// covering rootWeight requested leaves, to the future term: p̂_u·work(u), the
// extra rounds beyond the first it would need, and the requested leaves it
// covers if it can still be descended (zero otherwise: a mismatching requested
// leaf, or an authentication node, ends its branch).
func (m *costModel) futureTerms(info *treeInfo, position hpp.NodePosition,
	rootWeight int64) (work, extraRounds float64, covered int64) {

	if !info.onPath(position) || (position.Level == 0 && info.tree.Layer == hpp.LayerSegment) {
		return 0, 0, 0
	}
	probability := m.estimator.conditional(info.weight[position], rootWeight)
	remaining := m.remainingCost(info, position)
	return probability * remaining.work, probability * (remaining.rounds - 1), info.weight[position]
}

// future is p̂_u·V̂(u) for a single frontier node, the unshared form of the
// future term used to compare keeping one node unexpanded with expanding it.
func (m *costModel) future(info *treeInfo, position hpp.NodePosition, rootWeight int64) float64 {
	work, extraRounds, covered := m.futureTerms(info, position, rootWeight)
	if covered == 0 {
		return 0
	}
	probability := m.estimator.conditional(covered, rootWeight)
	return work + (extraRounds+probability)*m.fixedRound()
}

// prefetchPays reports whether fetching the whole subtree of an on-path node
// now beats leaving it: the work is paid for certain, against the round it
// would otherwise cost with probability p̂.
func (m *costModel) prefetchPays(info *treeInfo, position hpp.NodePosition, rootWeight int64) bool {
	if !info.descendable(position) {
		return false
	}
	counts := m.fullCounts(info, position)
	work := m.roundWork(counts.frontier, partitionsFor(info, counts.frontier), counts.expanded)
	probability := m.estimator.conditional(info.weight[position], rootWeight)
	return (1-probability)*work < probability*m.fixedRound()
}

// expandPays reports whether expanding one more level of an on-path node is
// expected to cost less than leaving it for a later round.
func (m *costModel) expandPays(info *treeInfo, position hpp.NodePosition, rootWeight int64) bool {
	children := info.children(position)
	cost := m.expandCost(len(children))
	var covered int64
	for _, child := range children {
		work, extraRounds, weight := m.futureTerms(info, child, rootWeight)
		cost += work + extraRounds*m.fixedRound()
		covered += weight
	}
	if covered > 0 {
		cost += m.estimator.conditional(covered, rootWeight) * m.fixedRound()
	}
	return m.future(info, position, rootWeight) > cost
}

// estimate prices a joint frontier with the full formula.
func (m *costModel) estimate(joint jointFrontier) CostEstimate {
	var result CostEstimate
	partitions := make(map[hpp.PartitionKey]int)
	nodes, hashes, comparisons := 0, 0, 0
	for _, plan := range joint.plans {
		info := m.structure.trees[plan.task.tree]
		rootWeight := info.weight[plan.task.node]
		for _, ref := range plan.fetchRefs(info) {
			partitions[hpp.PartitionOf(ref)]++
			nodes++
		}
		hashes += len(plan.expanded)
		if plan.task.rootCommit {
			hashes++ // the commitment hash that binds the fetched top node
		}
		comparisons += len(plan.frontier)
		// Σ p̂_u·V̂(u), with the fixed latency of a further round charged once
		// per task with the probability that any descendable frontier node
		// differs, since the suspects of one task are retrieved together.
		var covered int64
		for _, position := range plan.frontier {
			work, extraRounds, weight := m.futureTerms(info, position, rootWeight)
			result.Future += work + extraRounds*m.fixedRound()
			covered += weight
		}
		if covered > 0 {
			result.Future += m.estimator.conditional(covered, rootWeight) * m.fixedRound()
		}
	}
	result.IO = m.partitionIO(partitions)
	result.Network = m.networkCost(nodes)
	result.Verification = m.verificationCost(hashes, comparisons)
	result.Total = result.IO + result.Network + result.Verification + result.Future
	return result
}

// retrievalAtUnitScale is the I/O plus network estimate at scale one, the
// quantity observeRetrieval compares with a measurement.
func (m *costModel) retrievalAtUnitScale(joint jointFrontier) time.Duration {
	saved := m.estimator.retrievalScale
	m.estimator.retrievalScale = 1
	defer func() { m.estimator.retrievalScale = saved }()
	partitions := make(map[hpp.PartitionKey]int)
	nodes := 0
	for _, plan := range joint.plans {
		for _, ref := range plan.fetchRefs(m.structure.trees[plan.task.tree]) {
			partitions[hpp.PartitionOf(ref)]++
			nodes++
		}
	}
	return time.Duration((m.partitionIO(partitions) + m.networkCost(nodes)) * float64(time.Second))
}
