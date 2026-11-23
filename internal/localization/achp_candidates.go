package localization

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// task is one suspect branch awaiting expansion: an on-path node whose
// authenticated reference commitment is known (or, for a tree top, derivable
// from the tree's authenticated committed root) and differs from the auditor's.
type task struct {
	tree hpp.TreeRef
	node hpp.NodePosition
	// rootCommit marks a tree's top node. Its raw hash must be fetched and
	// authenticated through the tree's committed root.
	rootCommit bool
}

func lessTask(left, right task) bool {
	if left.tree != right.tree {
		return lessTree(left.tree, right.tree)
	}
	return lessPosition(left.node, right.node)
}

func sortTasks(tasks []task) {
	sort.Slice(tasks, func(i, j int) bool { return lessTask(tasks[i], tasks[j]) })
}

// taskPlan is one task's chosen expansion: the on-path interior nodes whose
// children are retrieved, and the resulting frontier. Different tasks, and
// different branches of one task, may be expanded to different depths.
type taskPlan struct {
	task     task
	expanded []hpp.NodePosition
	frontier []hpp.NodePosition
}

// fetchRefs lists every node the plan retrieves: its frontier and, for a tree
// top, the top node itself.
func (plan taskPlan) fetchRefs(info *treeInfo) []hpp.NodeRef {
	refs := make([]hpp.NodeRef, 0, len(plan.frontier)+1)
	if plan.task.rootCommit && len(plan.expanded) > 0 {
		refs = append(refs, hpp.NodeRef{Tree: plan.task.tree, Position: plan.task.node})
	}
	for _, position := range plan.frontier {
		refs = append(refs, hpp.NodeRef{Tree: plan.task.tree, Position: position})
	}
	return refs
}

// jointFrontier is one candidate for the whole round: an expansion for every
// active task, retrieved together.
type jointFrontier struct {
	label string
	plans []taskPlan
}

// signature identifies a frontier by content, for de-duplication and for the
// final deterministic tie-break.
func (joint jointFrontier) signature() string {
	var builder strings.Builder
	for _, plan := range joint.plans {
		fmt.Fprintf(&builder, "%d/%s/%d/%d/%d:", plan.task.tree.Layer, plan.task.tree.RegionID,
			plan.task.tree.ShardID, plan.task.tree.SegmentID, plan.task.node.Level)
		fmt.Fprintf(&builder, "%d[", plan.task.node.Index)
		for _, position := range plan.frontier {
			fmt.Fprintf(&builder, "%d.%d,", position.Level, position.Index)
		}
		builder.WriteString("]")
	}
	return builder.String()
}

func (joint jointFrontier) nodeCount(s *structure) int {
	total := 0
	for _, plan := range joint.plans {
		total += len(plan.fetchRefs(s.trees[plan.task.tree]))
	}
	return total
}

// candidateDepths are the uniform expansion depths enumerated each round, in
// levels below the suspect node. They bracket the fixed-depth κ values the
// cost model replaces.
var candidateDepths = []int32{1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64}

// candidateGenerator enumerates candidate joint frontiers deterministically.
type candidateGenerator struct {
	structure *structure
	model     *costModel
	limit     int
}

// expand builds a task's plan by breadth-first expansion from its node. rule
// decides, for an on-path interior node below the root, whether to expand it;
// the root itself is always expanded, which guarantees every replan descends.
func (g *candidateGenerator) expand(t task, rule func(position hpp.NodePosition) bool) taskPlan {
	info := g.structure.trees[t.tree]
	plan := taskPlan{task: t}
	if !info.descendable(t.node) {
		// A tree whose top is a leaf: the fetched top is the whole frontier.
		plan.frontier = []hpp.NodePosition{t.node}
		return plan
	}
	expanded := []hpp.NodePosition{t.node}
	queue := []hpp.NodePosition{t.node}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, child := range info.children(current) {
			if info.descendable(child) && rule(child) {
				expanded = append(expanded, child)
				queue = append(queue, child)
			}
		}
	}
	sortPositions(expanded)
	frontier, _ := info.frontierOf(t.node, expanded)
	plan.expanded, plan.frontier = expanded, frontier
	return plan
}

func (g *candidateGenerator) uniform(tasks []task, depth int32) jointFrontier {
	joint := jointFrontier{label: fmt.Sprintf("uniform-%d", depth)}
	for _, t := range tasks {
		root := t.node.Level
		joint.plans = append(joint.plans, g.expand(t, func(position hpp.NodePosition) bool {
			return root-position.Level < depth
		}))
	}
	return joint
}

func (g *candidateGenerator) full(tasks []task) jointFrontier {
	joint := jointFrontier{label: "full"}
	for _, t := range tasks {
		joint.plans = append(joint.plans, g.expand(t, func(hpp.NodePosition) bool { return true }))
	}
	return joint
}

// greedy chooses depths branch by branch. A node is expanded when either
//
//   - prefetching its whole subtree now is cheaper than the expected cost of
//     leaving it, i.e. (1-p̂)·work < p̂·fixed round latency, a lookahead that sees
//     the saving only a full descent delivers; or
//   - one more level is worth its price: the expected cost of leaving the node
//     (p̂·V̂) exceeds fetching its children plus what would still be left
//     beneath them.
//
// Branches covering more requested leaves have a higher p̂ and so descend
// further than sparse ones: depths differ between branches of one tree.
func (g *candidateGenerator) greedy(tasks []task) jointFrontier {
	joint := jointFrontier{label: "greedy"}
	for _, t := range tasks {
		info := g.structure.trees[t.tree]
		rootWeight := info.weight[t.node]
		prefetched := make(map[hpp.NodePosition]bool)
		prefetched[t.node] = g.model.prefetchPays(info, t.node, rootWeight)
		joint.plans = append(joint.plans, g.expand(t, func(position hpp.NodePosition) bool {
			parent := hpp.NodePosition{Level: position.Level + 1, Index: position.Index / 2}
			if prefetched[parent] || g.model.prefetchPays(info, position, rootWeight) {
				prefetched[position] = true
				return true
			}
			return g.model.expandPays(info, position, rootWeight)
		}))
	}
	return joint
}

// mixed expands the heaviest half of the tasks to the leaves and the rest only
// depth levels, so branches carrying more requested leaves descend further.
func (g *candidateGenerator) mixed(tasks []task, depth int32) jointFrontier {
	ranked := append([]task(nil), tasks...)
	sort.SliceStable(ranked, func(i, j int) bool {
		left := g.structure.trees[ranked[i].tree].weight[ranked[i].node]
		right := g.structure.trees[ranked[j].tree].weight[ranked[j].node]
		if left != right {
			return left > right
		}
		return lessTask(ranked[i], ranked[j])
	})
	heavy := make(map[task]bool, len(ranked))
	for index := 0; index < (len(ranked)+1)/2; index++ {
		heavy[ranked[index]] = true
	}
	joint := jointFrontier{label: fmt.Sprintf("mixed-%d", depth)}
	for _, t := range tasks {
		root := t.node.Level
		joint.plans = append(joint.plans, g.expand(t, func(position hpp.NodePosition) bool {
			return heavy[t] || root-position.Level < depth
		}))
	}
	return joint
}

// generate returns at most limit distinct joint frontiers in a fixed order:
// the cost-guided frontier, the full descent, then uniform depths shallow to
// deep, then mixed-depth frontiers. tasks must be sorted.
func (g *candidateGenerator) generate(tasks []task) []jointFrontier {
	if len(tasks) == 0 {
		return nil
	}
	var all []jointFrontier
	all = append(all, g.greedy(tasks), g.full(tasks))
	for _, depth := range candidateDepths {
		all = append(all, g.uniform(tasks, depth))
	}
	if len(tasks) > 1 {
		for _, depth := range []int32{1, 2, 4} {
			all = append(all, g.mixed(tasks, depth))
		}
	}
	seen := make(map[string]struct{}, len(all))
	result := make([]jointFrontier, 0, g.limit)
	for _, candidate := range all {
		signature := candidate.signature()
		if _, duplicate := seen[signature]; duplicate {
			continue
		}
		seen[signature] = struct{}{}
		result = append(result, candidate)
		if len(result) == g.limit {
			break
		}
	}
	return result
}

// selectFrontier returns the candidate with the lowest estimated cost. Ties
// break deterministically: fewer retrieved nodes, then the smaller signature,
// then enumeration order. A non-finite estimate never wins over a finite one.
func selectFrontier(candidates []jointFrontier, model *costModel) (jointFrontier, CostEstimate, bool) {
	if len(candidates) == 0 {
		return jointFrontier{}, CostEstimate{}, false
	}
	best, bestCost := -1, CostEstimate{}
	bestNodes, bestSignature := 0, ""
	for index, candidate := range candidates {
		cost := model.estimate(candidate)
		if math.IsNaN(cost.Total) {
			cost.Total = math.Inf(1)
		}
		nodes, signature := candidate.nodeCount(model.structure), candidate.signature()
		better := best < 0 || cost.Total < bestCost.Total
		if !better && cost.Total == bestCost.Total {
			better = nodes < bestNodes || (nodes == bestNodes && signature < bestSignature)
		}
		if better {
			best, bestCost, bestNodes, bestSignature = index, cost, nodes, signature
		}
	}
	return candidates[best], bestCost, true
}
