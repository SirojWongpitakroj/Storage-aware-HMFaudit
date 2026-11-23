package localization

import (
	"context"
	"fmt"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// fallbackError reports that ACHP could not run or could not make progress
// and the fixed-depth traversal should be used instead. It is never returned
// for a reference store that answered but failed to authenticate: that is
// recorded as unresolved evidence.
type fallbackError struct{ reason string }

func (err *fallbackError) Error() string { return "ACHP unavailable: " + err.reason }

func fallbackf(format string, args ...any) error {
	return &fallbackError{reason: fmt.Sprintf(format, args...)}
}

// topologyProbe asks the store for the top node of a tree under the reference
// leaf count, to confirm that the failed proof's leaf count is the one in
// disagreement.
type topologyProbe struct {
	tree      hpp.TreeRef
	leafCount int64
	top       hpp.NodePosition
}

// localizeACHP is Adaptive Cost-Aware Hierarchical Pruning.
//
// Each round it gathers every suspect branch, enumerates candidate joint
// frontiers (depths may differ between and within branches), costs them with
// Ĉ(F) and retrieves the cheapest through HPP's partition-aware node reader.
// The retrieved nodes are authenticated against the anchored root before any
// is compared; matching nodes are pruned, differing ones open the next
// round's branches, and the loop ends when every branch is a confirmed leaf,
// a differing authentication node, or unresolved. Because every replan
// expands at least the suspect node itself, each round moves the frontier
// strictly toward the leaves.
func (service *Service) localizeACHP(ctx context.Context, request Request,
	addresses []hpp.PhysicalAddress, auditorTrace hpp.ProofTrace) (Result, error) {

	source, ok := service.reference.(FrontierSource)
	if !ok {
		return Result{}, fallbackf("the reference builder cannot retrieve explicit frontiers")
	}
	global := hpp.TreeRef{Layer: hpp.LayerGlobal}
	s, err := newStructure(request.FailedProof, addresses)
	if err != nil {
		return Result{}, fallbackf("failed proof structure: %v", err)
	}
	if _, ok := s.trees[global]; !ok {
		return Result{}, fallbackf("failed proof has no global tree")
	}

	config := service.achp
	now := config.Now
	if now == nil {
		now = time.Now
	}
	estimator := newEstimator(config)
	model := newCostModel(config, estimator, s)
	generator := &candidateGenerator{structure: s, model: model, limit: config.MaxCandidates}
	engine := newEngine(s, auditorTrace, request.AnchoredGlobalRoot)
	transcript := &ACHPTranscript{Parameters: ACHPParameters{
		MaxCandidates: config.MaxCandidates, MismatchPrior: config.MismatchPrior,
	}}

	// Each replan expands the suspect node itself, so a chain of suspects
	// descends at least one level per round; a topology probe adds one round.
	maxRounds := 2
	for _, info := range s.trees {
		maxRounds += int(info.height) + 1
	}

	var referencePlan *hpp.ProofPlan
	planFailed := false
	var probes []topologyProbe
	tasks := engine.pendingTasks()
	var prunedBefore, confirmedBefore int64
	for round := 1; len(tasks) > 0 || len(probes) > 0; round++ {
		if round > maxRounds {
			return Result{}, fallbackf("no progress after %d rounds", maxRounds)
		}
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}

		model.reset()
		var joint jointFrontier
		var chosen CostEstimate
		candidateCount := 0
		if len(tasks) > 0 {
			candidates := generator.generate(tasks)
			candidateCount = len(candidates)
			var found bool
			if joint, chosen, found = selectFrontier(candidates, model); !found {
				return Result{}, fallbackf("no candidate frontier for %d suspect branches", len(tasks))
			}
		}

		expansions := make([]Expansion, 0, len(joint.plans)+len(probes))
		fetchRefs := make([][]hpp.NodeRef, 0, cap(expansions))
		for _, plan := range joint.plans {
			info := s.trees[plan.task.tree]
			expansions = append(expansions, Expansion{
				Kind: ExpansionFrontier, Tree: plan.task.tree, LeafCount: info.leafCount,
				Node: plan.task.node, RootCommit: plan.task.rootCommit, Expanded: plan.expanded,
			})
			fetchRefs = append(fetchRefs, plan.fetchRefs(info))
		}
		for _, probe := range probes {
			expansions = append(expansions, Expansion{
				Kind: ExpansionTopology, Tree: probe.tree, LeafCount: probe.leafCount,
				Node: probe.top, RootCommit: true,
			})
			fetchRefs = append(fetchRefs, []hpp.NodeRef{{Tree: probe.tree, Position: probe.top}})
		}
		probes = nil

		started := now()
		allFailed, fetchErr := fetchRound(ctx, source, expansions, fetchRefs)
		observed := now().Sub(started)
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if allFailed && round == 1 {
			return Result{}, fallbackf("initial retrieval failed: %v", fetchErr)
		}

		for index := range expansions {
			if err := engine.apply(&expansions[index], false); err != nil {
				return Result{}, fallbackf("%v", err)
			}
		}
		if round == 1 && len(joint.plans) > 0 && expansions[0].Status != EvidenceAuthenticated {
			return Result{}, fallbackf("the global commitment could not be authenticated (%s)", expansions[0].Status)
		}

		for _, exp := range expansions {
			if exp.Kind != ExpansionFrontier || !exp.RootCommit || exp.Status == EvidenceAuthenticated {
				continue
			}
			probe, scheduled, err := service.scheduleTopologyProbe(ctx, source, addresses, s, exp,
				&referencePlan, &planFailed)
			if err != nil {
				return Result{}, err
			}
			if scheduled {
				probes = append(probes, probe)
			}
		}

		next, err := engine.endRound()
		if err != nil {
			return Result{}, fallbackf("%v", err)
		}
		pendingWeights := make([]int64, 0, len(next))
		for _, t := range next {
			pendingWeights = append(pendingWeights, s.trees[t.tree].weight[t.node])
		}
		estimator.observeRound(engine.pruned-prunedBefore, engine.confirmed-confirmedBefore, pendingWeights)
		prunedBefore, confirmedBefore = engine.pruned, engine.confirmed
		if len(joint.plans) > 0 {
			estimator.observeRetrieval(model.retrievalAtUnitScale(joint), observed)
		}
		transcript.Rounds = append(transcript.Rounds, ACHPRound{
			Index: round, Candidates: candidateCount, Chosen: chosen, Expansions: expansions,
		})
		tasks = next
	}
	if err := engine.finish(); err != nil {
		return Result{}, fallbackf("%v", err)
	}

	badShards, rounds, suspects, unresolved := engine.results()
	proof := Proof{
		AnchoredGlobalRoot: request.AnchoredGlobalRoot, AuditorGlobalRoot: request.AuditorGlobalRoot,
		ReferenceGlobalRoot: request.AnchoredGlobalRoot, Strategy: StrategyACHP,
		Addresses: addresses, FailedProof: request.FailedProof,
		BadShards: badShards, Rounds: rounds, Suspects: suspects, Unresolved: unresolved,
		ACHP: transcript,
	}
	return Result{CalculatedReferenceRoot: request.AnchoredGlobalRoot, Proof: proof}, nil
}

// fetchRound retrieves every expansion's nodes together, so that partitions
// shared between branches are read once. If the joint read fails (the
// Cassandra reader fails a whole call when any node is absent) each expansion
// is retried alone, which confines a missing node to the branch that needs it.
// It reports whether every expansion failed.
func fetchRound(ctx context.Context, source FrontierSource, expansions []Expansion,
	refs [][]hpp.NodeRef) (bool, error) {

	var all []hpp.NodeRef
	for _, group := range refs {
		all = append(all, group...)
	}
	nodes, jointErr := source.FetchNodes(ctx, all)
	if jointErr == nil {
		byRef := make(map[hpp.NodeRef]hpp.ProofNode, len(nodes))
		for _, node := range nodes {
			byRef[node.Ref] = node
		}
		for index := range expansions {
			for _, ref := range refs[index] {
				if node, ok := byRef[ref]; ok {
					expansions[index].Fetched = append(expansions[index].Fetched, node)
				}
			}
		}
		return false, nil
	}
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	failed := 0
	for index := range expansions {
		nodes, err := source.FetchNodes(ctx, refs[index])
		if err != nil {
			failed++
			continue
		}
		expansions[index].Fetched = nodes
	}
	return failed == len(expansions), jointErr
}

// scheduleTopologyProbe decides whether a tree whose root expansion failed
// should be probed for a leaf-count disagreement. It loads the reference
// topology once, and only on this failure path.
func (service *Service) scheduleTopologyProbe(ctx context.Context, source FrontierSource,
	addresses []hpp.PhysicalAddress, s *structure, exp Expansion, plan **hpp.ProofPlan,
	failed *bool) (topologyProbe, bool, error) {

	if *plan == nil && !*failed {
		loaded, err := source.ReferencePlan(ctx, addresses)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return topologyProbe{}, false, ctxErr
		}
		if err != nil {
			*failed = true
		} else {
			*plan = &loaded
		}
	}
	if *plan == nil {
		return topologyProbe{}, false, nil
	}
	info := s.trees[exp.Tree]
	for _, treePlan := range (*plan).Trees {
		if treePlan.Tree != exp.Tree || treePlan.LeafCount <= 0 || treePlan.LeafCount == info.leafCount {
			continue
		}
		widths := levelWidths(treePlan.LeafCount)
		return topologyProbe{tree: exp.Tree, leafCount: treePlan.LeafCount,
			top: hpp.NodePosition{Level: int32(len(widths) - 1), Index: 0}}, true, nil
	}
	return topologyProbe{}, false, nil
}
