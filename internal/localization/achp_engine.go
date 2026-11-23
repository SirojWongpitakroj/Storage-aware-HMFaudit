package localization

import (
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// engine is the single implementation of ACHP's authenticated pruning logic.
// The localizer drives it as it retrieves evidence; the auditor drives an
// identical engine over the recorded transcript. Because both go through
// apply, what the localizer concluded is exactly what a replay concludes: a
// transcript that would not authenticate, would skip a suspect branch, or
// would prune a differing node cannot verify.
//
// The engine never consults a cost estimate. Costs choose what is retrieved;
// only authenticated hashes decide what is pruned.
type engine struct {
	structure *structure
	trace     hpp.ProofTrace
	state     *authState

	// pending holds the tasks the current round must expand, all of them;
	// next collects the branches this round's judgements opened.
	pending map[task]struct{}
	next    []task
	// topologyEligible marks trees whose root expansion failed, the only
	// trees a topology probe may name.
	topologyEligible map[hpp.TreeRef]bool

	suspects   map[hpp.NodeRef]Suspect
	unresolved map[hpp.NodeRef]UnresolvedNode
	badShards  map[hpp.TreeRef]struct{}
	rounds     []PruningRound

	// observations for the estimator
	pruned    int64
	confirmed int64
}

func newEngine(s *structure, trace hpp.ProofTrace, anchored [32]byte) *engine {
	global := hpp.TreeRef{Layer: hpp.LayerGlobal}
	root := task{tree: global, node: s.trees[global].top(), rootCommit: true}
	return &engine{
		structure: s, trace: trace, state: newAuthState(anchored),
		pending:          map[task]struct{}{root: {}},
		topologyEligible: make(map[hpp.TreeRef]bool),
		suspects:         make(map[hpp.NodeRef]Suspect),
		unresolved:       make(map[hpp.NodeRef]UnresolvedNode),
		badShards:        make(map[hpp.TreeRef]struct{}),
	}
}

// pendingTasks lists the tasks the round must expand, in canonical order.
func (e *engine) pendingTasks() []task {
	result := make([]task, 0, len(e.pending))
	for pending := range e.pending {
		result = append(result, pending)
	}
	sortTasks(result)
	return result
}

// apply authenticates one retrieved expansion and folds its judgements into the
// engine. With verify unset it records the derived status and judgements into
// exp; with verify set it requires exp to already state exactly what the
// evidence implies. Errors wrap errMalformed.
func (e *engine) apply(exp *Expansion, verify bool) error {
	switch exp.Kind {
	case ExpansionFrontier:
		return e.applyFrontier(exp, verify)
	case ExpansionTopology:
		return e.applyTopology(exp, verify)
	default:
		return fmt.Errorf("%w: unknown expansion kind %q", errMalformed, exp.Kind)
	}
}

func statusOf(err error) (EvidenceStatus, error) {
	switch {
	case err == nil:
		return EvidenceAuthenticated, nil
	case errors.Is(err, errEvidenceMissing):
		return EvidenceMissing, nil
	case errors.Is(err, errEvidenceInvalid):
		return EvidenceInvalid, nil
	default:
		return "", err
	}
}

func (e *engine) applyFrontier(exp *Expansion, verify bool) error {
	t := task{tree: exp.Tree, node: exp.Node, rootCommit: exp.RootCommit}
	if _, ok := e.pending[t]; !ok {
		return fmt.Errorf("%w: no pending suspect at %+v of tree %+v", errMalformed, exp.Node, exp.Tree)
	}
	delete(e.pending, t)

	frontier, err := e.state.authenticateFrontier(e.structure, exp)
	status, err := statusOf(err)
	if err != nil {
		return err
	}
	if verify && status != exp.Status {
		return fmt.Errorf("%w: expansion of %+v records status %q, evidence gives %q",
			errMalformed, exp.Node, exp.Status, status)
	}
	exp.Status = status

	ref := hpp.NodeRef{Tree: exp.Tree, Position: exp.Node}
	if status != EvidenceAuthenticated {
		if verify && len(exp.Judgements) != 0 {
			return fmt.Errorf("%w: unauthenticated expansion of %+v carries judgements", errMalformed, exp.Node)
		}
		exp.Judgements = nil
		e.unresolved[ref] = UnresolvedNode{Ref: ref, AuditorHash: e.trace.Nodes[ref], Reason: status}
		if exp.RootCommit {
			e.topologyEligible[exp.Tree] = true
		}
		return nil
	}

	judgements := make([]NodeJudgement, 0, len(frontier))
	round := PruningRound{Tree: exp.Tree, FromLevel: exp.Node.Level, TargetLevel: exp.Node.Level}
	for _, position := range frontier {
		frontierRef := hpp.NodeRef{Tree: exp.Tree, Position: position}
		reference := e.state.nodes[frontierRef]
		judgement, follow := e.structure.judge(e.trace, e.state, frontierRef, reference)
		judgements = append(judgements, judgement)
		round.Comparisons = append(round.Comparisons, NodeComparison{
			Ref: frontierRef, AuditorHash: judgement.AuditorHash, ReferenceHash: reference,
			Match: judgement.Disposition == DispositionPrune,
		})
		if position.Level < round.TargetLevel {
			round.TargetLevel = position.Level
		}
		e.record(judgement, follow)
	}
	if verify {
		if !reflect.DeepEqual(judgements, exp.Judgements) {
			return fmt.Errorf("%w: judgements of the expansion at %+v do not follow from its evidence",
				errMalformed, exp.Node)
		}
	}
	exp.Judgements = judgements
	e.rounds = append(e.rounds, round)
	return nil
}

// record folds one judgement into the derived results.
func (e *engine) record(judgement NodeJudgement, follow *task) {
	info := e.structure.trees[judgement.Ref.Tree]
	switch judgement.Disposition {
	case DispositionPrune:
		e.pruned += info.weight[judgement.Ref.Position]
	case DispositionUnresolved:
		e.unresolved[judgement.Ref] = UnresolvedNode{Ref: judgement.Ref, AuditorHash: judgement.AuditorHash,
			Reason: EvidenceMissing}
	case DispositionSuspect:
		if follow != nil {
			e.next = append(e.next, *follow)
		}
		if judgement.Classification == "" {
			break
		}
		suspect := Suspect{Ref: judgement.Ref, AuditorHash: judgement.AuditorHash,
			ReferenceHash: judgement.ReferenceHash, Classification: judgement.Classification}
		if judgement.Classification == LeafMismatch {
			address := e.structure.addressByLeaf[judgement.Ref]
			suspect.Address = &address
			e.confirmed++
		}
		e.suspects[judgement.Ref] = suspect
	}
	if info.tree.Layer == hpp.LayerRegion && judgement.Ref.Position.Level == 0 &&
		judgement.Disposition == DispositionSuspect {
		if child, ok := info.childTree[judgement.Ref.Position.Index]; ok && child.Layer == hpp.LayerShard {
			e.badShards[child] = struct{}{}
		}
	}
}

func (e *engine) applyTopology(exp *Expansion, verify bool) error {
	if !e.topologyEligible[exp.Tree] {
		return fmt.Errorf("%w: topology probe of %+v without a failed root expansion", errMalformed, exp.Tree)
	}
	delete(e.topologyEligible, exp.Tree)
	status, err := statusOf(e.state.authenticateTopology(e.structure, exp))
	if err != nil {
		return err
	}
	if verify && (status != exp.Status || len(exp.Judgements) != 0) {
		return fmt.Errorf("%w: topology probe of %+v records status %q, evidence gives %q",
			errMalformed, exp.Tree, exp.Status, status)
	}
	exp.Status, exp.Judgements = status, nil
	if status != EvidenceAuthenticated {
		return nil // the failed root expansion already left the tree unresolved
	}
	info := e.structure.trees[exp.Tree]
	delete(e.unresolved, hpp.NodeRef{Tree: exp.Tree, Position: info.top()})
	level := info.height
	if reference := int32(len(levelWidths(exp.LeafCount)) - 1); reference > level {
		level = reference
	}
	ref := hpp.NodeRef{Tree: exp.Tree, Position: hpp.NodePosition{Level: level, Index: 0}}
	e.suspects[ref] = Suspect{Ref: ref, AuditorHash: e.trace.CommittedRoots[exp.Tree],
		ReferenceHash: e.state.committed[exp.Tree], Classification: TopologyMismatch}
	if exp.Tree.Layer == hpp.LayerShard {
		e.badShards[exp.Tree] = struct{}{}
	}
	return nil
}

// endRound closes a round. Every pending suspect must have been expanded in it
// (a failed expansion counts: it leaves the branch unresolved, visibly).
// Branches opened by the round's judgements become the next round's tasks.
func (e *engine) endRound() ([]task, error) {
	if len(e.pending) != 0 {
		return nil, fmt.Errorf("%w: %d suspect branches were skipped", errMalformed, len(e.pending))
	}
	next := e.next
	e.next = nil
	sortTasks(next)
	for _, t := range next {
		e.pending[t] = struct{}{}
	}
	return next, nil
}

// finish requires that no suspect branch was left unexpanded.
func (e *engine) finish() error {
	if len(e.pending) != 0 {
		return fmt.Errorf("%w: %d suspect branches were never expanded", errMalformed, len(e.pending))
	}
	return nil
}

// results returns the derived outputs in canonical order, with empty results
// nil so that proofs compare equal however they were produced.
func (e *engine) results() (badShards []hpp.TreeRef, rounds []PruningRound, suspects []Suspect,
	unresolved []UnresolvedNode) {

	for tree := range e.badShards {
		badShards = append(badShards, tree)
	}
	sort.Slice(badShards, func(i, j int) bool { return lessTree(badShards[i], badShards[j]) })
	for _, suspect := range e.suspects {
		suspects = append(suspects, suspect)
	}
	sort.Slice(suspects, func(i, j int) bool { return lessNodeRef(suspects[i].Ref, suspects[j].Ref) })
	for _, node := range e.unresolved {
		unresolved = append(unresolved, node)
	}
	sort.Slice(unresolved, func(i, j int) bool { return lessNodeRef(unresolved[i].Ref, unresolved[j].Ref) })
	if len(e.rounds) > 0 {
		rounds = e.rounds
	}
	return badShards, rounds, suspects, unresolved
}
