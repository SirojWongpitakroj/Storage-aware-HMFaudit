package localization

import (
	"errors"
	"fmt"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

var (
	// errEvidenceMissing: a node the frontier needs was not supplied.
	errEvidenceMissing = errors.New("frontier evidence is missing")
	// errEvidenceInvalid: the supplied nodes do not reproduce the
	// authenticated commitment they were fetched to rebuild.
	errEvidenceInvalid = errors.New("frontier evidence does not authenticate")
	// errMalformed: the expansion itself is not well formed (a bad expanded
	// set, a foreign node, a task that was never pending). It is a defect of
	// the localizer or of a forged transcript, never of the reference store.
	errMalformed = errors.New("malformed expansion")
)

// authState is the reference evidence authenticated so far. committed holds the
// authenticated committed root of a tree; nodes holds authenticated node
// hashes. Nothing enters either map unless it was reproduced from the anchored
// root.
type authState struct {
	committed map[hpp.TreeRef][32]byte
	nodes     map[hpp.NodeRef][32]byte
}

func newAuthState(anchored [32]byte) *authState {
	return &authState{
		committed: map[hpp.TreeRef][32]byte{{Layer: hpp.LayerGlobal}: anchored},
		nodes:     make(map[hpp.NodeRef][32]byte),
	}
}

// fold rebuilds the hash of u from the nodes of a frontier beneath it. The walk
// is demand driven: it stops at the first supplied node on every branch, so a
// supplied node that is also derivable from supplied descendants is simply
// unused, and the caller rejects the leftover. It returns how many supplied
// nodes it consumed.
func fold(widths []int64, u hpp.NodePosition, nodes map[hpp.NodePosition][32]byte) ([32]byte, int, error) {
	used := 0
	var compute func(position hpp.NodePosition, isRoot bool) ([32]byte, error)
	compute = func(position hpp.NodePosition, isRoot bool) ([32]byte, error) {
		if !isRoot {
			if hash, ok := nodes[position]; ok {
				used++
				return hash, nil
			}
		}
		children := childrenOf(widths, position)
		if len(children) == 0 {
			return [32]byte{}, errEvidenceMissing
		}
		left, err := compute(children[0], false)
		if err != nil {
			return [32]byte{}, err
		}
		if len(children) == 1 {
			return left, nil // an odd node is promoted unchanged
		}
		right, err := compute(children[1], false)
		if err != nil {
			return [32]byte{}, err
		}
		return domain.HashPair("NODE", &left, &right), nil
	}
	hash, err := compute(u, true)
	return hash, used, err
}

// authenticateFrontier checks one retrieved frontier against the authenticated
// state and, only if it reproduces the commitment of its node, records every
// fetched node as authenticated. It returns the frontier in canonical order.
//
// Errors are errEvidenceMissing, errEvidenceInvalid or errMalformed; on any of
// them the state is left unchanged.
func (state *authState) authenticateFrontier(s *structure, exp *Expansion) ([]hpp.NodePosition, error) {
	info, ok := s.trees[exp.Tree]
	if !ok || exp.LeafCount != info.leafCount {
		return nil, fmt.Errorf("%w: tree %+v is not planned with %d leaves", errMalformed, exp.Tree, exp.LeafCount)
	}
	top := info.top()
	if exp.RootCommit && exp.Node != top {
		return nil, fmt.Errorf("%w: root commitment of %+v at a non-top node", errMalformed, exp.Tree)
	}
	var frontier []hpp.NodePosition
	if info.descendable(exp.Node) {
		frontier, ok = info.frontierOf(exp.Node, exp.Expanded)
		if !ok {
			return nil, fmt.Errorf("%w: invalid expanded set beneath %+v", errMalformed, exp.Node)
		}
	} else {
		if !exp.RootCommit || len(exp.Expanded) != 0 || !info.onPath(exp.Node) {
			return nil, fmt.Errorf("%w: node %+v cannot be expanded", errMalformed, exp.Node)
		}
		frontier = []hpp.NodePosition{exp.Node}
	}

	wanted := make(map[hpp.NodePosition]struct{}, len(frontier)+1)
	for _, position := range frontier {
		wanted[position] = struct{}{}
	}
	if exp.RootCommit {
		wanted[top] = struct{}{}
	}
	fetched := make(map[hpp.NodePosition][32]byte, len(exp.Fetched))
	for _, node := range exp.Fetched {
		if node.Ref.Tree != exp.Tree {
			return nil, fmt.Errorf("%w: fetched node %+v is outside tree %+v", errMalformed, node.Ref, exp.Tree)
		}
		if _, duplicate := fetched[node.Ref.Position]; duplicate {
			return nil, fmt.Errorf("%w: node %+v fetched twice", errMalformed, node.Ref)
		}
		if _, expected := wanted[node.Ref.Position]; !expected {
			return nil, fmt.Errorf("%w: node %+v was not part of the frontier", errMalformed, node.Ref)
		}
		fetched[node.Ref.Position] = node.Hash
	}
	for position := range wanted {
		if _, present := fetched[position]; !present {
			return nil, errEvidenceMissing
		}
	}

	var anchor [32]byte
	if exp.RootCommit {
		committed, known := state.committed[exp.Tree]
		if !known {
			return nil, fmt.Errorf("%w: tree %+v has no authenticated commitment", errMalformed, exp.Tree)
		}
		raw := fetched[top]
		if !equalHash(hpp.CommittedRoot(exp.Tree, info.leafCount, raw), committed) {
			return nil, errEvidenceInvalid
		}
		anchor = raw
		delete(fetched, top)
	} else {
		known, authenticated := state.nodes[hpp.NodeRef{Tree: exp.Tree, Position: exp.Node}]
		if !authenticated {
			return nil, fmt.Errorf("%w: node %+v has no authenticated hash", errMalformed, exp.Node)
		}
		anchor = known
	}

	if info.descendable(exp.Node) {
		computed, used, err := fold(info.widths, exp.Node, fetched)
		if err != nil {
			return nil, err
		}
		if !equalHash(computed, anchor) || used != len(fetched) {
			return nil, errEvidenceInvalid
		}
	}

	if exp.RootCommit {
		state.nodes[hpp.NodeRef{Tree: exp.Tree, Position: top}] = anchor
	}
	for position, hash := range fetched {
		state.nodes[hpp.NodeRef{Tree: exp.Tree, Position: position}] = hash
	}
	return frontier, nil
}

// authenticateTopology checks the topology probe: the reference tree's top node
// under the reference leaf count must reproduce the tree's authenticated
// committed root. Success proves the reference tree has exp.LeafCount leaves.
func (state *authState) authenticateTopology(s *structure, exp *Expansion) error {
	info, ok := s.trees[exp.Tree]
	if !ok || exp.LeafCount <= 0 || exp.LeafCount == info.leafCount {
		return fmt.Errorf("%w: topology probe of %+v needs a differing leaf count", errMalformed, exp.Tree)
	}
	widths := levelWidths(exp.LeafCount)
	top := hpp.NodePosition{Level: int32(len(widths) - 1), Index: 0}
	if !exp.RootCommit || exp.Node != top || len(exp.Expanded) != 0 {
		return fmt.Errorf("%w: topology probe of %+v must fetch only the top node", errMalformed, exp.Tree)
	}
	committed, known := state.committed[exp.Tree]
	if !known {
		return fmt.Errorf("%w: tree %+v has no authenticated commitment", errMalformed, exp.Tree)
	}
	if len(exp.Fetched) == 0 {
		return errEvidenceMissing
	}
	if len(exp.Fetched) != 1 || exp.Fetched[0].Ref != (hpp.NodeRef{Tree: exp.Tree, Position: top}) {
		return fmt.Errorf("%w: topology probe of %+v fetched an unexpected node", errMalformed, exp.Tree)
	}
	if !equalHash(hpp.CommittedRoot(exp.Tree, exp.LeafCount, exp.Fetched[0].Hash), committed) {
		return errEvidenceInvalid
	}
	return nil
}

// judge compares one authenticated reference node with the auditor's
// query-derived value. A node is pruned only when the two are equal; it is
// never pruned for any other reason. When the judgement leaves a branch to
// descend into it also returns that branch's task, and for an upper-tree leaf
// it records the child tree's authenticated committed root.
func (s *structure) judge(trace hpp.ProofTrace, state *authState, ref hpp.NodeRef,
	reference [32]byte) (NodeJudgement, *task) {

	auditor, known := trace.Nodes[ref]
	judgement := NodeJudgement{Ref: ref, AuditorHash: auditor, ReferenceHash: reference}
	if !known {
		judgement.Disposition = DispositionUnresolved
		return judgement, nil
	}
	if equalHash(auditor, reference) {
		judgement.Disposition = DispositionPrune
		return judgement, nil
	}
	judgement.Disposition = DispositionSuspect
	info := s.trees[ref.Tree]
	switch {
	case info.descendable(ref.Position):
		return judgement, &task{tree: ref.Tree, node: ref.Position}
	case info.onPath(ref.Position):
		if ref.Tree.Layer == hpp.LayerSegment {
			judgement.Classification = AuthenticationNodeMismatch
			if _, requested := s.addressByLeaf[ref]; requested {
				judgement.Classification = LeafMismatch
			}
			return judgement, nil
		}
		child, linked := info.childTree[ref.Position.Index]
		childInfo, planned := s.trees[child]
		if !linked || !planned {
			judgement.Classification = AuthenticationNodeMismatch
			return judgement, nil
		}
		state.committed[child] = reference
		return judgement, &task{tree: child, node: childInfo.top(), rootCommit: true}
	default:
		// An authentication node the auditor supplied with a different value:
		// the auditor holds nothing beneath it to descend with.
		judgement.Classification = AuthenticationNodeMismatch
		return judgement, nil
	}
}
