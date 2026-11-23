package localization

import (
	"fmt"
	"reflect"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// verifyACHP lets an auditor replay an ACHP localization from the failed proof,
// the expected addresses and the trusted root alone.
//
// The replay re-derives everything that matters and trusts nothing the
// localizer says about it: every retrieved frontier must reproduce an
// authenticated commitment (the global tree from trustedRoot, every deeper
// node from one authenticated before it), every pruning and suspect judgement
// must follow from the authenticated hashes, every suspect branch must be
// expanded in the following round or be reported unresolved, and the proof's
// suspects, unresolved nodes, bad shards and comparison transcript must equal
// what the replay derives. Cost estimates, candidate sets and the depths chosen
// are not verified: they only steer retrieval, and no replayed conclusion
// depends on them.
func verifyACHP(proof Proof, addresses []hpp.PhysicalAddress, trustedRoot [32]byte) error {
	if proof.K != 0 || proof.ACHP == nil {
		return fmt.Errorf("%w: ACHP proof carries no ACHP transcript or a fixed-depth k", ErrInvalidProof)
	}
	if !equalHash(proof.AnchoredGlobalRoot, trustedRoot) || !equalHash(proof.ReferenceGlobalRoot, trustedRoot) {
		return fmt.Errorf("%w: reference root does not match trusted root", ErrInvalidProof)
	}
	auditorTrace, err := hpp.TraceHMFProof(proof.FailedProof, addresses)
	if err != nil {
		return fmt.Errorf("%w: auditor proof: %v", ErrInvalidProof, err)
	}
	if !equalHash(auditorTrace.GlobalRoot, proof.AuditorGlobalRoot) || equalHash(proof.AuditorGlobalRoot, trustedRoot) {
		return fmt.Errorf("%w: auditor proof is not the reported failed computation", ErrInvalidProof)
	}
	s, err := newStructure(proof.FailedProof, addresses)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	if _, ok := s.trees[hpp.TreeRef{Layer: hpp.LayerGlobal}]; !ok {
		return fmt.Errorf("%w: failed proof has no global tree", ErrInvalidProof)
	}

	replay := newEngine(s, auditorTrace, trustedRoot)
	for index, round := range proof.ACHP.Rounds {
		if round.Index != index+1 {
			return fmt.Errorf("%w: round %d is numbered %d", ErrInvalidProof, index+1, round.Index)
		}
		for position := range round.Expansions {
			// apply fills the expansion it is given, so replay a copy.
			expansion := round.Expansions[position]
			expansion.Judgements = append([]NodeJudgement(nil), expansion.Judgements...)
			if err := replay.apply(&expansion, true); err != nil {
				return fmt.Errorf("%w: round %d: %v", ErrInvalidProof, round.Index, err)
			}
		}
		if _, err := replay.endRound(); err != nil {
			return fmt.Errorf("%w: round %d: %v", ErrInvalidProof, round.Index, err)
		}
	}
	if err := replay.finish(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}

	badShards, rounds, suspects, unresolved := replay.results()
	if !reflect.DeepEqual(badShards, proof.BadShards) || !reflect.DeepEqual(suspects, proof.Suspects) ||
		!reflect.DeepEqual(unresolved, proof.Unresolved) || !reflect.DeepEqual(rounds, proof.Rounds) {
		return fmt.Errorf("%w: pruning transcript was altered or is incomplete", ErrInvalidProof)
	}
	return nil
}
