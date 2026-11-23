package localization

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// suspectKeys reduces suspects to what both strategies must agree on.
func suspectKeys(suspects []Suspect) []string {
	keys := make([]string, 0, len(suspects))
	for _, suspect := range suspects {
		address := ""
		if suspect.Address != nil {
			address = fmt.Sprintf("%+v", *suspect.Address)
		}
		keys = append(keys, fmt.Sprintf("%+v|%s|%x|%x|%s", suspect.Ref, address, suspect.AuditorHash,
			suspect.ReferenceHash, suspect.Classification))
	}
	return keys
}

func TestACHPLocalizesSingleTamperedLeaf(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 24, 7, 3)
	tampered := addresses[10:11]
	sc := newScenario(t, f, addresses, tampered)
	service := deterministicService(t, sc.hpp, nil)

	result := localizeOK(t, service, sc, StrategyDefault)
	proof := result.Proof
	if proof.Strategy != StrategyACHP || proof.FallbackReason != "" || proof.ACHP == nil {
		t.Fatalf("strategy = %q fallback = %q transcript = %v, want ACHP without fallback",
			proof.Strategy, proof.FallbackReason, proof.ACHP)
	}
	if result.CalculatedReferenceRoot != f.root {
		t.Fatal("reference root is not the anchored root")
	}
	if len(proof.Suspects) != 1 || proof.Suspects[0].Classification != LeafMismatch ||
		proof.Suspects[0].Address == nil || *proof.Suspects[0].Address != tampered[0] {
		t.Fatalf("suspects = %+v, want one leaf mismatch at %+v", proof.Suspects, tampered[0])
	}
	if len(proof.Unresolved) != 0 || len(proof.BadShards) != 1 {
		t.Fatalf("unresolved = %v bad shards = %v, want none and one", proof.Unresolved, proof.BadShards)
	}
}

// ACHP and the fixed-depth traversal must reach identical conclusions: the same
// suspects, with the same authenticated hashes, and the same bad shards.
func TestACHPAgreesWithFixedDepthOnRandomTampering(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	random := rand.New(rand.NewSource(7))
	for trial := 0; trial < 40; trial++ {
		addresses := pickAddresses(f, 3+random.Intn(60), 1+random.Intn(40), random.Intn(len(f.addresses)))
		var tampered []hpp.PhysicalAddress
		for _, index := range random.Perm(len(addresses))[:1+random.Intn(min(5, len(addresses)))] {
			tampered = append(tampered, addresses[index])
		}
		sc := newScenario(t, f, addresses, tampered)
		// Half the trials also alter a supplied authentication node.
		if trial%2 == 1 {
			for index := range sc.failed.Nodes {
				if sc.failed.Nodes[index].Ref.Tree.Layer == hpp.LayerSegment && sc.failed.Nodes[index].Ref.Position.Level > 0 {
					sc.failed.Nodes[index].Hash[3] ^= 0x5a
					break
				}
			}
			root, err := hpp.VerifyHMFProof(sc.failed, addresses)
			if err != nil {
				t.Fatalf("trial %d: failed root: %v", trial, err)
			}
			sc.auditor = root
		}
		service := deterministicService(t, sc.hpp, func(config *ACHPConfig) {
			config.MaxCandidates = 1 + random.Intn(16)
			config.MismatchPrior = []float64{1e-6, 1e-3, 0.1, 0.5}[random.Intn(4)]
		})
		achp := localizeOK(t, service, sc, StrategyACHP)
		fixed := localizeOK(t, service, sc, StrategyFixedDepth)
		if achp.Proof.Strategy != StrategyACHP || fixed.Proof.Strategy != StrategyFixedDepth {
			t.Fatalf("trial %d: strategies %q and %q", trial, achp.Proof.Strategy, fixed.Proof.Strategy)
		}
		if len(achp.Proof.Unresolved) != 0 {
			t.Fatalf("trial %d: unexpected unresolved nodes %v", trial, achp.Proof.Unresolved)
		}
		if !reflect.DeepEqual(suspectKeys(achp.Proof.Suspects), suspectKeys(fixed.Proof.Suspects)) {
			t.Fatalf("trial %d: ACHP suspects differ from fixed-depth\nACHP:  %v\nfixed: %v", trial,
				suspectKeys(achp.Proof.Suspects), suspectKeys(fixed.Proof.Suspects))
		}
		if !reflect.DeepEqual(achp.Proof.BadShards, fixed.Proof.BadShards) {
			t.Fatalf("trial %d: bad shards %v, fixed-depth %v", trial, achp.Proof.BadShards, fixed.Proof.BadShards)
		}
	}
}

// A shard whose commitment matches is pruned, and nothing beneath it is read.
func TestACHPPrunesMatchingBranchesWithoutReadingThem(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 90, 5, 1) // touches every region, shard and many segments
	tampered := addresses[40:41]
	sc := newScenario(t, f, addresses, tampered)
	service := deterministicService(t, sc.hpp, nil)

	result := localizeOK(t, service, sc, StrategyACHP)
	if len(result.Proof.Suspects) != 1 || result.Proof.Suspects[0].Classification != LeafMismatch {
		t.Fatalf("suspects = %+v", result.Proof.Suspects)
	}
	bad := tampered[0]
	for _, ref := range sc.store.fetchedRefs() {
		if ref.Tree.Layer != hpp.LayerSegment {
			continue
		}
		if ref.Tree.RegionID != bad.RegionID || ref.Tree.ShardID != bad.ShardID || ref.Tree.SegmentID != bad.SegmentID {
			t.Fatalf("ACHP read %+v inside a segment that matches its commitment", ref)
		}
	}
	reads := len(sc.store.fetchedRefs())
	sc.store.resetCalls()
	localizeOK(t, service, sc, StrategyFixedDepth)
	if fixedReads := len(sc.store.fetchedRefs()); reads >= fixedReads {
		t.Fatalf("ACHP read %d nodes, fixed-depth %d: pruning saved nothing", reads, fixedReads)
	}
}

func TestACHPFindsTamperedLeavesInDifferentRegionsAtOnce(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 60, 9, 2)
	var tampered []hpp.PhysicalAddress
	regions := map[string]bool{}
	for _, address := range addresses {
		if !regions[address.RegionID] {
			regions[address.RegionID] = true
			tampered = append(tampered, address)
		}
	}
	sc := newScenario(t, f, addresses, tampered)
	result := localizeOK(t, deterministicService(t, sc.hpp, nil), sc, StrategyACHP)
	if len(result.Proof.Suspects) != len(tampered) || len(result.Proof.BadShards) != len(tampered) {
		t.Fatalf("suspects = %d bad shards = %d, want %d each", len(result.Proof.Suspects),
			len(result.Proof.BadShards), len(tampered))
	}
}

func TestACHPReportsAlteredAuthenticationNode(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 12, 11, 4)
	sc := newScenario(t, f, addresses, nil)
	var altered hpp.NodeRef
	for index := range sc.failed.Nodes {
		if ref := sc.failed.Nodes[index].Ref; ref.Tree.Layer == hpp.LayerSegment && ref.Position.Level > 0 {
			sc.failed.Nodes[index].Hash[0] ^= 0xff
			altered = ref
			break
		}
	}
	root, err := hpp.VerifyHMFProof(sc.failed, addresses)
	if err != nil {
		t.Fatalf("failed root: %v", err)
	}
	sc.auditor = root
	result := localizeOK(t, deterministicService(t, sc.hpp, nil), sc, StrategyACHP)
	if len(result.Proof.Suspects) != 1 || result.Proof.Suspects[0].Classification != AuthenticationNodeMismatch ||
		result.Proof.Suspects[0].Ref != altered {
		t.Fatalf("suspects = %+v, want the altered authentication node %+v", result.Proof.Suspects, altered)
	}
}

// ---- invalid or missing evidence ----

// Evidence that does not authenticate is never accepted: the branch it was
// meant to settle stays unresolved and nothing is concluded from it.
func TestACHPInvalidEvidenceStaysUnresolved(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 40, 6, 5)
	tampered := addresses[5:6]
	sc := newScenario(t, f, addresses, tampered)
	service := deterministicService(t, sc.hpp, nil)
	// First, learn which segment nodes ACHP reads for the clean store.
	clean := localizeOK(t, service, sc, StrategyACHP)
	if len(clean.Proof.Suspects) != 1 {
		t.Fatalf("clean run suspects = %+v", clean.Proof.Suspects)
	}
	var victim hpp.NodeRef
	for _, ref := range sc.store.fetchedRefs() {
		if ref.Tree.Layer == hpp.LayerSegment && ref.Position.Level > 0 {
			victim = ref
			break
		}
	}
	if victim == (hpp.NodeRef{}) {
		t.Fatal("ACHP fetched no interior segment node")
	}

	changed := sc.forest.nodes[victim.Tree][victim.Position]
	changed[7] ^= 0x01
	sc.store.override[victim] = changed
	result, err := service.Localize(context.Background(), sc.request(StrategyACHP))
	if err != nil {
		t.Fatalf("localize: %v", err)
	}
	proof := result.Proof
	if proof.Strategy != StrategyACHP {
		t.Fatalf("strategy = %q (%s), want ACHP", proof.Strategy, proof.FallbackReason)
	}
	if len(proof.Suspects) != 0 {
		t.Fatalf("suspects = %+v: a leaf was confirmed from evidence that does not authenticate", proof.Suspects)
	}
	if len(proof.Unresolved) != 1 || proof.Unresolved[0].Reason != EvidenceInvalid ||
		proof.Unresolved[0].Ref.Tree != victim.Tree {
		t.Fatalf("unresolved = %+v, want the segment unresolved as invalid evidence", proof.Unresolved)
	}
	if err := VerifyProof(proof, addresses, sc.forest.root); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestACHPMissingEvidenceStaysUnresolvedWhileOtherBranchesFinish(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 70, 3, 0)
	// Two tampered leaves in two different segments.
	var tampered []hpp.PhysicalAddress
	seen := map[hpp.SegmentKey]bool{}
	for _, address := range addresses {
		key := hpp.SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
		if !seen[key] && len(tampered) < 2 {
			seen[key] = true
			tampered = append(tampered, address)
		}
	}
	if len(tampered) != 2 {
		t.Fatal("need two segments")
	}
	sc := newScenario(t, f, addresses, tampered)
	service := deterministicService(t, sc.hpp, nil)
	clean := localizeOK(t, service, sc, StrategyACHP)
	if len(clean.Proof.Suspects) != 2 {
		t.Fatalf("clean run suspects = %+v", clean.Proof.Suspects)
	}
	var victim hpp.NodeRef
	for _, ref := range sc.store.fetchedRefs() {
		if ref.Tree.Layer == hpp.LayerSegment && ref.Tree.SegmentID == tampered[0].SegmentID &&
			ref.Tree.ShardID == tampered[0].ShardID && ref.Tree.RegionID == tampered[0].RegionID {
			victim = ref
		}
	}
	sc.store.omit[victim] = true

	result, err := service.Localize(context.Background(), sc.request(StrategyACHP))
	if err != nil {
		t.Fatalf("localize: %v", err)
	}
	proof := result.Proof
	if proof.Strategy != StrategyACHP {
		t.Fatalf("strategy = %q (%s)", proof.Strategy, proof.FallbackReason)
	}
	if len(proof.Unresolved) != 1 || proof.Unresolved[0].Reason != EvidenceMissing || proof.Unresolved[0].Ref.Tree != victim.Tree {
		t.Fatalf("unresolved = %+v, want only the segment with the missing node", proof.Unresolved)
	}
	if len(proof.Suspects) != 1 || *proof.Suspects[0].Address != tampered[1] {
		t.Fatalf("suspects = %+v, want only the leaf in the segment that could be read", proof.Suspects)
	}
	if err := VerifyProof(proof, addresses, sc.forest.root); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestACHPLeafCountDisagreementIsATopologyMismatch(t *testing.T) {
	spec := defaultForestSpec()
	reference := buildForest(t, spec)
	// The auditor's forest has one more leaf in segment (R0, 0, 0): same
	// height, different leaf count and content.
	altered := spec
	altered.leaves = func(region, shard, segment int) int {
		if region == 0 && shard == 0 && segment == 0 {
			return spec.leaves(region, shard, segment) + 1
		}
		return spec.leaves(region, shard, segment)
	}
	other := buildForest(t, altered)
	addresses := []hpp.PhysicalAddress{
		{RegionID: "R0", ShardID: 0, SegmentID: 0, LeafID: 2},
		{RegionID: "R1", ShardID: 1, SegmentID: 1, LeafID: 3},
	}
	auditorStore := newStore(other)
	auditorService, _ := hpp.NewService(auditorStore, auditorStore)
	failedResult, err := auditorService.BuildAndCalculate(context.Background(), addresses)
	if err != nil {
		t.Fatalf("auditor proof: %v", err)
	}
	st := newStore(reference)
	service, _ := hpp.NewService(st, st)
	referenceResult, err := service.BuildAndVerify(context.Background(), addresses, reference.root)
	if err != nil {
		t.Fatalf("reference proof: %v", err)
	}
	sc := scenario{forest: reference, store: st, hpp: service, addresses: addresses,
		reference: referenceResult, failed: failedResult.Proof, auditor: failedResult.CalculatedGlobalRoot}

	localizer := deterministicService(t, service, nil)
	achp := localizeOK(t, localizer, sc, StrategyACHP)
	fixed := localizeOK(t, localizer, sc, StrategyFixedDepth)
	if achp.Proof.Strategy != StrategyACHP {
		t.Fatalf("strategy = %q (%s)", achp.Proof.Strategy, achp.Proof.FallbackReason)
	}
	topology := 0
	for _, suspect := range achp.Proof.Suspects {
		if suspect.Classification == TopologyMismatch {
			topology++
		}
	}
	if topology != 1 {
		t.Fatalf("suspects = %+v, want one topology mismatch", achp.Proof.Suspects)
	}
	if !reflect.DeepEqual(suspectKeys(achp.Proof.Suspects), suspectKeys(fixed.Proof.Suspects)) {
		t.Fatalf("ACHP suspects %v differ from fixed-depth %v", suspectKeys(achp.Proof.Suspects),
			suspectKeys(fixed.Proof.Suspects))
	}
	if len(achp.Proof.Unresolved) != 0 {
		t.Fatalf("unresolved = %+v", achp.Proof.Unresolved)
	}
}

// ---- termination and fallback ----

func TestACHPTerminatesUnderExtremeCoefficients(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 50, 4, 9)
	sc := newScenario(t, f, addresses, addresses[20:23])
	extremes := []func(*ACHPConfig){
		func(c *ACHPConfig) { c.MaxCandidates = 1; c.Costs.NetworkRTT = time.Hour },
		func(c *ACHPConfig) {
			c.Costs.NetworkRTT = 0
			c.Costs.PartitionAccess = 0
			c.Costs.RowRead = time.Second
		},
		func(c *ACHPConfig) { c.MismatchPrior = 1e-12 },
		func(c *ACHPConfig) { c.MismatchPrior = 1 - 1e-12 },
		func(c *ACHPConfig) { c.Costs = CostCoefficients{Concurrency: 1, NetworkBytesPerSecond: 1} },
	}
	want := localizeOK(t, deterministicService(t, sc.hpp, nil), sc, StrategyFixedDepth)
	for index, mutate := range extremes {
		result := localizeOK(t, deterministicService(t, sc.hpp, mutate), sc, StrategyACHP)
		if result.Proof.Strategy != StrategyACHP {
			t.Fatalf("extreme %d: fell back: %s", index, result.Proof.FallbackReason)
		}
		bound := 2
		for _, info := range mustStructure(t, sc).trees {
			bound += int(info.height) + 1
		}
		if len(result.Proof.ACHP.Rounds) > bound {
			t.Fatalf("extreme %d: %d rounds exceeds the bound %d", index, len(result.Proof.ACHP.Rounds), bound)
		}
		if !reflect.DeepEqual(suspectKeys(result.Proof.Suspects), suspectKeys(want.Proof.Suspects)) {
			t.Fatalf("extreme %d: suspects differ from fixed-depth", index)
		}
	}
}

func mustStructure(t testing.TB, sc scenario) *structure {
	t.Helper()
	s, err := newStructure(sc.failed, sc.addresses)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Every replan expands the suspect node itself, so descent never stalls.
func TestACHPEveryCandidateDescends(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 80, 3, 1)
	sc := newScenario(t, f, addresses, addresses[:1])
	s := mustStructure(t, sc)
	for _, mutate := range []func(*ACHPConfig){nil, func(c *ACHPConfig) { c.MaxCandidates = 3 }} {
		config := DefaultACHPConfig()
		if mutate != nil {
			mutate(&config)
		}
		model := newCostModel(config, newEstimator(config), s)
		generator := &candidateGenerator{structure: s, model: model, limit: config.MaxCandidates}
		var tasks []task
		for _, tree := range s.order {
			info := s.trees[tree]
			if tree.Layer == hpp.LayerShard && info.descendable(info.top()) {
				tasks = append(tasks, task{tree: tree, node: info.top(), rootCommit: true})
			}
		}
		sortTasks(tasks)
		for _, joint := range generator.generate(tasks) {
			if len(joint.plans) != len(tasks) {
				t.Fatalf("%s covers %d of %d tasks", joint.label, len(joint.plans), len(tasks))
			}
			for _, plan := range joint.plans {
				if len(plan.expanded) == 0 || plan.expanded[0] != plan.task.node {
					t.Fatalf("%s does not expand its suspect node %+v", joint.label, plan.task.node)
				}
				for _, position := range plan.frontier {
					if position.Level >= plan.task.node.Level {
						t.Fatalf("%s frontier node %+v is not below %+v", joint.label, position, plan.task.node)
					}
				}
			}
		}
	}
}

func TestACHPFallsBackWhenReferenceCannotRetrieveFrontiers(t *testing.T) {
	sc := tinyScenario(t)
	service, err := NewService(staticReference{result: sc.reference})
	if err != nil {
		t.Fatal(err)
	}
	result := localizeOK(t, service, sc, StrategyDefault)
	if result.Proof.Strategy != StrategyFixedDepth || result.Proof.FallbackReason == "" ||
		result.Proof.ACHP != nil || result.Proof.K != DefaultJumpLevels {
		t.Fatalf("proof strategy %q fallback %q k %d, want a fixed-depth fallback",
			result.Proof.Strategy, result.Proof.FallbackReason, result.Proof.K)
	}
	if len(result.Proof.Suspects) != 1 || result.Proof.Suspects[0].Classification != LeafMismatch {
		t.Fatalf("suspects = %+v", result.Proof.Suspects)
	}
}

func TestACHPFallsBackWhenTheFirstRetrievalFails(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 20, 5, 2)
	sc := newScenario(t, f, addresses, addresses[3:4])
	global := hpp.TreeRef{Layer: hpp.LayerGlobal}
	sc.store.omit[hpp.NodeRef{Tree: global, Position: hpp.NodePosition{Level: 2, Index: 0}}] = true
	result, err := deterministicService(t, sc.hpp, nil).Localize(context.Background(), sc.request(StrategyACHP))
	if err != nil {
		t.Fatalf("localize: %v", err)
	}
	if result.Proof.Strategy != StrategyFixedDepth || result.Proof.FallbackReason == "" {
		t.Fatalf("strategy %q fallback %q, want the fixed-depth fallback", result.Proof.Strategy, result.Proof.FallbackReason)
	}
}

func TestServiceStrategySelection(t *testing.T) {
	sc := tinyScenario(t)
	fixedService, err := NewService(sc.hpp, WithStrategy(StrategyFixedDepth))
	if err != nil {
		t.Fatal(err)
	}
	if got := localizeOK(t, fixedService, sc, StrategyDefault).Proof.Strategy; got != StrategyFixedDepth {
		t.Fatalf("service default strategy = %q, want fixed-depth", got)
	}
	if got := localizeOK(t, fixedService, sc, StrategyACHP).Proof.Strategy; got != StrategyACHP {
		t.Fatalf("per-request strategy = %q, want ACHP", got)
	}
	if _, err := fixedService.Localize(context.Background(), sc.request("bogus")); err == nil {
		t.Fatal("unknown strategy accepted")
	}
	if _, err := NewService(sc.hpp, WithStrategy("bogus")); err == nil {
		t.Fatal("unknown default strategy accepted")
	}
	bad := DefaultACHPConfig()
	bad.MismatchPrior = 0
	if _, err := NewService(sc.hpp, WithACHPConfig(bad)); err == nil {
		t.Fatal("invalid ACHP configuration accepted")
	}
}

func TestACHPConfigValidation(t *testing.T) {
	if err := DefaultACHPConfig().Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	for name, mutate := range map[string]func(*ACHPConfig){
		"no candidates":   func(c *ACHPConfig) { c.MaxCandidates = 0 },
		"prior zero":      func(c *ACHPConfig) { c.MismatchPrior = 0 },
		"prior one":       func(c *ACHPConfig) { c.MismatchPrior = 1 },
		"no strength":     func(c *ACHPConfig) { c.PriorStrength = 0 },
		"no concurrency":  func(c *ACHPConfig) { c.Costs.Concurrency = 0 },
		"negative rtt":    func(c *ACHPConfig) { c.Costs.NetworkRTT = -1 },
		"no bandwidth":    func(c *ACHPConfig) { c.Costs.NetworkBytesPerSecond = 0 },
		"adaptation rate": func(c *ACHPConfig) { c.Costs.AdaptationRate = 2 },
	} {
		config := DefaultACHPConfig()
		mutate(&config)
		if config.Validate() == nil {
			t.Errorf("%s: invalid config accepted", name)
		}
	}
}

// ---- forged transcripts ----

func TestVerifyProofRejectsForgedACHPTranscripts(t *testing.T) {
	f := buildForest(t, defaultForestSpec())
	addresses := pickAddresses(f, 40, 7, 2)
	sc := newScenario(t, f, addresses, addresses[8:9])
	result := localizeOK(t, deterministicService(t, sc.hpp, nil), sc, StrategyACHP)
	good := result.Proof
	if len(good.ACHP.Rounds) < 3 {
		t.Fatalf("only %d rounds; the forgeries below need a multi-round proof", len(good.ACHP.Rounds))
	}

	deepCopy := func() Proof {
		clone := good
		transcript := *good.ACHP
		transcript.Rounds = make([]ACHPRound, len(good.ACHP.Rounds))
		for index, round := range good.ACHP.Rounds {
			round.Expansions = make([]Expansion, len(good.ACHP.Rounds[index].Expansions))
			for position, expansion := range good.ACHP.Rounds[index].Expansions {
				expansion.Fetched = append([]hpp.ProofNode(nil), expansion.Fetched...)
				expansion.Judgements = append([]NodeJudgement(nil), expansion.Judgements...)
				expansion.Expanded = append([]hpp.NodePosition(nil), expansion.Expanded...)
				round.Expansions[position] = expansion
			}
			transcript.Rounds[index] = round
		}
		clone.ACHP = &transcript
		clone.Suspects = append([]Suspect(nil), good.Suspects...)
		clone.Rounds = append([]PruningRound(nil), good.Rounds...)
		clone.BadShards = append([]hpp.TreeRef(nil), good.BadShards...)
		return clone
	}
	// firstPrune returns the round and expansion holding a pruned judgement.
	type location struct{ round, expansion, judgement int }
	find := func(proof Proof, want Disposition) location {
		for r, round := range proof.ACHP.Rounds {
			for e, expansion := range round.Expansions {
				for j, judgement := range expansion.Judgements {
					if judgement.Disposition == want {
						return location{r, e, j}
					}
				}
			}
		}
		t.Fatalf("no %s judgement in the transcript", want)
		return location{}
	}

	forgeries := map[string]func(*Proof){
		"prune turned into suspect": func(p *Proof) {
			at := find(*p, DispositionPrune)
			p.ACHP.Rounds[at.round].Expansions[at.expansion].Judgements[at.judgement].Disposition = DispositionSuspect
		},
		"suspect turned into prune": func(p *Proof) {
			at := find(*p, DispositionSuspect)
			p.ACHP.Rounds[at.round].Expansions[at.expansion].Judgements[at.judgement].Disposition = DispositionPrune
		},
		"fetched hash altered": func(p *Proof) {
			p.ACHP.Rounds[1].Expansions[0].Fetched[0].Hash[0] ^= 1
		},
		"fetched node dropped": func(p *Proof) {
			e := &p.ACHP.Rounds[1].Expansions[0]
			e.Fetched = e.Fetched[1:]
		},
		"reference hash altered": func(p *Proof) {
			at := find(*p, DispositionPrune)
			p.ACHP.Rounds[at.round].Expansions[at.expansion].Judgements[at.judgement].ReferenceHash[1] ^= 1
		},
		"suspect branch skipped": func(p *Proof) {
			last := len(p.ACHP.Rounds) - 1
			p.ACHP.Rounds = p.ACHP.Rounds[:last]
		},
		"whole expansion removed": func(p *Proof) {
			p.ACHP.Rounds[1].Expansions = nil
		},
		"suspect invented": func(p *Proof) {
			extra := p.Suspects[0]
			extra.Ref.Position.Index++
			p.Suspects = append(p.Suspects, extra)
		},
		"suspect hidden":   func(p *Proof) { p.Suspects = nil },
		"bad shard hidden": func(p *Proof) { p.BadShards = nil },
		"unresolved invented": func(p *Proof) {
			p.Unresolved = []UnresolvedNode{{Ref: p.Suspects[0].Ref, Reason: EvidenceMissing}}
		},
		"expansion of an unknown node": func(p *Proof) {
			p.ACHP.Rounds[1].Expansions[0].Node.Index += 100
		},
		"expanded set altered": func(p *Proof) {
			e := &p.ACHP.Rounds[1].Expansions[0]
			e.Expanded = append(e.Expanded, hpp.NodePosition{Level: 99, Index: 0})
		},
		"transcript removed":             func(p *Proof) { p.ACHP = nil },
		"fixed-depth k on an ACHP proof": func(p *Proof) { p.K = DefaultJumpLevels },
		"round view altered": func(p *Proof) {
			p.Rounds = append([]PruningRound(nil), p.Rounds...)
			p.Rounds[0].Comparisons = nil
		},
	}
	for name, forge := range forgeries {
		proof := deepCopy()
		forge(&proof)
		if err := VerifyProof(proof, addresses, sc.forest.root); !errors.Is(err, ErrInvalidProof) {
			t.Errorf("%s: verify error = %v, want %v", name, err, ErrInvalidProof)
		}
	}
	other := sc.forest.root
	other[0] ^= 1
	if err := VerifyProof(deepCopy(), addresses, other); !errors.Is(err, ErrInvalidProof) {
		t.Errorf("wrong trusted root: verify error = %v, want %v", err, ErrInvalidProof)
	}
	if err := VerifyProof(deepCopy(), addresses[1:], sc.forest.root); !errors.Is(err, ErrInvalidProof) {
		t.Errorf("wrong addresses: verify error = %v, want %v", err, ErrInvalidProof)
	}
	if err := VerifyProof(good, addresses, sc.forest.root); err != nil {
		t.Errorf("unmodified proof rejected: %v", err)
	}
}

// ---- helpers ----

// tinyScenario is the one-leaf fixture of the fixed-depth tests, served by an
// hpp.Service that can also retrieve explicit nodes.
func tinyScenario(t testing.TB) scenario {
	t.Helper()
	spec := forestSpec{regions: 1, shardsPerRegion: 1,
		segments: func(int, int) int { return 2 },
		leaves:   func(int, int, int) int { return 4 }}
	f := buildForest(t, spec)
	addresses := []hpp.PhysicalAddress{{RegionID: "R0", ShardID: 0, SegmentID: 1, LeafID: 2}}
	return newScenario(t, f, addresses, addresses)
}
