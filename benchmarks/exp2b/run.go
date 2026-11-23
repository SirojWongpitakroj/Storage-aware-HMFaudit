package exp2b

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
)

// Algorithm is one localization strategy under test, wired to its own counting
// reader so its reads are never mixed with another strategy's.
type Algorithm struct {
	// Name labels the rows: ACHP, FIXED or EVSEB.
	Name      string
	Requested localization.Strategy
	Service   *localization.Service
	Reader    *MeasuredReader
	// K is the fixed-depth jump size passed in the request (0 selects the
	// service default).
	K int32
	// ResetObserved and ObservedReads expose the storage driver's own count of
	// successful partition queries when one exists (the Cassandra reader's
	// ReadStats); both may be nil.
	ResetObserved func()
	ObservedReads func() int64
}

// Environment is the storage under the experiment.
type Environment interface {
	// Addresses maps dataset ordinals to physical addresses, in the order given.
	Addresses(ordinals []int) ([]hpp.PhysicalAddress, error)
	// Inject corrupts the records, persistently, in the auditor's log store.
	Inject(ctx context.Context, ordinals []int) error
	// Restore returns every injected record to its original content. It must
	// never touch a reference commitment.
	Restore(ctx context.Context) error
	// FailedProof is the auditor's evidence for the audit batch under the
	// current (corrupted) logs, and the root it computes.
	FailedProof(ctx context.Context, addresses []hpp.PhysicalAddress) (hpp.HMFProof, [32]byte, error)
	// TrustedRoot is the finalized checkpoint root every authentication is
	// checked against.
	TrustedRoot() [32]byte
}

// Config controls a run.
type Config struct {
	Algorithms []Algorithm
	// VerifyProofs replays each localization proof against the trusted root,
	// outside the timed operation.
	VerifyProofs bool
	// Sink receives every measured row as it is produced.
	Sink     func(RawRow) error
	Progress func(format string, args ...any)
}

func (c Config) progress(format string, args ...any) {
	if c.Progress != nil {
		c.Progress(format, args...)
	}
}

// Run executes every case of the manifests: for each query, corruption count
// and pattern, the warm-up cases and then the measured ones. For every case the
// records are corrupted once, the auditor's failed proof is built once, and each
// algorithm then localizes it, so all algorithms see exactly the same corruption
// and evidence. The algorithm order rotates from case to case.
//
// The timed operation is only Localize. Query construction, corruption
// injection, the initial batch verification (the failed proof), proof replay
// and restoration are all outside it.
func Run(ctx context.Context, queries QueryManifest, corruption CorruptionManifest, env Environment,
	cfg Config) ([]RawRow, error) {
	if len(cfg.Algorithms) == 0 {
		return nil, fmt.Errorf("exp2b: no algorithms")
	}
	var rows []RawRow
	caseNumber := 0
	for _, query := range queries.Queries {
		batch, err := env.Addresses(query.Ordinals)
		if err != nil {
			return rows, fmt.Errorf("exp2b: %s: %w", query.ID, err)
		}
		for _, count := range queries.Params.CorruptionCounts {
			for _, pattern := range Patterns(count) {
				for _, c := range corruption.CasesFor(query.ID, count, pattern) {
					caseRows, err := runCase(ctx, env, cfg, batch, c, caseNumber)
					caseNumber++
					if err != nil {
						return rows, err
					}
					if c.Phase == PhaseWarmup {
						continue
					}
					for _, row := range caseRows {
						rows = append(rows, row)
						if cfg.Sink != nil {
							if err := cfg.Sink(row); err != nil {
								return rows, fmt.Errorf("exp2b: write row: %w", err)
							}
						}
					}
				}
				cfg.progress("%s m=%d %s done (%d rows so far)", query.ID, count, pattern, len(rows))
			}
		}
	}
	return rows, nil
}

func runCase(ctx context.Context, env Environment, cfg Config, batch []hpp.PhysicalAddress, c Case,
	caseNumber int) (rows []RawRow, err error) {
	corrupted, err := env.Addresses(c.Ordinals())
	if err != nil {
		return nil, err
	}
	if err := env.Inject(ctx, c.Ordinals()); err != nil {
		_ = env.Restore(ctx)
		return nil, fmt.Errorf("exp2b: inject %s m=%d %s #%d: %w", c.QueryID, c.Count, c.Pattern, c.Repetition, err)
	}
	defer func() {
		if restoreErr := env.Restore(ctx); restoreErr != nil && err == nil {
			err = fmt.Errorf("exp2b: restore after %s m=%d %s #%d: %w", c.QueryID, c.Count, c.Pattern, c.Repetition, restoreErr)
		}
	}()
	proof, auditorRoot, err := env.FailedProof(ctx, batch)
	if err != nil {
		return nil, fmt.Errorf("exp2b: failed proof for %s: %w", c.QueryID, err)
	}
	trusted := env.TrustedRoot()
	if auditorRoot == trusted {
		return nil, fmt.Errorf("exp2b: corrupting %v did not change the auditor's root", c.Ordinals())
	}
	expected := make(map[hpp.PhysicalAddress]struct{}, len(corrupted))
	for _, address := range corrupted {
		expected[address] = struct{}{}
	}
	order := make([]int, len(cfg.Algorithms))
	for index := range order {
		order[index] = (index + caseNumber) % len(cfg.Algorithms)
	}
	for _, index := range order {
		row := measure(ctx, cfg.Algorithms[index], cfg.VerifyProofs, batch, proof, auditorRoot, trusted, expected, c)
		rows = append(rows, row)
	}
	return rows, nil
}

// measure times one Localize call and judges its answer.
func measure(ctx context.Context, alg Algorithm, verify bool, batch []hpp.PhysicalAddress,
	failed hpp.HMFProof, auditorRoot, trusted [32]byte, expected map[hpp.PhysicalAddress]struct{}, c Case) RawRow {
	row := RawRow{
		Algorithm: alg.Name, RequestedStrategy: strategyName(alg.Requested), QueryID: c.QueryID,
		CorruptionCount: c.Count, Pattern: c.Pattern, Repetition: c.Repetition, Seed: c.Seed,
		CorruptedOrdinals: c.Ordinals(), DistinctSegments: c.DistinctSegments, PlanningMS: -1, CassandraReads: -1,
	}
	request := localization.Request{
		Addresses: slices.Clone(batch), AuditorGlobalRoot: auditorRoot, FailedProof: failed,
		AnchoredGlobalRoot: trusted, K: alg.K, Strategy: alg.Requested,
	}
	alg.Reader.Reset()
	if alg.ResetObserved != nil {
		alg.ResetObserved()
	}

	started := time.Now()
	result, err := alg.Service.Localize(ctx, request)
	elapsed := time.Since(started)

	counters := alg.Reader.Snapshot()
	row.LatencyMS = float64(elapsed) / float64(time.Millisecond)
	row.PartitionReads = counters.PartitionReads
	row.DistinctPartitions = counters.DistinctPartitions
	row.MetadataReads = counters.MetadataReads
	row.RetrievalRounds = counters.RetrievalRounds
	row.NodesRetrieved = counters.NodesRetrieved
	row.EvidenceBytes = counters.EvidenceBytes
	row.RetrievalMS = float64(counters.RetrievalTime) / float64(time.Millisecond)
	if alg.ObservedReads != nil {
		row.CassandraReads = alg.ObservedReads()
	}
	if err != nil {
		row.Status, row.Error = StatusError, err.Error()
		row.Missed = len(expected)
		row.ExecutedStrategy = "NONE"
		return row
	}

	proof := result.Proof
	row.ExecutedStrategy = strategyName(proof.Strategy)
	if proof.Strategy == "" {
		row.ExecutedStrategy = strategyName(localization.StrategyFixedDepth)
	}
	row.Fallback = alg.Requested == localization.StrategyACHP && proof.Strategy != localization.StrategyACHP
	row.FallbackReason = proof.FallbackReason
	row.Unresolved = len(proof.Unresolved)

	found := make(map[hpp.PhysicalAddress]struct{})
	for _, suspect := range proof.Suspects {
		if suspect.Address == nil || suspect.Classification != localization.LeafMismatch {
			row.NonLeaf++
			continue
		}
		if _, listed := expected[*suspect.Address]; !listed {
			row.FalsePositives++
		}
		found[*suspect.Address] = struct{}{}
	}
	for address := range expected {
		if _, ok := found[address]; !ok {
			row.Missed++
		}
	}
	for address := range found {
		if _, ok := expected[address]; ok {
			row.ConfirmedLeaves++
		}
	}
	row.Correct = row.FalsePositives == 0 && row.Missed == 0 && row.NonLeaf == 0 && row.Unresolved == 0

	if proof.ACHP != nil {
		var planning time.Duration
		row.PruningRounds = len(proof.ACHP.Rounds)
		for _, round := range proof.ACHP.Rounds {
			planning += round.PlanningTime
			for _, expansion := range round.Expansions {
				for _, judgement := range expansion.Judgements {
					if judgement.Disposition == localization.DispositionSuspect {
						row.SuspectBranches++
					}
				}
			}
		}
		row.PlanningMS = float64(planning) / float64(time.Millisecond)
	} else {
		row.PruningRounds = len(proof.Rounds)
		for _, round := range proof.Rounds {
			for _, comparison := range round.Comparisons {
				if !comparison.Match {
					row.SuspectBranches++
				}
			}
		}
	}

	if verify {
		row.ProofVerified = localization.VerifyProof(proof, batch, trusted) == nil
	}
	// With VerifyProofs off the column stays false: the proof was not replayed,
	// which run_config.json records as verify_proofs=false.
	switch {
	case row.Fallback:
		row.Status = StatusFallback
	case !row.Correct:
		row.Status = StatusIncorrect
	case verify && !row.ProofVerified:
		row.Status = StatusUnproven
	default:
		row.Status = StatusOK
	}
	return row
}

func strategyName(strategy localization.Strategy) string {
	if strategy == localization.StrategyDefault {
		return "DEFAULT"
	}
	return string(strategy)
}
