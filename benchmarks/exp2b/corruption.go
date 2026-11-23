package exp2b

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
)

// Case is one corruption assignment: which requested records are corrupted in
// one run. Every algorithm receives exactly the same Case.
type Case struct {
	QueryID          string   `json:"query_id"`
	Count            int      `json:"count"`
	Pattern          string   `json:"pattern"`
	Phase            string   `json:"phase"`
	Repetition       int      `json:"repetition"` // 1-based within the phase
	Seed             uint64   `json:"seed"`
	DistinctSegments int      `json:"distinct_segments"`
	Records          []Record `json:"records"`
}

// Ordinals lists the corrupted records' dataset ordinals, ascending.
func (c Case) Ordinals() []int {
	ordinals := make([]int, len(c.Records))
	for index, record := range c.Records {
		ordinals[index] = record.Ordinal
	}
	return ordinals
}

// CorruptionManifest is corruption.json.
type CorruptionManifest struct {
	Version       int    `json:"version"`
	MasterSeed    uint64 `json:"master_seed"`
	QueriesSHA256 string `json:"queries_sha256"`
	Cases         []Case `json:"cases"`
}

// Patterns are the corruption patterns evaluated for m records.
func Patterns(count int) []string {
	if count == 1 {
		return []string{PatternCommon}
	}
	return []string{PatternClustered, PatternScattered}
}

type segmentGroup struct {
	segment  int
	ordinals []int // ascending
}

func groupBySegment(query Query, layout *Layout) []segmentGroup {
	var groups []segmentGroup
	for _, ordinal := range query.Ordinals {
		segment, _, _ := layout.Locate(ordinal)
		if last := len(groups) - 1; last >= 0 && groups[last].segment == segment {
			groups[last].ordinals = append(groups[last].ordinals, ordinal)
			continue
		}
		groups = append(groups, segmentGroup{segment: segment, ordinals: []int{ordinal}})
	}
	return groups
}

// sampleCommon draws m = 1 uniformly from the whole query.
func sampleCommon(rng *rand.Rand, groups []segmentGroup, query Query) []int {
	return []int{query.Ordinals[rng.IntN(len(query.Ordinals))]}
}

// sampleClustered picks one eligible segment (one holding at least m requested
// records) at random, then m of its requested records at random. The records
// share one segment, hence one Cassandra partition and one segment tree.
func sampleClustered(rng *rand.Rand, groups []segmentGroup, count int) ([]int, error) {
	var eligible []int
	for index, group := range groups {
		if len(group.ordinals) >= count {
			eligible = append(eligible, index)
		}
	}
	if len(eligible) == 0 {
		return nil, fmt.Errorf("no segment holds %d requested records, clustered corruption is not possible", count)
	}
	group := groups[eligible[rng.IntN(len(eligible))]]
	return pickDistinct(rng, group.ordinals, count), nil
}

// sampleScattered spreads m corrupted records over m distinct segments with the
// widest spread the query allows: the segments the query touches, in physical
// order, are cut into m equal strata and one segment is drawn from each.
func sampleScattered(rng *rand.Rand, groups []segmentGroup, count int) ([]int, error) {
	if len(groups) < count {
		return nil, fmt.Errorf("the query touches %d segments, scattered corruption needs %d", len(groups), count)
	}
	result := make([]int, 0, count)
	for stratum := range count {
		low, high := stratum*len(groups)/count, (stratum+1)*len(groups)/count
		group := groups[low+rng.IntN(high-low)]
		result = append(result, group.ordinals[rng.IntN(len(group.ordinals))])
	}
	sort.Ints(result)
	return result, nil
}

// pickDistinct returns count distinct elements of pool, ascending.
func pickDistinct(rng *rand.Rand, pool []int, count int) []int {
	work := slices.Clone(pool)
	for index := range count {
		other := index + rng.IntN(len(work)-index)
		work[index], work[other] = work[other], work[index]
	}
	picked := slices.Clone(work[:count])
	sort.Ints(picked)
	return picked
}

func sameOrdinals(a, b []int) bool { return slices.Equal(a, b) }

// GenerateCorruption draws the corruption cases for every query, count and
// pattern: Warmups warm-up cases then Repetitions measured cases, each with a
// distinct record set. A query that cannot support a pattern is an error.
func GenerateCorruption(queries QueryManifest, layout *Layout) (CorruptionManifest, error) {
	params := queries.Params
	manifest := CorruptionManifest{Version: ManifestVersion, MasterSeed: params.MasterSeed, QueriesSHA256: queries.Hash()}
	for _, query := range queries.Queries {
		groups := groupBySegment(query, layout)
		for _, count := range params.CorruptionCounts {
			for _, pattern := range Patterns(count) {
				var previous [][]int
				for _, phase := range []string{PhaseWarmup, PhaseMeasured} {
					repetitions := params.Warmups
					if phase == PhaseMeasured {
						repetitions = params.Repetitions
					}
					for repetition := 1; repetition <= repetitions; repetition++ {
						var drawn Case
						for attempt := 0; ; attempt++ {
							if attempt > 1000 {
								return CorruptionManifest{}, fmt.Errorf("query %s m=%d %s: could not draw %d distinct corruption sets",
									query.ID, count, pattern, params.Warmups+params.Repetitions)
							}
							seed := DeriveSeed(params.MasterSeed, "corruption", query.ID, count, pattern, phase, repetition, attempt)
							rng := newRand(seed)
							var ordinals []int
							var err error
							switch pattern {
							case PatternCommon:
								ordinals = sampleCommon(rng, groups, query)
							case PatternClustered:
								ordinals, err = sampleClustered(rng, groups, count)
							default:
								ordinals, err = sampleScattered(rng, groups, count)
							}
							if err != nil {
								return CorruptionManifest{}, fmt.Errorf("query %s m=%d %s: %w", query.ID, count, pattern, err)
							}
							if slices.ContainsFunc(previous, func(old []int) bool { return sameOrdinals(old, ordinals) }) {
								continue
							}
							previous = append(previous, ordinals)
							drawn = Case{QueryID: query.ID, Count: count, Pattern: pattern, Phase: phase,
								Repetition: repetition, Seed: seed}
							segments := map[int]struct{}{}
							for _, ordinal := range ordinals {
								record, err := layout.Record(ordinal)
								if err != nil {
									return CorruptionManifest{}, err
								}
								segment, _, _ := layout.Locate(ordinal)
								segments[segment] = struct{}{}
								drawn.Records = append(drawn.Records, record)
							}
							drawn.DistinctSegments = len(segments)
							break
						}
						manifest.Cases = append(manifest.Cases, drawn)
					}
				}
			}
		}
	}
	if err := ValidateCorruption(queries, manifest, layout); err != nil {
		return CorruptionManifest{}, err
	}
	return manifest, nil
}

// ValidateCorruption checks the manifest against the queries, so a run fails
// rather than silently changing the workload.
func ValidateCorruption(queries QueryManifest, manifest CorruptionManifest, layout *Layout) error {
	params := queries.Params
	if manifest.Version != ManifestVersion {
		return fmt.Errorf("exp2b: corruption manifest version %d, this build writes version %d", manifest.Version, ManifestVersion)
	}
	if manifest.QueriesSHA256 != queries.Hash() {
		return fmt.Errorf("exp2b: the corruption manifest was drawn for different queries")
	}
	if manifest.MasterSeed != params.MasterSeed {
		return fmt.Errorf("exp2b: corruption master seed %d differs from the queries' %d", manifest.MasterSeed, params.MasterSeed)
	}
	type group struct {
		query, pattern string
		count          int
	}
	counts := map[group]int{}
	sets := map[group][][]int{}
	for _, c := range manifest.Cases {
		query, ok := queries.Query(c.QueryID)
		if !ok {
			return fmt.Errorf("exp2b: case refers to unknown query %q", c.QueryID)
		}
		if len(c.Records) != c.Count || c.Count <= 0 {
			return fmt.Errorf("exp2b: %s m=%d %s #%d lists %d records", c.QueryID, c.Count, c.Pattern, c.Repetition, len(c.Records))
		}
		inQuery := make(map[int]struct{}, len(query.Ordinals))
		for _, ordinal := range query.Ordinals {
			inQuery[ordinal] = struct{}{}
		}
		segments := map[int]struct{}{}
		ordinals := c.Ordinals()
		for index, record := range c.Records {
			if _, ok := inQuery[record.Ordinal]; !ok {
				return fmt.Errorf("exp2b: %s corrupts ordinal %d, which the query does not request", c.QueryID, record.Ordinal)
			}
			if index > 0 && record.Ordinal <= ordinals[index-1] {
				return fmt.Errorf("exp2b: %s corrupted ordinals are not distinct and ascending", c.QueryID)
			}
			want, err := layout.Record(record.Ordinal)
			if err != nil || want != record {
				return fmt.Errorf("exp2b: %s record %+v does not match the layout", c.QueryID, record)
			}
			segment, _, _ := layout.Locate(record.Ordinal)
			segments[segment] = struct{}{}
		}
		if len(segments) != c.DistinctSegments {
			return fmt.Errorf("exp2b: %s m=%d %s #%d records %d distinct segments, found %d",
				c.QueryID, c.Count, c.Pattern, c.Repetition, c.DistinctSegments, len(segments))
		}
		switch c.Pattern {
		case PatternCommon:
			if c.Count != 1 {
				return fmt.Errorf("exp2b: the common pattern is for m = 1, got %d", c.Count)
			}
		case PatternClustered:
			if len(segments) != 1 {
				return fmt.Errorf("exp2b: clustered case %s m=%d spans %d segments", c.QueryID, c.Count, len(segments))
			}
		case PatternScattered:
			if len(segments) != c.Count {
				return fmt.Errorf("exp2b: scattered case %s m=%d covers only %d distinct segments", c.QueryID, c.Count, len(segments))
			}
		default:
			return fmt.Errorf("exp2b: unknown pattern %q", c.Pattern)
		}
		key := group{c.QueryID, c.Pattern, c.Count}
		counts[key]++
		for _, old := range sets[key] {
			if sameOrdinals(old, ordinals) {
				return fmt.Errorf("exp2b: %s m=%d %s repeats a corruption set", c.QueryID, c.Count, c.Pattern)
			}
		}
		sets[key] = append(sets[key], ordinals)
	}
	for _, query := range queries.Queries {
		for _, count := range params.CorruptionCounts {
			for _, pattern := range Patterns(count) {
				if got, want := counts[group{query.ID, pattern, count}], params.Warmups+params.Repetitions; got != want {
					return fmt.Errorf("exp2b: %s m=%d %s has %d cases, want %d", query.ID, count, pattern, got, want)
				}
			}
		}
	}
	return nil
}

// CasesFor returns the cases of one query, count and pattern in run order:
// warm-ups first, then the measured repetitions.
func (manifest CorruptionManifest) CasesFor(queryID string, count int, pattern string) []Case {
	var cases []Case
	for _, c := range manifest.Cases {
		if c.QueryID == queryID && c.Count == count && c.Pattern == pattern {
			cases = append(cases, c)
		}
	}
	return cases
}
