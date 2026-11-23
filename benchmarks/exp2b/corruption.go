package exp2b

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"sort"
)

// Corruption localities. LocalityCommon is m = 1, where locality is undefined: one
// shared case serves every algorithm and is aggregated once.
//
// These describe where the corrupted records sit and are independent of the
// query's own locality (Query.QueryLocality).
const (
	LocalityCommon    = "common"
	LocalityClustered = "clustered"
	LocalityScattered = "scattered"

	// Actual corruption localities, derived from the drawn records.
	ActualSingleRecord  = "single-record"
	ActualSingleSegment = "single-segment"
	ActualMaxSpread     = "max-spread"     // as many distinct segments as the query allows
	ActualPartialSpread = "partial-spread" // more than one segment, fewer than feasible
)

// UnsuitableQueryError flags a query that cannot support a requested locality.
// The experiment stops: the locality definition is never weakened to fit.
type UnsuitableQueryError struct {
	QueryID string
	Count   int
	Reason  string
}

func (err *UnsuitableQueryError) Error() string {
	return fmt.Sprintf("exp2b: query %s is unsuitable for m = %d: %s", err.QueryID, err.Count, err.Reason)
}

// SegmentCount is the number of corrupted records in one segment.
type SegmentCount struct {
	Region  string `json:"region"`
	Shard   int64  `json:"shard"`
	Segment int64  `json:"segment"`
	Records int    `json:"records"`
}

// Case is one corruption assignment: which requested records are corrupted in
// one run. Every algorithm receives exactly the same Case.
type Case struct {
	QueryID string `json:"query_id"`
	// Query locality (a property of the audited batch) and corruption locality
	// (a property of this case) are different things and are kept apart.
	QueryLocality string `json:"query_locality"`
	QuerySegments int    `json:"query_segments"`
	Count         int    `json:"count"`
	Locality      string `json:"corruption_locality"`
	Phase         string `json:"phase"`
	Repetition    int    `json:"repetition"` // 1-based within the phase
	Seed          uint64 `json:"seed"`

	ActualLocality    string         `json:"actual_corruption_locality"`
	DistinctSegments  int            `json:"distinct_segments"`
	DistinctShards    int            `json:"distinct_shards"`
	DistinctRegions   int            `json:"distinct_regions"`
	RecordsPerSegment []SegmentCount `json:"records_per_segment"`
	Records           []Record       `json:"records"`
}

// Ordinals lists the corrupted records' dataset ordinals, ascending. The ordinal
// is the canonical record ID: both the HMF log ID and EVSEB's LID derive from it.
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

// Localities are the corruption localities evaluated for m records.
func Localities(count int) []string {
	if count == 1 {
		return []string{LocalityCommon}
	}
	return []string{LocalityClustered, LocalityScattered}
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
func sampleCommon(rng *rand.Rand, query Query) []int {
	return []int{query.Ordinals[rng.IntN(len(query.Ordinals))]}
}

// sampleClustered picks one eligible segment (one holding at least m requested
// records) uniformly at random, then m of its requested records uniformly at
// random. Every corrupted record lies in that one segment.
func sampleClustered(rng *rand.Rand, queryID string, groups []segmentGroup, count int) ([]int, error) {
	var eligible []int
	for index, group := range groups {
		if len(group.ordinals) >= count {
			eligible = append(eligible, index)
		}
	}
	if len(eligible) == 0 {
		return nil, &UnsuitableQueryError{QueryID: queryID, Count: count,
			Reason: "no segment holds that many requested records, so clustered corruption cannot be drawn"}
	}
	group := groups[eligible[rng.IntN(len(eligible))]]
	return pickDistinct(rng, group.ordinals, count), nil
}

// sampleScattered spreads m corrupted records over as many distinct segments as
// possible.
//
// With at least m segments each record gets its own segment: the query's segments,
// in physical order, are cut into m equal strata and one segment is drawn from each,
// so the m segments are distinct and spread over the whole query. With fewer than m
// segments every segment is used and the records are dealt out one at a time round
// robin (in a random segment order), which is as even as the query's per-segment
// capacity allows.
func sampleScattered(rng *rand.Rand, queryID string, groups []segmentGroup, count int) ([]int, error) {
	if len(groups) >= count {
		result := make([]int, 0, count)
		for stratum := range count {
			low, high := stratum*len(groups)/count, (stratum+1)*len(groups)/count
			group := groups[low+rng.IntN(high-low)]
			result = append(result, group.ordinals[rng.IntN(len(group.ordinals))])
		}
		sort.Ints(result)
		return result, nil
	}
	capacity := 0
	for _, group := range groups {
		capacity += len(group.ordinals)
	}
	if capacity < count {
		return nil, &UnsuitableQueryError{QueryID: queryID, Count: count,
			Reason: fmt.Sprintf("the query holds only %d records", capacity)}
	}
	share := make([]int, len(groups))
	order := rng.Perm(len(groups))
	for assigned := 0; assigned < count; {
		for _, index := range order {
			if assigned == count {
				break
			}
			if share[index] < len(groups[index].ordinals) {
				share[index]++
				assigned++
			}
		}
	}
	var result []int
	for index, group := range groups {
		if share[index] > 0 {
			result = append(result, pickDistinct(rng, group.ordinals, share[index])...)
		}
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

// locate returns the metadata that follows from the corrupted records alone:
// the records with their addresses and the segment, shard and region spread. The
// same function runs at generation and at validation, so a hand-edited manifest
// cannot claim a locality its records do not have.
func locate(layout *Layout, query Query, count int, ordinals []int) (Case, error) {
	c := Case{QueryLocality: query.QueryLocality, QuerySegments: query.SegmentCount}
	perSegment := map[int]int{}
	var order []int
	shards, regions := map[string]struct{}{}, map[string]struct{}{}
	for _, ordinal := range ordinals {
		record, err := layout.Record(ordinal)
		if err != nil {
			return Case{}, err
		}
		c.Records = append(c.Records, record)
		segment, _, _ := layout.Locate(ordinal)
		if perSegment[segment] == 0 {
			order = append(order, segment)
		}
		perSegment[segment]++
		shards[fmt.Sprintf("%s/%d", record.Region, record.Shard)] = struct{}{}
		regions[record.Region] = struct{}{}
	}
	sort.Ints(order)
	for _, segment := range order {
		span := layout.spans[segment]
		c.RecordsPerSegment = append(c.RecordsPerSegment, SegmentCount{
			Region: span.Region, Shard: span.Shard, Segment: span.Segment, Records: perSegment[segment],
		})
	}
	c.DistinctSegments, c.DistinctShards, c.DistinctRegions = len(perSegment), len(shards), len(regions)
	switch {
	case count == 1:
		c.ActualLocality = ActualSingleRecord
	case c.DistinctSegments == 1:
		c.ActualLocality = ActualSingleSegment
	case c.DistinctSegments == min(count, query.SegmentCount):
		c.ActualLocality = ActualMaxSpread
	default:
		c.ActualLocality = ActualPartialSpread
	}
	return c, nil
}

func sameOrdinals(a, b []int) bool { return slices.Equal(a, b) }

// GenerateCorruption draws the corruption cases for every query, count and
// locality: Warmups warm-up cases then Repetitions measured cases, each a fresh
// draw with a distinct record set. A query that cannot support a locality is an
// UnsuitableQueryError; the locality is never weakened.
func GenerateCorruption(queries QueryManifest, layout *Layout) (CorruptionManifest, error) {
	params := queries.Params
	manifest := CorruptionManifest{Version: ManifestVersion, MasterSeed: params.MasterSeed, QueriesSHA256: queries.Hash()}
	for _, query := range queries.Queries {
		groups := groupBySegment(query, layout)
		for _, count := range params.CorruptionCounts {
			for _, locality := range Localities(count) {
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
									query.ID, count, locality, params.Warmups+params.Repetitions)
							}
							// The seed depends on the master seed, the query, m, the locality and the
							// repetition (the phase and a redraw counter keep draws distinct).
							seed := DeriveSeed(params.MasterSeed, "corruption", query.ID, count, locality, phase, repetition, attempt)
							rng := newRand(seed)
							var ordinals []int
							var err error
							switch locality {
							case LocalityCommon:
								ordinals = sampleCommon(rng, query)
							case LocalityClustered:
								ordinals, err = sampleClustered(rng, query.ID, groups, count)
							default:
								ordinals, err = sampleScattered(rng, query.ID, groups, count)
							}
							if err != nil {
								return CorruptionManifest{}, err
							}
							if slices.ContainsFunc(previous, func(old []int) bool { return sameOrdinals(old, ordinals) }) {
								continue
							}
							previous = append(previous, ordinals)
							drawn, err = locate(layout, query, count, ordinals)
							if err != nil {
								return CorruptionManifest{}, err
							}
							drawn.QueryID, drawn.Count, drawn.Locality = query.ID, count, locality
							drawn.Phase, drawn.Repetition, drawn.Seed = phase, repetition, seed
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
// rather than silently changing the workload. Every case must corrupt exactly m
// distinct records, all requested by its query; clustered cases must sit in one
// segment and scattered cases must span the widest spread the query allows; the
// recorded locality metadata must match the records.
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
		query, locality string
		count           int
	}
	counts := map[group]int{}
	sets := map[group][][]int{}
	for _, c := range manifest.Cases {
		query, ok := queries.Query(c.QueryID)
		if !ok {
			return fmt.Errorf("exp2b: case refers to unknown query %q", c.QueryID)
		}
		label := fmt.Sprintf("%s m=%d %s %s #%d", c.QueryID, c.Count, c.Locality, c.Phase, c.Repetition)
		if len(c.Records) != c.Count || c.Count <= 0 {
			return fmt.Errorf("exp2b: %s lists %d records, want exactly %d", label, len(c.Records), c.Count)
		}
		inQuery := make(map[int]struct{}, len(query.Ordinals))
		for _, ordinal := range query.Ordinals {
			inQuery[ordinal] = struct{}{}
		}
		ordinals := c.Ordinals()
		for index, ordinal := range ordinals {
			if _, ok := inQuery[ordinal]; !ok {
				return fmt.Errorf("exp2b: %s corrupts ordinal %d, which the audit query does not request", label, ordinal)
			}
			if index > 0 && ordinal <= ordinals[index-1] {
				return fmt.Errorf("exp2b: %s corrupted ordinals are not distinct and ascending", label)
			}
		}
		want, err := locate(layout, query, c.Count, ordinals)
		if err != nil {
			return fmt.Errorf("exp2b: %s: %w", label, err)
		}
		want.QueryID, want.Count, want.Locality, want.Phase, want.Repetition, want.Seed =
			c.QueryID, c.Count, c.Locality, c.Phase, c.Repetition, c.Seed
		if !reflect.DeepEqual(want, c) {
			return fmt.Errorf("exp2b: %s locality metadata does not match its records", label)
		}
		switch c.Locality {
		case LocalityCommon:
			if c.Count != 1 {
				return fmt.Errorf("exp2b: %s: the common locality is for m = 1", label)
			}
		case LocalityClustered:
			if c.DistinctSegments != 1 {
				return fmt.Errorf("exp2b: %s spans %d segments, clustered corruption occupies exactly one", label, c.DistinctSegments)
			}
		case LocalityScattered:
			if feasible := min(c.Count, query.SegmentCount); c.DistinctSegments != feasible {
				return fmt.Errorf("exp2b: %s covers %d segments, the maximum feasible spread is %d", label, c.DistinctSegments, feasible)
			}
			if query.SegmentCount >= c.Count {
				for _, per := range c.RecordsPerSegment {
					if per.Records != 1 {
						return fmt.Errorf("exp2b: %s puts %d records in one segment although %d segments are available",
							label, per.Records, query.SegmentCount)
					}
				}
			}
		default:
			return fmt.Errorf("exp2b: %s: unknown corruption locality", label)
		}
		key := group{c.QueryID, c.Locality, c.Count}
		counts[key]++
		for _, old := range sets[key] {
			if sameOrdinals(old, ordinals) {
				return fmt.Errorf("exp2b: %s repeats a corruption set", label)
			}
		}
		sets[key] = append(sets[key], ordinals)
	}
	for _, query := range queries.Queries {
		for _, count := range params.CorruptionCounts {
			for _, locality := range Localities(count) {
				if got, want := counts[group{query.ID, locality, count}], params.Warmups+params.Repetitions; got != want {
					return fmt.Errorf("exp2b: %s m=%d %s has %d cases, want %d", query.ID, count, locality, got, want)
				}
			}
		}
	}
	return nil
}

// CasesFor returns the cases of one query, count and corruption locality in run
// order: warm-ups first, then the measured repetitions.
func (manifest CorruptionManifest) CasesFor(queryID string, count int, locality string) []Case {
	var cases []Case
	for _, c := range manifest.Cases {
		if c.QueryID == queryID && c.Count == count && c.Locality == locality {
			cases = append(cases, c)
		}
	}
	return cases
}

// IsUnsuitable reports whether err flags an unsuitable query.
func IsUnsuitable(err error) bool {
	var unsuitable *UnsuitableQueryError
	return errors.As(err, &unsuitable)
}
