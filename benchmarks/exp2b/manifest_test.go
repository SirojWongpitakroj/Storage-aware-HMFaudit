package exp2b

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
)

// testLayout is 4 regions of 160 segments of 512 leaves.
func testLayout(t testing.TB, regions, segmentsPerRegion, leaves int) *Layout {
	t.Helper()
	var spans []SegmentSpan
	first := 0
	for region := range regions {
		for segment := range segmentsPerRegion {
			spans = append(spans, SegmentSpan{
				Region: fmt.Sprintf("R%d", region), Shard: 0, Segment: int64(segment), First: first, Leaves: leaves,
			})
			first += leaves
		}
	}
	layout, err := NewLayout(spans)
	if err != nil {
		t.Fatal(err)
	}
	return layout
}

func TestDefaultParamsAreTheSpecification(t *testing.T) {
	p := DefaultParams()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Q != 4096 || p.QueryCount != 5 || p.Warmups != 3 || p.Repetitions != 20 ||
		!slices.Equal(p.CorruptionCounts, []int{1, 4, 16, 64}) {
		t.Fatalf("defaults drifted from the specification: %+v", p)
	}
	if p.DenseSegments*p.DensePerSegment+p.SparseSegments()*p.SparsePerSegment != p.Q {
		t.Fatal("dense and sparse segments do not add up to q")
	}
}

func TestParamsRejectWhatCannotBeBuilt(t *testing.T) {
	for name, mutate := range map[string]func(*Params){
		"m larger than a dense segment": func(p *Params) { p.CorruptionCounts = []int{1, 300} },
		"m larger than the segments":    func(p *Params) { p.CorruptionCounts = []int{1, 200}; p.DensePerSegment = 256 },
		"sparse not a multiple":         func(p *Params) { p.SparsePerSegment = 15 },
		"descending counts":             func(p *Params) { p.CorruptionCounts = []int{4, 1} },
		"no repetitions":                func(p *Params) { p.Repetitions = 0 },
		"dense segments fill the query": func(p *Params) { p.DenseSegments = 16 },
	} {
		p := DefaultParams()
		mutate(&p)
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestQueriesAreExactDistinctAndReproducible(t *testing.T) {
	layout := testLayout(t, 4, 160, 512)
	params := DefaultParams()
	params.DensePerSegment = 256
	first, err := GenerateQueries(params, layout)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateQueries(params, layout)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatal("the same parameters produced different queries")
	}
	for _, query := range first.Queries {
		if len(query.Ordinals) != 4096 {
			t.Fatalf("%s has %d records", query.ID, len(query.Ordinals))
		}
		seen := map[int]bool{}
		for _, ordinal := range query.Ordinals {
			if seen[ordinal] {
				t.Fatalf("%s repeats ordinal %d", query.ID, ordinal)
			}
			seen[ordinal] = true
		}
	}
	if slices.Equal(first.Queries[0].Ordinals, first.Queries[1].Ordinals) {
		t.Fatal("two query sets are identical")
	}
	params.MasterSeed++
	other, err := GenerateQueries(params, layout)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Equal(first.Queries[0].Ordinals, other.Queries[0].Ordinals) {
		t.Fatal("the master seed does not change the queries")
	}
}

func TestQueriesFailWhenTheLayoutIsTooSmall(t *testing.T) {
	small := testLayout(t, 1, 100, 512) // 100 segments < 136
	if _, err := GenerateQueries(DefaultParams(), small); err == nil {
		t.Fatal("a layout with too few segments was accepted")
	}
	narrow := testLayout(t, 4, 160, 128) // segments too short for a 256-record run
	if _, err := GenerateQueries(DefaultParams(), narrow); err == nil {
		t.Fatal("a layout with segments shorter than the dense run was accepted")
	}
}

func scaled(t testing.TB) (Params, *Layout) {
	t.Helper()
	params := DefaultParams()
	params.Q, params.DenseSegments, params.DensePerSegment, params.SparsePerSegment = 512, 4, 64, 16
	params.CorruptionCounts = []int{1, 4, 16}
	params.Warmups, params.Repetitions = 2, 5
	return params, testLayout(t, 2, 40, 256)
}

func TestCorruptionIsReproducibleAndMeetsEachPattern(t *testing.T) {
	params, layout := scaled(t)
	queries, err := GenerateQueries(params, layout)
	if err != nil {
		t.Fatal(err)
	}
	first, err := GenerateCorruption(queries, layout)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateCorruption(queries, layout)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatal("the same manifests produced different corruption")
	}
	// 5 queries... here QueryCount stays 5: queries x (1 common + 2 patterns x 2 counts) x (2+5).
	wantCases := params.QueryCount * (1 + 2*2) * (params.Warmups + params.Repetitions)
	if len(first.Cases) != wantCases {
		t.Fatalf("%d cases, want %d", len(first.Cases), wantCases)
	}
	for _, c := range first.Cases {
		switch c.Pattern {
		case PatternClustered:
			if c.DistinctSegments != 1 {
				t.Fatalf("clustered case spans %d segments", c.DistinctSegments)
			}
		case PatternScattered:
			if c.DistinctSegments != c.Count {
				t.Fatalf("scattered m=%d covers %d segments", c.Count, c.DistinctSegments)
			}
		case PatternCommon:
			if c.Count != 1 {
				t.Fatal("common pattern with m != 1")
			}
		}
	}
	if err := ValidateCorruption(queries, first, layout); err != nil {
		t.Fatal(err)
	}
}

func TestScatteredSpreadsAcrossThePhysicalRange(t *testing.T) {
	params, layout := scaled(t)
	queries, _ := GenerateQueries(params, layout)
	manifest, err := GenerateCorruption(queries, layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.Cases {
		if c.Pattern != PatternScattered || c.Count != 16 {
			continue
		}
		// Strata of the query's segments in physical order: the i-th corrupted
		// record comes from the i-th stratum, so the spread is as wide as the
		// query allows.
		query, _ := queries.Query(c.QueryID)
		groups := groupBySegment(query, layout)
		var segmentOf []int
		for _, record := range c.Records {
			segment, _, _ := layout.Locate(record.Ordinal)
			segmentOf = append(segmentOf, segment)
		}
		for index, segment := range segmentOf {
			low, high := index*len(groups)/16, (index+1)*len(groups)/16
			ok := false
			for g := low; g < high; g++ {
				ok = ok || groups[g].segment == segment
			}
			if !ok {
				t.Fatalf("record %d of %s is outside stratum %d", index, c.QueryID, index)
			}
		}
	}
}

func TestCorruptionSetsAreDistinctWithinAGroup(t *testing.T) {
	params, layout := scaled(t)
	queries, _ := GenerateQueries(params, layout)
	manifest, err := GenerateCorruption(queries, layout)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range manifest.Cases {
		key := fmt.Sprint(c.QueryID, c.Count, c.Pattern, c.Ordinals())
		if seen[key] {
			t.Fatalf("repeated corruption set %s", key)
		}
		seen[key] = true
	}
}

func TestSeedsDependOnlyOnTheCaseIdentity(t *testing.T) {
	if DeriveSeed(7, "a", 1) != DeriveSeed(7, "a", 1) {
		t.Fatal("seed is not deterministic")
	}
	if DeriveSeed(7, "a", 1) == DeriveSeed(8, "a", 1) || DeriveSeed(7, "a", 1) == DeriveSeed(7, "a", 2) {
		t.Fatal("seed ignores part of the identity")
	}
	// Removing a count from the experiment must not change the other cases.
	params, layout := scaled(t)
	queries, _ := GenerateQueries(params, layout)
	full, _ := GenerateCorruption(queries, layout)
	params.CorruptionCounts = []int{4, 16}
	reduced, err := GenerateQueries(params, layout)
	if err != nil {
		t.Fatal(err)
	}
	subset, err := GenerateCorruption(reduced, layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range subset.Cases {
		var match *Case
		for index := range full.Cases {
			f := &full.Cases[index]
			if f.QueryID == c.QueryID && f.Count == c.Count && f.Pattern == c.Pattern && f.Phase == c.Phase && f.Repetition == c.Repetition {
				match = f
			}
		}
		if match == nil || !slices.Equal(match.Ordinals(), c.Ordinals()) {
			t.Fatalf("case %s m=%d %s %s #%d changed when another count was removed", c.QueryID, c.Count, c.Pattern, c.Phase, c.Repetition)
		}
	}
}

func TestCorruptionFailsInsteadOfChangingTheWorkload(t *testing.T) {
	params, layout := scaled(t)
	queries, _ := GenerateQueries(params, layout)
	tampered := CorruptionManifest{Version: ManifestVersion, MasterSeed: params.MasterSeed, QueriesSHA256: queries.Hash()}
	good, _ := GenerateCorruption(queries, layout)
	tampered.Cases = slices.Clone(good.Cases)
	// A scattered case squeezed into one segment must be rejected.
	for index := range tampered.Cases {
		c := &tampered.Cases[index]
		if c.Pattern == PatternScattered && c.Count == 4 {
			c.Records = slices.Clone(c.Records)
			base := c.Records[0]
			for i := range c.Records {
				c.Records[i] = base
			}
			if ValidateCorruption(queries, tampered, layout) == nil {
				t.Fatal("a scattered case in one segment was accepted")
			}
			break
		}
	}
	// A corrupted record the query does not request.
	tampered.Cases = slices.Clone(good.Cases)
	tampered.Cases[0].Records = slices.Clone(tampered.Cases[0].Records)
	outside, _ := layout.Record(0)
	query, _ := queries.Query(tampered.Cases[0].QueryID)
	for ordinal := 0; ordinal < layout.Total(); ordinal++ {
		if _, found := slices.BinarySearch(query.Ordinals, ordinal); !found {
			outside, _ = layout.Record(ordinal)
			break
		}
	}
	tampered.Cases[0].Records[0] = outside
	if ValidateCorruption(queries, tampered, layout) == nil {
		t.Fatal("a corrupted record outside the query was accepted")
	}
	// Sampling fails, rather than relaxing the pattern, when the query cannot support it.
	groups := groupBySegment(Query{Ordinals: []int{0, 300, 600, 900}}, layout)
	if _, err := sampleClustered(newRand(1), groups, 2); err == nil {
		t.Fatal("clustered sampling succeeded where no segment holds m records")
	}
	if _, err := sampleScattered(newRand(1), groups, 5); err == nil {
		t.Fatal("scattered sampling succeeded with fewer segments than m")
	}
}

func TestManifestsRefuseAForeignLayout(t *testing.T) {
	params, layout := scaled(t)
	queries, _ := GenerateQueries(params, layout)
	other := testLayout(t, 2, 41, 256)
	if err := ValidateQueries(queries, other); err == nil || !strings.Contains(err.Error(), "different dataset layout") {
		t.Fatalf("a manifest for another layout was accepted: %v", err)
	}
	corruption, _ := GenerateCorruption(queries, layout)
	queries.Queries[0].Ordinals = slices.Clone(queries.Queries[0].Ordinals)
	queries.Queries[0].Ordinals[0]++
	if err := ValidateCorruption(queries, corruption, layout); err == nil {
		t.Fatal("corruption manifest accepted after the queries changed")
	}
}

func TestPercentileIsNearestRank(t *testing.T) {
	values := []float64{9, 1, 5, 3, 7, 2, 8, 4, 6, 10}
	if got := Percentile(values, 50); got != 5 {
		t.Fatalf("p50 = %v, want 5", got)
	}
	if got := Percentile(values, 95); got != 10 {
		t.Fatalf("p95 = %v, want 10", got)
	}
	if !math.IsNaN(Percentile(nil, 50)) {
		t.Fatal("percentile of nothing must not be a number")
	}
	if values[0] != 9 {
		t.Fatal("percentile reordered its input")
	}
}

func TestSummaryKeepsErrorsAndFallbacksOutOfLatency(t *testing.T) {
	ok := func(latency float64) RawRow {
		return RawRow{Algorithm: "ACHP", CorruptionCount: 4, Pattern: PatternClustered, Status: StatusOK,
			LatencyMS: latency, PartitionReads: 10, EvidenceBytes: 640, RetrievalRounds: 3, PlanningMS: 1, CassandraReads: -1}
	}
	rows := []RawRow{ok(10), ok(20), ok(30), ok(40)}
	rows = append(rows,
		RawRow{Algorithm: "ACHP", CorruptionCount: 4, Pattern: PatternClustered, Status: StatusFallback, LatencyMS: 1, Fallback: true, PlanningMS: -1},
		RawRow{Algorithm: "ACHP", CorruptionCount: 4, Pattern: PatternClustered, Status: StatusError, LatencyMS: 0, PlanningMS: -1, Missed: 4},
		RawRow{Algorithm: "ACHP", CorruptionCount: 4, Pattern: PatternClustered, Status: StatusIncorrect, LatencyMS: 2, FalsePositives: 1, Missed: 1, PlanningMS: -1},
	)
	table := Summarize(rows)
	if len(table) != 1 {
		t.Fatalf("%d groups", len(table))
	}
	col := map[string]string{}
	for index, name := range SummaryHeader {
		col[name] = table[0][index]
	}
	for name, want := range map[string]string{
		"attempted": "7", "valid": "4", "error_count": "1", "incorrect_count": "1", "fallback_count": "1",
		"false_positive_total": "1", "missed_total": "5", "p50_latency_ms": "20.000000", "p95_latency_ms": "40.000000",
		"mean_partition_reads": "10.000000", "mean_planning_ms": "1.000000",
	} {
		if col[name] != want {
			t.Errorf("%s = %q, want %q", name, col[name], want)
		}
	}
}

func TestRawRowLeavesInapplicableCellsEmpty(t *testing.T) {
	fields := RawRow{Algorithm: "FIXED", Status: StatusError, PlanningMS: -1, CassandraReads: -1}.Fields()
	if len(fields) != len(RawHeader) {
		t.Fatalf("%d fields for %d columns", len(fields), len(RawHeader))
	}
	index := map[string]int{}
	for i, name := range RawHeader {
		index[name] = i
	}
	for _, name := range []string{"planning_ms", "cassandra_reads_observed", "latency_ms"} {
		if fields[index[name]] != "" {
			t.Errorf("%s = %q, want an empty cell, not a number", name, fields[index[name]])
		}
	}
}
