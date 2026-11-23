package exp2b

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// defaultScale draws the real specification (q = 4096, m up to 64) over a layout
// with room for it, so the locality properties are checked at the real size.
func defaultScale(t testing.TB) (QueryManifest, CorruptionManifest, *Layout) {
	t.Helper()
	layout := testLayout(t, 4, 160, 512)
	params := DefaultParams()
	params.DensePerSegment = 256
	params.QueryCount = 2
	params.Warmups, params.Repetitions = 3, 20
	queries, err := GenerateQueries(params, layout)
	if err != nil {
		t.Fatal(err)
	}
	corruption, err := GenerateCorruption(queries, layout)
	if err != nil {
		t.Fatal(err)
	}
	return queries, corruption, layout
}

func TestClusteredCorruptionOccupiesExactlyOneSegment(t *testing.T) {
	queries, corruption, _ := defaultScale(t)
	seen := 0
	for _, c := range corruption.Cases {
		if c.Locality != LocalityClustered {
			continue
		}
		seen++
		query, _ := queries.Query(c.QueryID)
		if c.DistinctSegments != 1 || c.DistinctShards != 1 || c.DistinctRegions != 1 ||
			len(c.RecordsPerSegment) != 1 || c.RecordsPerSegment[0].Records != c.Count || c.ActualLocality != ActualSingleSegment {
			t.Fatalf("clustered m=%d is not inside one segment: %+v", c.Count, c.RecordsPerSegment)
		}
		// The chosen segment holds at least m requested records.
		per := 0
		for _, segment := range query.Segments {
			if segment.Region == c.Records[0].Region && segment.Shard == c.Records[0].Shard && segment.Segment == c.Records[0].Segment {
				per = segment.Records
			}
		}
		if per < c.Count {
			t.Fatalf("clustered m=%d drawn from a segment with only %d requested records", c.Count, per)
		}
	}
	if want := 2 * 3 * 23; seen != want { // 2 queries x m in {4,16,64} x (3+20)
		t.Fatalf("%d clustered cases, want %d", seen, want)
	}
}

func TestScatteredCorruptionTakesOneRecordPerSegmentWhenSegmentsSuffice(t *testing.T) {
	queries, corruption, _ := defaultScale(t)
	for _, c := range corruption.Cases {
		if c.Locality != LocalityScattered {
			continue
		}
		query, _ := queries.Query(c.QueryID)
		if query.SegmentCount < c.Count {
			t.Fatalf("test query has only %d segments", query.SegmentCount)
		}
		if c.DistinctSegments != c.Count || c.ActualLocality != ActualMaxSpread {
			t.Fatalf("scattered m=%d covers %d segments (%s), want %d", c.Count, c.DistinctSegments, c.ActualLocality, c.Count)
		}
		for _, per := range c.RecordsPerSegment {
			if per.Records != 1 {
				t.Fatalf("scattered m=%d put %d records in one segment", c.Count, per.Records)
			}
		}
	}
}

func TestScatteredSpreadsEvenlyWhenFewerSegmentsThanRecords(t *testing.T) {
	groups := []segmentGroup{
		{segment: 0, ordinals: []int{0, 1, 2, 3, 4, 5}},
		{segment: 1, ordinals: []int{10, 11, 12, 13, 14}},
		{segment: 2, ordinals: []int{20, 21, 22, 23}},
	}
	for seed := uint64(1); seed <= 50; seed++ {
		ordinals, err := sampleScattered(newRand(seed), "q", groups, 7)
		if err != nil {
			t.Fatal(err)
		}
		if len(ordinals) != 7 || !slices.IsSorted(ordinals) {
			t.Fatalf("seed %d: %v", seed, ordinals)
		}
		perSegment := map[int]int{}
		for _, ordinal := range ordinals {
			perSegment[ordinal/10]++
		}
		low, high := 99, 0
		for _, count := range perSegment {
			low, high = min(low, count), max(high, count)
		}
		// 7 records over 3 segments: 3, 2, 2 in some order.
		if len(perSegment) != 3 || high != 3 || low != 2 {
			t.Fatalf("seed %d: records per segment %v, want an even 3/2/2 split", seed, perSegment)
		}
	}
	// Capacity bounds the evenness: a small segment cannot take its share.
	small := []segmentGroup{{segment: 0, ordinals: []int{0}}, {segment: 1, ordinals: []int{10, 11, 12, 13, 14, 15}}}
	ordinals, err := sampleScattered(newRand(3), "q", small, 5)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(ordinals); got != 5 || !slices.Contains(ordinals, 0) {
		t.Fatalf("capacity-bound scatter = %v", ordinals)
	}
}

func TestScatteredWithFewSegmentsPassesValidation(t *testing.T) {
	// A query touching 6 segments cannot place 16 records in distinct segments; the spec
	// asks for the most even spread, and validation expects exactly that spread.
	params := DefaultParams()
	params.Q, params.DenseSegments, params.DensePerSegment, params.SparsePerSegment = 144, 2, 48, 16
	params.CorruptionCounts = []int{1, 4, 16}
	params.QueryCount, params.Warmups, params.Repetitions = 1, 1, 3
	layout := testLayout(t, 1, 12, 256)
	queries, err := GenerateQueries(params, layout)
	if err != nil {
		t.Fatal(err)
	}
	// 2 dense segments of 48 and (144-96)/16 = 3 sparse segments of 16: 5 segments in all.
	if queries.Queries[0].SegmentCount != 5 {
		t.Fatalf("query touches %d segments, want 5", queries.Queries[0].SegmentCount)
	}
	corruption, err := GenerateCorruption(queries, layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corruption.Cases {
		if c.Locality != LocalityScattered || c.Count != 16 {
			continue
		}
		if c.DistinctSegments != 5 || c.ActualLocality != ActualMaxSpread {
			t.Fatalf("m=16 over 5 segments covered %d (%s)", c.DistinctSegments, c.ActualLocality)
		}
		low, high := 99, 0
		for _, per := range c.RecordsPerSegment {
			low, high = min(low, per.Records), max(high, per.Records)
		}
		// 16 records over 5 segments is 4/3/3/3/3; no segment's capacity (16 or 48) binds.
		if high-low > 1 {
			t.Fatalf("uneven spread %v", c.RecordsPerSegment)
		}
	}
}

func TestCorruptionNeverTouchesRecordsOutsideTheAuditQuery(t *testing.T) {
	queries, corruption, _ := defaultScale(t)
	for _, c := range corruption.Cases {
		query, _ := queries.Query(c.QueryID)
		for _, ordinal := range c.Ordinals() {
			if _, found := slices.BinarySearch(query.Ordinals, ordinal); !found {
				t.Fatalf("%s corrupts ordinal %d outside its audit query", c.QueryID, ordinal)
			}
		}
		if len(c.Records) != c.Count || !slices.IsSorted(c.Ordinals()) || len(slices.Compact(c.Ordinals())) != c.Count {
			t.Fatalf("%s m=%d does not corrupt exactly m distinct records", c.QueryID, c.Count)
		}
	}
}

func TestEveryRepetitionIsADistinctSeededDraw(t *testing.T) {
	_, first, _ := defaultScale(t)
	_, second, _ := defaultScale(t)
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Fatal("the same master seed produced different corruption")
	}
	seeds := map[uint64]bool{}
	type group struct {
		query    string
		count    int
		locality string
	}
	sets := map[group]map[string]bool{}
	for _, c := range first.Cases {
		if seeds[c.Seed] {
			t.Fatalf("seed %d is shared by two cases", c.Seed)
		}
		seeds[c.Seed] = true
		key := group{c.QueryID, c.Count, c.Locality}
		if sets[key] == nil {
			sets[key] = map[string]bool{}
		}
		set := fmt.Sprint(c.Ordinals())
		if sets[key][set] {
			t.Fatalf("%v repeated a corruption set", key)
		}
		sets[key][set] = true
	}
	for key, drawn := range sets {
		if len(drawn) != 23 {
			t.Fatalf("%v has %d distinct draws, want 3 warm-up + 20 measured", key, len(drawn))
		}
	}
	// A different master seed gives different corruption on the same queries' layout.
	layout := testLayout(t, 4, 160, 512)
	params := DefaultParams()
	params.DensePerSegment, params.QueryCount = 256, 2
	params.MasterSeed++
	queries, _ := GenerateQueries(params, layout)
	other, err := GenerateCorruption(queries, layout)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(other.Cases[0].Ordinals()) == fmt.Sprint(first.Cases[0].Ordinals()) {
		t.Fatal("the master seed does not change the corruption")
	}
}

func TestSharedCaseForSingleRecordIsCountedOnce(t *testing.T) {
	if got := Localities(1); !slices.Equal(got, []string{LocalityCommon}) {
		t.Fatalf("m = 1 localities = %v, want one shared case", got)
	}
	if got := Localities(4); !slices.Equal(got, []string{LocalityClustered, LocalityScattered}) {
		t.Fatalf("m = 4 localities = %v", got)
	}
	_, corruption, _ := defaultScale(t)
	common := 0
	for _, c := range corruption.Cases {
		if c.Count == 1 {
			common++
			if c.Locality != LocalityCommon || c.ActualLocality != ActualSingleRecord {
				t.Fatalf("m = 1 case %+v", c)
			}
		}
	}
	if want := 2 * 23; common != want {
		t.Fatalf("%d m = 1 cases, want %d (one shared set per query, not one per locality)", common, want)
	}
	// Two algorithms x 4 shared rows: the summary has one m = 1 group per algorithm.
	var rows []RawRow
	for _, algorithm := range []string{"ACHP", "FIXED"} {
		for rep := 1; rep <= 4; rep++ {
			rows = append(rows, RawRow{Algorithm: algorithm, QueryID: "q1", CorruptionCount: 1, Locality: LocalityCommon,
				Status: StatusOK, LatencyMS: float64(rep), PlanningMS: -1, CassandraReads: -1})
		}
	}
	table := Summarize(rows)
	if len(table) != 2 {
		t.Fatalf("m = 1 summarized into %d groups, want 2 (one per algorithm)", len(table))
	}
	for _, line := range table {
		if line[slices.Index(SummaryHeader, "attempted")] != "4" {
			t.Fatalf("m = 1 rows were counted %s times, want 4", line[slices.Index(SummaryHeader, "attempted")])
		}
	}
}

func TestQueryLocalityAndCorruptionLocalityAreSeparateFields(t *testing.T) {
	queries, corruption, _ := defaultScale(t)
	encoded, _ := json.Marshal(corruption.Cases[0])
	var fields map[string]any
	_ = json.Unmarshal(encoded, &fields)
	for _, name := range []string{"query_locality", "corruption_locality", "actual_corruption_locality", "query_segments"} {
		if _, ok := fields[name]; !ok {
			t.Fatalf("case has no %q field", name)
		}
	}
	for _, c := range corruption.Cases {
		if c.QueryLocality != QueryLocalityMixed {
			t.Fatalf("query locality %q", c.QueryLocality)
		}
		if c.Locality == c.QueryLocality {
			t.Fatal("corruption locality was confused with query locality")
		}
	}
	query := queries.Queries[0]
	if query.SegmentCount != 136 || query.MaxRecordsInSegment != 256 || len(query.Suitability) != 3 {
		t.Fatalf("query locality metadata: %+v", query)
	}
	for _, fit := range query.Suitability {
		// 8 dense segments hold 256 records, 128 sparse ones hold 16: m = 4 and 16 fit
		// everywhere, m = 64 only in the dense segments.
		wantEligible := map[int]int{4: 136, 16: 136, 64: 8}[fit.Count]
		if fit.ClusteredEligibleSegments != wantEligible || fit.ScatteredSegments != fit.Count {
			t.Fatalf("suitability %+v", fit)
		}
	}
	header := strings.Join(RawHeader, ",")
	for _, name := range []string{"query_locality", "corruption_locality", "actual_corruption_locality", "distinct_shards", "distinct_regions", "records_per_segment"} {
		if !strings.Contains(header, name) {
			t.Fatalf("raw.csv has no %s column", name)
		}
	}
}

func TestLocalityMetadataMustMatchTheRecords(t *testing.T) {
	queries, corruption, layout := defaultScale(t)
	edit := func(mutate func(*Case)) error {
		cases := slices.Clone(corruption.Cases)
		for index := range cases {
			if cases[index].Locality == LocalityScattered && cases[index].Count == 16 {
				mutate(&cases[index])
				break
			}
		}
		return ValidateCorruption(queries, CorruptionManifest{Version: ManifestVersion, MasterSeed: corruption.MasterSeed,
			QueriesSHA256: corruption.QueriesSHA256, Cases: cases}, layout)
	}
	for name, mutate := range map[string]func(*Case){
		"segment count":   func(c *Case) { c.DistinctSegments++ },
		"shard count":     func(c *Case) { c.DistinctShards++ },
		"actual locality": func(c *Case) { c.ActualLocality = ActualSingleSegment },
		"per-segment":     func(c *Case) { c.RecordsPerSegment = c.RecordsPerSegment[:1] },
		"query locality":  func(c *Case) { c.QueryLocality = "uniform" },
		"address":         func(c *Case) { c.Records = slices.Clone(c.Records); c.Records[0].Address = "R9/S0/G0/L0" },
	} {
		if edit(mutate) == nil {
			t.Errorf("a case with a wrong %s was accepted", name)
		}
	}
	if err := edit(func(*Case) {}); err != nil {
		t.Fatalf("the unedited manifest was rejected: %v", err)
	}
}

func TestScatteredBelowMaximumSpreadAndClusteredAcrossSegmentsAreRejected(t *testing.T) {
	queries, corruption, layout := defaultScale(t)
	retarget := func(locality string, count int, ordinals func(Query, Case) []int) error {
		cases := slices.Clone(corruption.Cases)
		for index := range cases {
			c := cases[index]
			if c.Locality != locality || c.Count != count {
				continue
			}
			query, _ := queries.Query(c.QueryID)
			rebuilt, err := locate(layout, query, count, ordinals(query, c))
			if err != nil {
				t.Fatal(err)
			}
			rebuilt.QueryID, rebuilt.Count, rebuilt.Locality = c.QueryID, c.Count, c.Locality
			rebuilt.Phase, rebuilt.Repetition, rebuilt.Seed = c.Phase, c.Repetition, c.Seed
			cases[index] = rebuilt
			break
		}
		return ValidateCorruption(queries, CorruptionManifest{Version: ManifestVersion, MasterSeed: corruption.MasterSeed,
			QueriesSHA256: corruption.QueriesSHA256, Cases: cases}, layout)
	}
	// Four records that all share one segment, labelled scattered.
	if err := retarget(LocalityScattered, 4, func(query Query, c Case) []int {
		groups := groupBySegment(query, layout)
		for _, group := range groups {
			if len(group.ordinals) >= 4 {
				return group.ordinals[:4]
			}
		}
		return nil
	}); err == nil {
		t.Error("a scattered case inside one segment was accepted")
	}
	// Four records in two segments, labelled scattered: spread below the maximum of 4.
	if err := retarget(LocalityScattered, 4, func(query Query, c Case) []int {
		groups := groupBySegment(query, layout)
		var picked []int
		for _, group := range groups {
			if len(group.ordinals) >= 2 {
				picked = append(picked, group.ordinals[:2]...)
			}
			if len(picked) == 4 {
				break
			}
		}
		return picked
	}); err == nil {
		t.Error("a scattered case below the maximum spread was accepted")
	}
	// Four records from four segments, labelled clustered.
	if err := retarget(LocalityClustered, 4, func(query Query, c Case) []int {
		groups := groupBySegment(query, layout)
		return []int{groups[0].ordinals[0], groups[1].ordinals[0], groups[2].ordinals[0], groups[3].ordinals[0]}
	}); err == nil {
		t.Error("a clustered case across four segments was accepted")
	}
}

func TestUnsuitableQueryIsFlaggedNotWeakened(t *testing.T) {
	params := DefaultParams()
	params.CorruptionCounts = []int{1, 300} // a dense segment holds only 256
	if err := params.Validate(); err == nil || !strings.Contains(err.Error(), "unsuitable") {
		t.Fatalf("m larger than any segment's requested records: %v", err)
	}
	// The sampler itself reports the same condition on a query whose segments are too thin.
	thin := []segmentGroup{{segment: 0, ordinals: []int{1, 2}}, {segment: 1, ordinals: []int{10, 11}}}
	_, err := sampleClustered(newRand(1), "q9", thin, 3)
	if !IsUnsuitable(err) || !strings.Contains(err.Error(), "q9") {
		t.Fatalf("clustered corruption on thin segments: %v", err)
	}
}

func TestExistingQueriesSatisfyBothLocalities(t *testing.T) {
	// The default query shape (8 dense segments of 256, 128 sparse of 16) supports
	// every m in {4, 16, 64} both clustered and scattered, so the queries are reused
	// unchanged: only their metadata is new.
	queries, _, _ := defaultScale(t)
	for _, query := range queries.Queries {
		for _, fit := range query.Suitability {
			if fit.ClusteredEligibleSegments == 0 || fit.ScatteredSegments != fit.Count {
				t.Fatalf("%s cannot support m=%d: %+v", query.ID, fit.Count, fit)
			}
		}
	}
}
