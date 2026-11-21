package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
)

// syntheticNativeMetadata gives 2 regions x 600 records deterministic metadata with
// repeated event times (so a range can contain several logs per second), unsorted
// string tables, and several tenants.
func syntheticNativeMetadata(total int) *fairNativeMetadata {
	meta := &fairNativeMetadata{
		services: []string{"svc-b", "svc-a"},
		logTypes: []string{"WARN", "INFO", "ERROR"},
		tenants:  []string{"T9", "T10", "T2"},
	}
	for ordinal := 0; ordinal < total; ordinal++ {
		meta.service = append(meta.service, uint16((ordinal/7)%2))
		meta.logType = append(meta.logType, uint16((ordinal/3)%3))
		meta.tenant = append(meta.tenant, uint16((ordinal*5)%3))
		meta.eventTime = append(meta.eventTime, 1_700_000_000+int64(ordinal/4)) // four logs per second
	}
	return meta
}

func TestNativeLocatorTreeAnswersTheQueryShapeOfTheFile(t *testing.T) {
	layout, err := newFairLayout([]int{600, 600}, 1, 128)
	if err != nil {
		t.Fatal(err)
	}
	meta := syntheticNativeMetadata(layout.total())
	tree, err := buildNativeLocatorTree(layout, meta)
	if err != nil {
		t.Fatal(err)
	}
	if int(tree.LeafCount) != layout.total() {
		t.Fatalf("tree has %d entries, want %d", tree.LeafCount, layout.total())
	}

	// Brute force: the records of region R1 with service svc-a, type INFO and an
	// event time in [from, to] (whole seconds, both ends included), of one tenant.
	from := time.Unix(1_700_000_000+180, 0).UTC()
	to := time.Unix(1_700_000_000+270, 0).UTC()
	for _, tenant := range []string{"T10", "T9"} {
		var want []int
		for ordinal := 600; ordinal < 1200; ordinal++ {
			when := time.Unix(meta.eventTime[ordinal], 0).UTC()
			if meta.services[meta.service[ordinal]] == "svc-a" && meta.logTypes[meta.logType[ordinal]] == "INFO" &&
				!when.Before(from) && !when.After(to) &&
				meta.tenants[meta.tenant[ordinal]] == tenant {
				want = append(want, ordinal)
			}
		}
		if len(want) < 2 {
			t.Fatalf("tenant %q: test data has %d matching records; the check needs at least 2", tenant, len(want))
		}
		query := fairHMFNativeQuery{Q: len(want), Region: "R1", Service: "svc-a", LogType: "INFO", Tenant: tenant, From: from, To: to}
		locatorQuery := query.locatorQuery()
		result, err := tree.Resolve(locatorQuery)
		if err != nil {
			t.Fatal(err)
		}
		entries := result.Entries // the tenant leads the key order: the range holds only its logs
		_, got, err := nativePhysicalAddresses(layout, entries)
		if err != nil {
			t.Fatal(err)
		}
		sort.Ints(got)
		if len(got) != len(want) {
			t.Fatalf("tenant %q: ALL returned %d records, want %d", tenant, len(got), len(want))
		}
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("tenant %q: record %d is ordinal %d, want %d", tenant, index, got[index], want[index])
			}
		}
	}
}

func TestFairHMFNativeQueriesOrderAndFields(t *testing.T) {
	dir := t.TempDir()
	file := `{"queries":[
	 {"scheme":"BLAS","shape":"clustered","q":1,"set":1},
	 {"scheme":"HMF-Audit","region":"R0","shape":"clustered","q":4096,"note":"only 3 distinct queries exist"},
	 {"scheme":"HMF-Audit","region":"R0","shape":"scattered","q":2,"set":2,"service":"s","log_type":"INFO","tenant":"T7","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:09Z"],"record_ordinals":[5,9]},
	 {"scheme":"HMF-Audit","region":"R0","shape":"scattered","q":2,"set":1,"service":"s","log_type":"INFO","tenant":"T3","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:09Z"],"record_ordinals":[4,8]},
	 {"scheme":"HMF-Audit","region":"R0","shape":"clustered","q":1,"set":1,"service":"s","log_type":"WARN","tenant":"T1","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:05Z"],"record_ordinals":[3]}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "R0_queries.json"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	queries, err := fairHMFNativeQueries(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, query := range queries {
		names = append(names, query.name())
	}
	want := []string{"clustered/q=1/set=1", "scattered/q=2/set=1", "scattered/q=2/set=2"}
	if len(names) != 3 || names[0] != want[0] || names[1] != want[1] || names[2] != want[2] {
		t.Fatalf("queries = %v, want %v", names, want)
	}
	if queries[0].Tenant != "T1" || queries[1].Tenant != "T3" || queries[2].Tenant != "T7" {
		t.Fatalf("tenants = %q %q %q", queries[0].Tenant, queries[1].Tenant, queries[2].Tenant)
	}
	// A single-second window must still be a valid (non-empty) half-open range.
	if bounds := queries[0].locatorQuery(); !bounds.StartTime.Before(bounds.EndTime) {
		t.Fatalf("one-second query has an empty range: %v .. %v", bounds.StartTime, bounds.EndTime)
	}
	var _ locator.LocatorQuery = queries[0].locatorQuery()
}

// A query without a tenant cannot be a range under the tenant-first key order.
func TestFairHMFNativeQueriesRejectMissingTenant(t *testing.T) {
	dir := t.TempDir()
	file := `{"queries":[
	 {"scheme":"HMF-Audit","region":"R0","shape":"clustered","q":1,"set":1,"service":"s","log_type":"WARN","tenant":"","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:05Z"],"record_ordinals":[3]}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "R0_queries.json"), []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fairHMFNativeQueries(dir); err == nil {
		t.Fatal("a query without a tenant was accepted")
	}
}

// A batch of several ranges (one per tenant group) is read in file order and must add up to q.
func TestFairHMFNativeQueriesMultiRange(t *testing.T) {
	dir := t.TempDir()
	write := func(entry string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "R0_queries.json"), []byte(`{"queries":[`+entry+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	good := `{"scheme":"HMF-Audit","region":"R0","shape":"clustered","q":5,"set":1,"record_ordinals":[1,2,3,4,5],
	 "ranges":[
	  {"tenant":"T1","service":"s","log_type":"INFO","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:06Z"],"returns":2},
	  {"tenant":"T2","service":"s","log_type":"WARN","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:07Z"],"returns":3}]}`
	write(good)
	queries, err := fairHMFNativeQueries(dir)
	if err != nil {
		t.Fatal(err)
	}
	ranges := queries[0].allRanges()
	if len(queries) != 1 || len(ranges) != 2 || ranges[0].Tenant != "T1" || ranges[1].Tenant != "T2" ||
		ranges[1].Returns != 3 || ranges[1].LogType != "WARN" || ranges[1].Region != "R0" {
		t.Fatalf("queries = %+v", queries)
	}
	if bounds := ranges[1].locatorQuery(); !bounds.EndTime.Equal(ranges[1].To.Add(time.Second)) {
		t.Fatalf("range is not closed to the second: %v", bounds.EndTime)
	}
	// The ranges must return exactly q logs together.
	write(`{"scheme":"HMF-Audit","region":"R0","shape":"clustered","q":6,"set":1,"record_ordinals":[1,2,3,4,5,6],
	 "ranges":[{"tenant":"T1","service":"s","log_type":"INFO","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:06Z"],"returns":2},
	           {"tenant":"T2","service":"s","log_type":"WARN","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:07Z"],"returns":3}]}`)
	if _, err := fairHMFNativeQueries(dir); err == nil {
		t.Fatal("ranges that do not add up to q were accepted")
	}
	// Every range needs a tenant.
	write(`{"scheme":"HMF-Audit","region":"R0","shape":"clustered","q":1,"set":1,"record_ordinals":[1],
	 "ranges":[{"tenant":"","service":"s","log_type":"INFO","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:05Z"],"returns":1}]}`)
	if _, err := fairHMFNativeQueries(dir); err == nil {
		t.Fatal("a range without a tenant was accepted")
	}
}

// Resolving a batch of ranges and joining the results gives the union of the groups' records.
func TestNativeLocatorTreeAnswersAMultiRangeBatch(t *testing.T) {
	layout, err := newFairLayout([]int{600, 600}, 1, 128)
	if err != nil {
		t.Fatal(err)
	}
	meta := syntheticNativeMetadata(layout.total())
	tree, err := buildNativeLocatorTree(layout, meta)
	if err != nil {
		t.Fatal(err)
	}
	from, to := time.Unix(1_700_000_000+180, 0).UTC(), time.Unix(1_700_000_000+270, 0).UTC()
	var parts []fairHMFRange
	var want []int
	for _, tenant := range []string{"T10", "T9"} {
		count := 0
		for ordinal := 600; ordinal < 1200; ordinal++ {
			when := time.Unix(meta.eventTime[ordinal], 0).UTC()
			if meta.services[meta.service[ordinal]] == "svc-a" && meta.logTypes[meta.logType[ordinal]] == "INFO" &&
				!when.Before(from) && !when.After(to) && meta.tenants[meta.tenant[ordinal]] == tenant {
				want = append(want, ordinal)
				count++
			}
		}
		if count == 0 {
			t.Fatalf("tenant %q has no matching test records", tenant)
		}
		parts = append(parts, fairHMFRange{Region: "R1", Service: "svc-a", LogType: "INFO", Tenant: tenant,
			From: from, To: to, Returns: count})
	}
	query := fairHMFNativeQuery{Q: len(want), Ranges: parts}
	var entries []locator.LocatorEntry
	for _, part := range query.allRanges() {
		result, err := tree.Resolve(part.locatorQuery())
		if err != nil {
			t.Fatal(err)
		}
		if err := locator.VerifyLocatorQueryResult(part.locatorQuery(), result, tree.RootHash); err != nil {
			t.Fatal(err)
		}
		if len(result.Entries) != part.Returns {
			t.Fatalf("tenant %q: range returned %d, want %d", part.Tenant, len(result.Entries), part.Returns)
		}
		entries = append(entries, result.Entries...)
	}
	_, got, err := nativePhysicalAddresses(layout, entries)
	if err != nil {
		t.Fatal(err)
	}
	sort.Ints(got)
	sort.Ints(want)
	if len(got) != len(want) {
		t.Fatalf("batch has %d records, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("record %d is ordinal %d, want %d", index, got[index], want[index])
		}
	}
}

// Bulk loading must build exactly the tree that one Insert per record builds; it is only faster.
func TestNativeLocatorTreeBulkLoadMatchesIncrementalInserts(t *testing.T) {
	layout, err := newFairLayout([]int{150_000, 150_000}, 2, 8192)
	if err != nil {
		t.Fatal(err)
	}
	meta := syntheticNativeMetadata(layout.total())
	build := func(bulk bool) (*locator.LocatorTree, time.Duration) {
		defer func(previous bool) { fairNativeBulkLoad = previous }(fairNativeBulkLoad)
		fairNativeBulkLoad = bulk
		start := time.Now()
		tree, err := buildNativeLocatorTree(layout, meta)
		if err != nil {
			t.Fatal(err)
		}
		return tree, time.Since(start)
	}
	slow, slowTime := build(false)
	fast, fastTime := build(true)
	if slow.RootHash != fast.RootHash || slow.LeafCount != fast.LeafCount {
		t.Fatalf("bulk-loaded tree differs: root %x vs %x, leaves %d vs %d",
			fast.RootHash, slow.RootHash, fast.LeafCount, slow.LeafCount)
	}
	t.Logf("%d records: one insert per record %v, bulk load %v (%.1fx)", layout.total(), slowTime, fastTime,
		float64(slowTime)/float64(fastTime))
}

func TestLocalizationBatchIsSortedAndTampersTheMiddleRecord(t *testing.T) {
	layout, err := newFairLayout([]int{600, 600}, 1, 128)
	if err != nil {
		t.Fatal(err)
	}
	// The ordinals come in file order (not ascending); the batch must be ascending, and the
	// tampered record is the element at index len/2 of the ascending list.
	batch, tampered, err := fairHMFLocalizationBatch(layout, []int{900, 5, 130, 700, 41})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{5, 41, 130, 700, 900}
	if len(batch) != len(want) {
		t.Fatalf("batch has %d records, want %d", len(batch), len(want))
	}
	for index, ordinal := range want {
		if batch[index] != layout.address(ordinal) {
			t.Fatalf("batch[%d] = %+v, want ordinal %d", index, batch[index], ordinal)
		}
	}
	if tampered != layout.address(130) {
		t.Fatalf("tampered = %+v, want ordinal 130 (index 2 of 5)", tampered)
	}
	single, only, err := fairHMFLocalizationBatch(layout, []int{777})
	if err != nil || len(single) != 1 || only != layout.address(777) {
		t.Fatalf("q=1 batch %+v tampered %+v err %v", single, only, err)
	}
	for name, ordinals := range map[string][]int{"empty": nil, "duplicate": {3, 3}, "negative": {-1}, "past the end": {1200}} {
		if _, _, err := fairHMFLocalizationBatch(layout, ordinals); err == nil {
			t.Fatalf("%s ordinals were accepted", name)
		}
	}
}
