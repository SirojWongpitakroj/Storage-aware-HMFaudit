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
	// event time in [from, to] (whole seconds, both ends included), optionally of T10.
	from := time.Unix(1_700_000_000+180, 0).UTC()
	to := time.Unix(1_700_000_000+270, 0).UTC()
	for _, tenant := range []string{"", "T10"} {
		var want []int
		for ordinal := 600; ordinal < 1200; ordinal++ {
			when := time.Unix(meta.eventTime[ordinal], 0).UTC()
			if meta.services[meta.service[ordinal]] == "svc-a" && meta.logTypes[meta.logType[ordinal]] == "INFO" &&
				!when.Before(from) && !when.After(to) &&
				(tenant == "" || meta.tenants[meta.tenant[ordinal]] == tenant) {
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
		entries := locatorQuery.FilterTenant(result.Entries)
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
		if tenant == "T10" && len(result.Entries) <= len(entries) {
			t.Fatalf("the range proof should cover more entries (%d) than the tenant's (%d)", len(result.Entries), len(entries))
		}
	}
}

func TestFairHMFNativeQueriesOrderAndFields(t *testing.T) {
	dir := t.TempDir()
	file := `{"queries":[
	 {"scheme":"BLAS","shape":"clustered","q":1,"set":1},
	 {"scheme":"HMF-Audit","region":"R0","shape":"clustered","q":4096,"note":"only 3 distinct queries exist"},
	 {"scheme":"HMF-Audit","region":"R0","shape":"scattered","q":2,"set":2,"service":"s","log_type":"INFO","tenant":"T7","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:09Z"],"record_ordinals":[5,9]},
	 {"scheme":"HMF-Audit","region":"R0","shape":"scattered","q":2,"set":1,"service":"s","log_type":"INFO","tenant":"any (no tenant filter)","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:09Z"],"record_ordinals":[4,8]},
	 {"scheme":"HMF-Audit","region":"R0","shape":"clustered","q":1,"set":1,"service":"s","log_type":"WARN","tenant":"any (no tenant filter)","time_range":["2016-01-02T03:04:05Z","2016-01-02T03:04:05Z"],"record_ordinals":[3]}
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
	if queries[0].Tenant != "" || queries[1].Tenant != "" || queries[2].Tenant != "T7" {
		t.Fatalf("tenants = %q %q %q", queries[0].Tenant, queries[1].Tenant, queries[2].Tenant)
	}
	// A single-second window must still be a valid (non-empty) half-open range.
	if bounds := queries[0].locatorQuery(); !bounds.StartTime.Before(bounds.EndTime) {
		t.Fatalf("one-second query has an empty range: %v .. %v", bounds.StartTime, bounds.EndTime)
	}
	var _ locator.LocatorQuery = queries[0].locatorQuery()
}
