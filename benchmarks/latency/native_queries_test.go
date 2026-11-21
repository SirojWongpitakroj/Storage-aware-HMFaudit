package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"testing"
	"time"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// Native query sets (FAIR_QUERY_DIR). In this mode the ALL locator tree indexes every
// record under its real tenant, service, log type, region and event time, and the
// verification benchmark runs the HMF-Audit queries of R0_queries.json: one ALL range
// query (tenant, service, log type, region, time range) per audit batch.

// fairNativeMetadata is the per-record metadata the ALL tree indexes.
type fairNativeMetadata struct {
	services, logTypes, tenants []string // string tables, so 10M keys share a few strings
	service, logType            []uint16 // per record, indexes into the tables
	tenant                      []uint16
	eventTime                   []int64 // Unix seconds
}

// fairNativeRecord is the part of a dataset line the ALL tree needs.
type fairNativeRecord struct {
	ServiceID string `json:"service_id"`
	LogType   string `json:"log_type"`
	TenantID  string `json:"tenant_id"`
	EventTime string `json:"event_time"`
}

// loadFairNativeMetadata reads the dataset once more and keeps each record's ALL
// metadata (about 16 bytes per record).
func loadFairNativeMetadata(path string, total int) (*fairNativeMetadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	meta := &fairNativeMetadata{
		service: make([]uint16, 0, total), logType: make([]uint16, 0, total),
		tenant: make([]uint16, 0, total), eventTime: make([]int64, 0, total),
	}
	intern := func(table *[]string, index map[string]uint16, value string) (uint16, error) {
		if id, ok := index[value]; ok {
			return id, nil
		}
		if len(*table) >= 1<<16-1 {
			return 0, fmt.Errorf("more than 65535 distinct values")
		}
		id := uint16(len(*table))
		*table = append(*table, value)
		index[value] = id
		return id, nil
	}
	serviceIndex, typeIndex, tenantIndex := map[string]uint16{}, map[string]uint16{}, map[string]uint16{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		var record fairNativeRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("decode dataset record %d: %w", len(meta.service), err)
		}
		if record.ServiceID == "" || record.LogType == "" || record.TenantID == "" {
			return nil, fmt.Errorf("record %d lacks service, log type or tenant", len(meta.service))
		}
		when, err := time.Parse(time.RFC3339, record.EventTime)
		if err != nil {
			return nil, fmt.Errorf("record %d event time: %w", len(meta.service), err)
		}
		service, err := intern(&meta.services, serviceIndex, record.ServiceID)
		if err != nil {
			return nil, err
		}
		logType, err := intern(&meta.logTypes, typeIndex, record.LogType)
		if err != nil {
			return nil, err
		}
		tenant, err := intern(&meta.tenants, tenantIndex, record.TenantID)
		if err != nil {
			return nil, err
		}
		meta.service = append(meta.service, service)
		meta.logType = append(meta.logType, logType)
		meta.tenant = append(meta.tenant, tenant)
		meta.eventTime = append(meta.eventTime, when.Unix())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(meta.service) != total {
		return nil, fmt.Errorf("dataset has %d records, expected %d", len(meta.service), total)
	}
	return meta, nil
}

// stringRanks maps each table index to its rank in sorted string order, which is the
// order the ALL key comparison uses.
func stringRanks(table []string) []uint16 {
	order := make([]int, len(table))
	for index := range order {
		order[index] = index
	}
	sort.Slice(order, func(i, j int) bool { return table[order[i]] < table[order[j]] })
	ranks := make([]uint16, len(table))
	for rank, index := range order {
		ranks[index] = uint16(rank)
	}
	return ranks
}

// buildNativeLocatorTree indexes every record under its real metadata. Records are
// inserted in key order (tenant, service, log type, region, event time, log ID), the
// same right-edge insertion the synthetic tree uses, so the tree's shape does not
// depend on the dataset's file order.
func buildNativeLocatorTree(layout *fairLayout, meta *fairNativeMetadata) (*locator.LocatorTree, error) {
	total := layout.total()
	if len(meta.service) != total {
		return nil, fmt.Errorf("metadata for %d records, layout has %d", len(meta.service), total)
	}
	serviceRank, typeRank, tenantRank := stringRanks(meta.services), stringRanks(meta.logTypes), stringRanks(meta.tenants)
	region := make([]uint8, total)
	for index := range layout.starts {
		for ordinal := layout.starts[index]; ordinal < layout.starts[index]+layout.sizes[index]; ordinal++ {
			region[ordinal] = uint8(index)
		}
	}
	order := make([]int32, total)
	for ordinal := range order {
		order[ordinal] = int32(ordinal)
	}
	slices.SortFunc(order, func(a, b int32) int {
		switch {
		case tenantRank[meta.tenant[a]] != tenantRank[meta.tenant[b]]:
			return int(tenantRank[meta.tenant[a]]) - int(tenantRank[meta.tenant[b]])
		case serviceRank[meta.service[a]] != serviceRank[meta.service[b]]:
			return int(serviceRank[meta.service[a]]) - int(serviceRank[meta.service[b]])
		case typeRank[meta.logType[a]] != typeRank[meta.logType[b]]:
			return int(typeRank[meta.logType[a]]) - int(typeRank[meta.logType[b]])
		case region[a] != region[b]:
			return int(region[a]) - int(region[b])
		case meta.eventTime[a] != meta.eventTime[b]:
			if meta.eventTime[a] < meta.eventTime[b] {
				return -1
			}
			return 1
		}
		return int(a) - int(b) // the log ID grows with the ordinal
	})
	tree := locator.NewLocatorTree(fairLocatorOrder)
	if fairNativeBulkLoad {
		// Setup only: bulk loading builds exactly the tree of one Insert per record (same
		// pages and root, see internal/all/locator_bulk_test.go) but hashes each page once,
		// at the end, instead of re-hashing the path to the root after every insert.
		tree.BeginBulkLoad()
	}
	for _, ordinal32 := range order {
		ordinal := int(ordinal32)
		address := layout.address(ordinal)
		key := locator.LocatorKey{
			LogID:     fairHMFUUID(ordinal),
			EventTime: time.Unix(meta.eventTime[ordinal], 0).UTC(),
			RegionID:  address.RegionID,
			TenantID:  meta.tenants[meta.tenant[ordinal]],
			ServiceID: meta.services[meta.service[ordinal]],
			LogType:   meta.logTypes[meta.logType[ordinal]],
		}
		value := &locator.LocatorValue{
			RegionID:  address.RegionID,
			ShardID:   fmt.Sprintf("%d", address.ShardID),
			SegmentID: fmt.Sprintf("%d", address.SegmentID),
			LeafID:    fmt.Sprintf("%d", address.LeafID),
		}
		tree.Insert(key, value, tree.RootPage)
	}
	if fairNativeBulkLoad {
		tree.FinishBulkLoad()
	}
	return tree, nil
}

// fairNativeBulkLoad turns the bulk-load shortcut of buildNativeLocatorTree on (default) or off
// (the tests compare both).
var fairNativeBulkLoad = true

// fairHMFNativeQuery is one HMF-Audit audit batch from the query file.
// fairHMFRange is one ALL range query: one (tenant, service, log type, region) group over
// a time range. Returns is how many logs the range holds.
type fairHMFRange struct {
	Region, Service, LogType, Tenant string
	From, To                         time.Time
	Returns                          int
}

// locatorQuery is the ALL query: the time range [From, To] covers whole seconds, and
// the ALL range is half-open, so it ends one second after To.
func (r fairHMFRange) locatorQuery() locator.LocatorQuery {
	return locator.LocatorQuery{
		TenantID: r.Tenant, ServiceID: r.Service, LogType: r.LogType, RegionID: r.Region,
		StartTime: r.From, EndTime: r.To.Add(time.Second),
	}
}

// fairHMFNativeQuery is one HMF-Audit audit batch from the query file. A batch is one
// ALL range, or, when a single (tenant, service, log type, region) group has no run of
// exactly q logs in the shape, several ranges (Ranges, one per group) whose results
// together are the q records: each range is resolved and verified on its own, the
// addresses are concatenated, and one HPP proof covers them all.
type fairHMFNativeQuery struct {
	Shape    string
	Q        int
	Set      int
	Region   string
	Service  string
	LogType  string
	Tenant   string
	From, To time.Time
	Ranges   []fairHMFRange // empty: the single range given by the fields above
	Ordinals []int
}

func (query fairHMFNativeQuery) name() string {
	return fmt.Sprintf("%s/q=%d/set=%d", query.Shape, query.Q, query.Set)
}

// allRanges returns the batch's ALL ranges in file order.
func (query fairHMFNativeQuery) allRanges() []fairHMFRange {
	if len(query.Ranges) > 0 {
		return query.Ranges
	}
	return []fairHMFRange{{Region: query.Region, Service: query.Service, LogType: query.LogType,
		Tenant: query.Tenant, From: query.From, To: query.To, Returns: query.Q}}
}

// locatorQuery is the ALL query of the batch's first (for most batches, only) range.
func (query fairHMFNativeQuery) locatorQuery() locator.LocatorQuery {
	return query.allRanges()[0].locatorQuery()
}

// fairHMFNativeQueries reads R0_queries.json from dir: shapes in the order clustered,
// scattered; q ascending; the sets of a cell in file order.
func fairHMFNativeQueries(dir string) ([]fairHMFNativeQuery, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "R0_queries.json"))
	if err != nil {
		return nil, fmt.Errorf("read HMF-Audit query file: %w", err)
	}
	var file struct {
		Queries []struct {
			Scheme         string   `json:"scheme"`
			Region         string   `json:"region"`
			Shape          string   `json:"shape"`
			Q              int      `json:"q"`
			Set            int      `json:"set"`
			Service        string   `json:"service"`
			LogType        string   `json:"log_type"`
			Tenant         string   `json:"tenant"`
			TimeRange      []string `json:"time_range"`
			RecordOrdinals []int    `json:"record_ordinals"`
			Note           string   `json:"note"`
			Ranges         []struct {
				Tenant    string   `json:"tenant"`
				Service   string   `json:"service"`
				LogType   string   `json:"log_type"`
				TimeRange []string `json:"time_range"`
				Returns   int      `json:"returns"`
			} `json:"ranges"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parse HMF-Audit query file: %w", err)
	}
	type cell struct {
		shape string
		q     int
	}
	cells := map[cell][]fairHMFNativeQuery{}
	for _, entry := range file.Queries {
		if entry.Scheme != "HMF-Audit" || entry.Note != "" { // a note marks a cell with fewer sets
			continue
		}
		if len(entry.RecordOrdinals) != entry.Q {
			return nil, fmt.Errorf("HMF-Audit %s q=%d set %d: malformed query", entry.Shape, entry.Q, entry.Set)
		}
		parse := func(rangeText []string) (from, to time.Time, err error) {
			if len(rangeText) != 2 {
				return from, to, fmt.Errorf("HMF-Audit %s q=%d set %d: malformed time range", entry.Shape, entry.Q, entry.Set)
			}
			if from, err = time.Parse(time.RFC3339, rangeText[0]); err != nil {
				return from, to, err
			}
			to, err = time.Parse(time.RFC3339, rangeText[1])
			return from, to, err
		}
		query := fairHMFNativeQuery{Shape: entry.Shape, Q: entry.Q, Set: entry.Set, Ordinals: entry.RecordOrdinals}
		if len(entry.Ranges) == 0 {
			from, to, err := parse(entry.TimeRange)
			if err != nil {
				return nil, err
			}
			if entry.Tenant == "" || entry.Service == "" || entry.LogType == "" || entry.Region == "" {
				return nil, fmt.Errorf("HMF-Audit %s q=%d set %d: tenant, service, log type and region are required (the ALL key starts with the tenant; regenerate the query files)",
					entry.Shape, entry.Q, entry.Set)
			}
			query.Region, query.Service, query.LogType, query.Tenant, query.From, query.To =
				entry.Region, entry.Service, entry.LogType, entry.Tenant, from, to
		} else {
			total := 0
			for number, part := range entry.Ranges {
				from, to, err := parse(part.TimeRange)
				if err != nil {
					return nil, err
				}
				if part.Tenant == "" || part.Service == "" || part.LogType == "" || entry.Region == "" || part.Returns < 1 {
					return nil, fmt.Errorf("HMF-Audit %s q=%d set %d range %d: tenant, service, log type, region and a positive count are required",
						entry.Shape, entry.Q, entry.Set, number+1)
				}
				total += part.Returns
				query.Ranges = append(query.Ranges, fairHMFRange{Region: entry.Region, Service: part.Service,
					LogType: part.LogType, Tenant: part.Tenant, From: from, To: to, Returns: part.Returns})
			}
			if total != entry.Q {
				return nil, fmt.Errorf("HMF-Audit %s q=%d set %d: its %d ranges return %d logs, want %d",
					entry.Shape, entry.Q, entry.Set, len(entry.Ranges), total, entry.Q)
			}
			first := query.Ranges[0]
			query.Region, query.Service, query.LogType, query.Tenant, query.From, query.To =
				first.Region, first.Service, first.LogType, first.Tenant, first.From, first.To
		}
		key := cell{entry.Shape, entry.Q}
		cells[key] = append(cells[key], query)
	}
	var result []fairHMFNativeQuery
	for _, shape := range []string{"clustered", "scattered"} {
		var sizes []int
		for key := range cells {
			if key.shape == shape {
				sizes = append(sizes, key.q)
			}
		}
		sort.Ints(sizes)
		for _, q := range sizes {
			sets := cells[cell{shape, q}]
			sort.Slice(sets, func(i, j int) bool { return sets[i].Set < sets[j].Set })
			result = append(result, sets...)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no HMF-Audit queries in %s", dir)
	}
	return result, nil
}

// nativePhysicalAddresses turns verified ALL entries into physical addresses, checking
// that each entry's log ID and region match the address it points to.
func nativePhysicalAddresses(layout *fairLayout, entries []locator.LocatorEntry) ([]hpp.PhysicalAddress, []int, error) {
	addresses := make([]hpp.PhysicalAddress, 0, len(entries))
	ordinals := make([]int, 0, len(entries))
	seen := make(map[hpp.PhysicalAddress]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Value == nil {
			return nil, nil, fmt.Errorf("ALL entry %v has no physical address", entry.Key.LogID)
		}
		shard, err := strconv.ParseInt(entry.Value.ShardID, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("ALL shard %q: %w", entry.Value.ShardID, err)
		}
		segment, err := strconv.ParseInt(entry.Value.SegmentID, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("ALL segment %q: %w", entry.Value.SegmentID, err)
		}
		leaf, err := strconv.ParseInt(entry.Value.LeafID, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("ALL leaf %q: %w", entry.Value.LeafID, err)
		}
		address := hpp.PhysicalAddress{RegionID: entry.Value.RegionID, ShardID: shard, SegmentID: segment, LeafID: leaf}
		ordinal, valid := layout.ordinal(address)
		if !valid || entry.Key.LogID != fairHMFUUID(ordinal) || entry.Key.RegionID != address.RegionID {
			return nil, nil, fmt.Errorf("ALL entry %v is not bound to physical address %+v", entry.Key.LogID, address)
		}
		if _, duplicate := seen[address]; duplicate {
			return nil, nil, fmt.Errorf("ALL returned duplicate physical address %+v", address)
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
		ordinals = append(ordinals, ordinal)
	}
	return addresses, ordinals, nil
}

// resolveNative makes the batch's ALL range queries (one, or one per group for a
// multi-range batch), verifies each proof against the trusted locator root, and joins
// the results. The tenant leads the ALL key order, so each range holds only that
// tenant's logs. check also compares the result with the records the query file expects.
// It returns the physical addresses and how many entries the range proofs covered.
func (fixture *persistentFairHMFFixture) resolveNative(ctx context.Context,
	query fairHMFNativeQuery, check bool) ([]hpp.PhysicalAddress, int, error) {
	var entries []locator.LocatorEntry
	scanned := 0
	for number, part := range query.allRanges() {
		locatorQuery := part.locatorQuery()
		result, err := fixture.allRepo.ResolveLocatorQuery(ctx, fairLocatorTreeID, fixture.locatorRoot, locatorQuery)
		if err != nil {
			return nil, 0, fmt.Errorf("resolve ALL locator query: %w", err)
		}
		if err := locator.VerifyLocatorQueryResult(locatorQuery, result, fixture.locatorRoot); err != nil {
			return nil, 0, fmt.Errorf("verify ALL locator proof: %w", err)
		}
		if len(result.Entries) != part.Returns {
			return nil, 0, fmt.Errorf("ALL returned %d records for range %d of %s, want %d",
				len(result.Entries), number+1, query.name(), part.Returns)
		}
		entries = append(entries, result.Entries...)
		scanned += len(result.Entries)
	}
	if len(entries) != query.Q {
		return nil, 0, fmt.Errorf("ALL returned %d records for %s, want %d", len(entries), query.name(), query.Q)
	}
	addresses, ordinals, err := nativePhysicalAddresses(fixture.forest.layout, entries)
	if err != nil {
		return nil, 0, err
	}
	if check {
		want := append([]int(nil), query.Ordinals...)
		got := append([]int(nil), ordinals...)
		sort.Ints(want)
		sort.Ints(got)
		if !slices.Equal(got, want) {
			return nil, 0, fmt.Errorf("ALL returned different records than the query file lists for %s", query.name())
		}
	}
	return addresses, scanned, nil
}

// BenchmarkFairHMFNativeVerification is BenchmarkFairHMFVerificationCore's body for
// native query sets: one logical ALL query, the HPP proof built from Cassandra and
// PostgreSQL, and verification against the anchored root, per timed operation.
func runFairHMFNativeVerification(b *testing.B, fixture *persistentFairHMFFixture, dir string) {
	queries, err := fairHMFNativeQueries(dir)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	for _, query := range queries {
		b.Run(query.name(), func(b *testing.B) {
			addresses, scanned, err := fixture.resolveNative(ctx, query, true)
			if err != nil {
				b.Fatal(err)
			}
			reference, err := fixture.verify(ctx, addresses)
			if err != nil {
				b.Fatal(err)
			}
			run := func() {
				resolved, _, err := fixture.resolveNative(ctx, query, false)
				if err != nil {
					b.Fatal(err)
				}
				result, err := fixture.verify(ctx, resolved)
				if err != nil {
					b.Fatal(err)
				}
				fairHMFResult = result.CalculatedGlobalRoot
			}
			warmup := fairHMFWarmupCount(b)
			for range warmup {
				run()
			}
			b.ResetTimer()
			b.ReportMetric(float64(query.Q), "records/op")
			b.ReportMetric(float64(len(reference.Proof.Leaves)), "proof-leaves/op")
			b.ReportMetric(float64(len(reference.Proof.Nodes)), "proof-nodes/op")
			b.ReportMetric(1, "postgres-batches/op")
			b.ReportMetric(float64(len(query.allRanges())), "all-queries/op")
			b.ReportMetric(float64(scanned), "all-entries/op")
			b.ReportMetric(9, "workload-version/op")
			b.ReportMetric(1, "cassandra-proof-builds/op")
			b.ReportMetric(float64(fixture.hppConcurrency), "hpp-concurrency/op")
			b.ReportMetric(float64(warmup), "warmup-ops")
			for range b.N {
				run()
			}
		})
	}
}

// fairHMFLocalizationBatch is the audit batch of a native query in the localization
// experiment. The records are the query's, in ascending ordinal order (EVSEB is given the
// same list in the same order), and the tampered record is the middle one of that list,
// index len/2. Both schemes therefore audit the same records and tamper the same one.
func fairHMFLocalizationBatch(layout *fairLayout, ordinals []int) (batch []hpp.PhysicalAddress, tampered hpp.PhysicalAddress, err error) {
	if len(ordinals) == 0 {
		return nil, hpp.PhysicalAddress{}, fmt.Errorf("a localization batch needs at least one record")
	}
	sorted := append([]int(nil), ordinals...)
	sort.Ints(sorted)
	batch = make([]hpp.PhysicalAddress, 0, len(sorted))
	for index, ordinal := range sorted {
		if ordinal < 0 || ordinal >= layout.total() {
			return nil, hpp.PhysicalAddress{}, fmt.Errorf("ordinal %d is outside the %d-record layout", ordinal, layout.total())
		}
		if index > 0 && ordinal == sorted[index-1] {
			return nil, hpp.PhysicalAddress{}, fmt.Errorf("ordinal %d is listed twice", ordinal)
		}
		batch = append(batch, layout.address(ordinal))
	}
	return batch, batch[len(batch)/2], nil
}

// runFairHMFNativeLocalization is Experiment 2 on the native query set: for every HMF-Audit
// query of R0_queries.json, the ALL range query is resolved and checked once (outside the
// timer), the middle record of the result is tampered in PostgreSQL, and each timed
// operation detects the mismatch and localizes the tampered record.
func runFairHMFNativeLocalization(b *testing.B, fixture *persistentFairHMFFixture, dir string) {
	queries, err := fairHMFNativeQueries(dir)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	for _, query := range queries {
		b.Run(query.name(), func(b *testing.B) {
			if _, _, err := fixture.resolveNative(ctx, query, true); err != nil {
				b.Fatal(err)
			}
			addresses, tampered, err := fairHMFLocalizationBatch(fixture.forest.layout, query.Ordinals)
			if err != nil {
				b.Fatal(err)
			}
			if err := fixture.setTampered(ctx, tampered); err != nil {
				b.Fatal(err)
			}
			localized, err := fixture.localize(ctx, addresses)
			if err != nil {
				b.Fatal(err)
			}
			if len(localized.Proof.Suspects) != 1 || localized.Proof.Suspects[0].Address == nil ||
				*localized.Proof.Suspects[0].Address != tampered {
				b.Fatalf("localization of %s found %+v, want the tampered record %+v",
					query.name(), localized.Proof.Suspects, tampered)
			}
			warmup := fairHMFWarmupCount(b)
			for range warmup {
				result, err := fixture.localize(ctx, addresses)
				if err != nil {
					b.Fatal(err)
				}
				fairHMFResult = result.CalculatedReferenceRoot
			}
			b.ResetTimer()
			b.ReportMetric(float64(query.Q), "records/op")
			b.ReportMetric(1, "tampered-records/op")
			b.ReportMetric(float64(len(localized.Proof.Rounds)), "pruning-rounds/op")
			b.ReportMetric(float64(len(localized.Proof.Suspects)), "suspects/op")
			b.ReportMetric(1, "postgres-batches/op")
			b.ReportMetric(1, "cassandra-proof-builds/op")
			b.ReportMetric(1, "cassandra-reference-leaf-fetches/op")
			b.ReportMetric(9, "workload-version/op")
			b.ReportMetric(float64(fixture.hppConcurrency), "hpp-concurrency/op")
			b.ReportMetric(float64(warmup), "warmup-ops")
			for range b.N {
				result, err := fixture.localize(ctx, addresses)
				if err != nil {
					b.Fatal(err)
				}
				fairHMFResult = result.CalculatedReferenceRoot
			}
		})
	}
	if err := fixture.clearTamper(ctx); err != nil {
		b.Fatal(err)
	}
}
