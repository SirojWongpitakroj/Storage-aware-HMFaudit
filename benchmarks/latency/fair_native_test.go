package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
)

// Experiment 1 (and the ablation) on the native query set
// (systems/experiments/native-queries/R0_queries.json): HMF-Audit answers
// native ALL queries -- (region, service, log type, [start, end), optional
// tenant) -- five per (shape, q). The ALL tree therefore indexes every record
// under its real attributes from the shared dataset; the range is resolved
// over all tenants and a named tenant is filtered afterwards (FilterTenant),
// exactly as internal/all/locator_range.go defines the query.

const fairNativeWorkloadVersion = 9

var fairNativeShapes = []string{"clustered", "scattered"}

const fairNativeSets = 5

func fairNativeQueriesDir() string { return os.Getenv("FAIR_NATIVE_QUERIES_DIR") }

type fairHMFNativeQuery struct {
	Shape string
	Q     int
	Set   int
	Query locator.LocatorQuery
}

func (native fairHMFNativeQuery) name() string {
	return fmt.Sprintf("%s/q=%d/set=%d", native.Shape, native.Q, native.Set)
}

// loadFairHMFNativeQueries reads the HMF-Audit queries for the requested q
// values. The file lists five queries per (shape, q); their order there is the
// set number 1..5. time_range is half-open [from, to).
func loadFairHMFNativeQueries(dir string, counts []int) ([]fairHMFNativeQuery, error) {
	data, err := os.ReadFile(filepath.Join(dir, "R0_queries.json"))
	if err != nil {
		return nil, err
	}
	var file struct {
		Queries []struct {
			Scheme    string   `json:"scheme"`
			Region    string   `json:"region"`
			Shape     string   `json:"shape"`
			Q         int      `json:"q"`
			Returns   int      `json:"returns"`
			Service   string   `json:"service"`
			LogType   string   `json:"log_type"`
			Tenant    string   `json:"tenant"`
			TimeRange []string `json:"time_range"`
			Note      string   `json:"note"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode native queries: %w", err)
	}
	wanted := make(map[int]bool, len(counts))
	for _, q := range counts {
		wanted[q] = true
	}
	shapeOrder := map[string]int{}
	for index, shape := range fairNativeShapes {
		shapeOrder[shape] = index
	}
	next := map[[2]int]int{}
	var queries []fairHMFNativeQuery
	for _, entry := range file.Queries {
		if entry.Scheme != "HMF-Audit" || !wanted[entry.Q] {
			continue
		}
		order, ok := shapeOrder[entry.Shape]
		if !ok {
			return nil, fmt.Errorf("native HMF-Audit query has unknown shape %q", entry.Shape)
		}
		if entry.Note != "" || entry.Returns != entry.Q || len(entry.TimeRange) != 2 ||
			entry.Region == "" || entry.Service == "" || entry.LogType == "" {
			return nil, fmt.Errorf("native HMF-Audit query %s/q=%d is malformed", entry.Shape, entry.Q)
		}
		start, err := time.Parse(time.RFC3339, entry.TimeRange[0])
		if err != nil {
			return nil, fmt.Errorf("native HMF-Audit query start: %w", err)
		}
		end, err := time.Parse(time.RFC3339, entry.TimeRange[1])
		if err != nil {
			return nil, fmt.Errorf("native HMF-Audit query end: %w", err)
		}
		tenant := entry.Tenant
		if strings.HasPrefix(tenant, "any") {
			tenant = "" // the all-tenant query
		}
		query := locator.LocatorQuery{TenantID: tenant, ServiceID: entry.Service, LogType: entry.LogType,
			RegionID: entry.Region, StartTime: start.UTC(), EndTime: end.UTC()}
		if _, _, err := query.Bounds(); err != nil {
			return nil, fmt.Errorf("native HMF-Audit query %s/q=%d: %w", entry.Shape, entry.Q, err)
		}
		key := [2]int{order, entry.Q}
		next[key]++
		queries = append(queries, fairHMFNativeQuery{Shape: entry.Shape, Q: entry.Q, Set: next[key], Query: query})
	}
	for _, shape := range fairNativeShapes {
		for _, q := range counts {
			if got := next[[2]int{shapeOrder[shape], q}]; got != fairNativeSets {
				return nil, fmt.Errorf("native HMF-Audit %s/q=%d has %d queries, want %d", shape, q, got, fairNativeSets)
			}
		}
	}
	sort.SliceStable(queries, func(i, j int) bool {
		a, b := queries[i], queries[j]
		if a.Shape != b.Shape {
			return shapeOrder[a.Shape] < shapeOrder[b.Shape]
		}
		if a.Q != b.Q {
			return a.Q < b.Q
		}
		return a.Set < b.Set
	})
	return queries, nil
}

// fairHMFAttributes holds every record's ALL key attributes, interned, in
// dataset order. Region comes from the layout (it equals the record's region).
type fairHMFAttributes struct {
	services, logTypes, tenants []string
	service, logType, tenant    []uint16
	eventTime                   []int64 // Unix seconds
}

type fairHMFAttributeRecord struct {
	RegionID  string `json:"region_id"`
	TenantID  string `json:"tenant_id"`
	ServiceID string `json:"service_id"`
	LogType   string `json:"log_type"`
	EventTime string `json:"event_time"`
}

func loadFairHMFAttributes(path string, layout *fairLayout) (*fairHMFAttributes, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	total := layout.total()
	attributes := &fairHMFAttributes{
		service: make([]uint16, 0, total), logType: make([]uint16, 0, total),
		tenant: make([]uint16, 0, total), eventTime: make([]int64, 0, total),
	}
	intern := func(names *[]string, index map[string]uint16, value string) (uint16, error) {
		if id, ok := index[value]; ok {
			return id, nil
		}
		if len(*names) >= 1<<16 {
			return 0, fmt.Errorf("more than 65536 distinct values")
		}
		id := uint16(len(*names))
		index[value] = id
		*names = append(*names, value)
		return id, nil
	}
	serviceIDs, typeIDs, tenantIDs := map[string]uint16{}, map[string]uint16{}, map[string]uint16{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		ordinal := len(attributes.eventTime)
		if ordinal >= total {
			return nil, fmt.Errorf("dataset has more than %d records", total)
		}
		var record fairHMFAttributeRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("decode record %d: %w", ordinal, err)
		}
		if record.RegionID != layout.address(ordinal).RegionID {
			return nil, fmt.Errorf("record %d is in %q, the layout places it in %q",
				ordinal, record.RegionID, layout.address(ordinal).RegionID)
		}
		when, err := time.Parse(time.RFC3339, record.EventTime)
		if err != nil {
			return nil, fmt.Errorf("record %d event_time: %w", ordinal, err)
		}
		service, err := intern(&attributes.services, serviceIDs, record.ServiceID)
		if err != nil {
			return nil, err
		}
		logType, err := intern(&attributes.logTypes, typeIDs, record.LogType)
		if err != nil {
			return nil, err
		}
		tenant, err := intern(&attributes.tenants, tenantIDs, record.TenantID)
		if err != nil {
			return nil, err
		}
		attributes.service = append(attributes.service, service)
		attributes.logType = append(attributes.logType, logType)
		attributes.tenant = append(attributes.tenant, tenant)
		attributes.eventTime = append(attributes.eventTime, when.Unix())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(attributes.eventTime) != total {
		return nil, fmt.Errorf("dataset has %d records, the layout %d", len(attributes.eventTime), total)
	}
	return attributes, nil
}

// key is record ordinal's ALL key, bound to its deterministic log ID.
func (attributes *fairHMFAttributes) key(layout *fairLayout, ordinal int) locator.LocatorKey {
	return locator.LocatorKey{
		LogID:     fairHMFUUID(ordinal),
		EventTime: time.Unix(attributes.eventTime[ordinal], 0).UTC(),
		RegionID:  layout.address(ordinal).RegionID,
		TenantID:  attributes.tenants[attributes.tenant[ordinal]],
		ServiceID: attributes.services[attributes.service[ordinal]],
		LogType:   attributes.logTypes[attributes.logType[ordinal]],
	}
}

// expected recounts a native query from the dataset attributes, independently
// of the ALL tree: rangeOrdinals is every record of (service, log type,
// region) with start <= time < end (all tenants), matched those of the
// query's tenant (all of them for the all-tenant query).
func (attributes *fairHMFAttributes) expected(layout *fairLayout, query locator.LocatorQuery) (rangeCount int, matched map[int]bool) {
	matched = map[int]bool{}
	start, end := query.StartTime.Unix(), query.EndTime.Unix()
	for ordinal := range attributes.eventTime {
		if attributes.services[attributes.service[ordinal]] != query.ServiceID ||
			attributes.logTypes[attributes.logType[ordinal]] != query.LogType ||
			attributes.eventTime[ordinal] < start || attributes.eventTime[ordinal] >= end ||
			layout.address(ordinal).RegionID != query.RegionID {
			continue
		}
		rangeCount++
		if query.TenantID == "" || attributes.tenants[attributes.tenant[ordinal]] == query.TenantID {
			matched[ordinal] = true
		}
	}
	return rangeCount, matched
}
