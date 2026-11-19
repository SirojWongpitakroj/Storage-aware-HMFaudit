package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	cassandrastore "github.com/SirojWongpitakroj/hmf-audit/internal/storage/cassandra"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fairCloudDemoRecord is the part of a dataset line the cloud demo selects on.
type fairCloudDemoRecord struct {
	RegionID  string `json:"region_id"`
	TenantID  string `json:"tenant_id"`
	ServiceID string `json:"service_id"`
	LogType   string `json:"log_type"`
	EventTime string `json:"event_time"`
}

// TestCloudDemoVerification reads the existing fair fixture. The source digest
// pins the attributes and the leaves used to rebuild the independent HMF root.
func TestCloudDemoVerification(t *testing.T) {
	if os.Getenv("DEMO_CLOUD_VERIFY") != "1" {
		t.Skip("run from the cloud dashboard")
	}
	emit := func(kind string, fields map[string]any) {
		fields["type"], fields["scheme"] = kind, "HMF-Audit"
		payload, _ := json.Marshal(fields)
		fmt.Printf("DEMO_EVENT %s\n", payload)
	}
	start, startErr := time.Parse(time.RFC3339Nano, os.Getenv("DEMO_QUERY_START"))
	end, endErr := time.Parse(time.RFC3339Nano, os.Getenv("DEMO_QUERY_END"))
	repeats, repeatErr := strconv.Atoi(os.Getenv("DEMO_QUERY_REPEATS"))
	if startErr != nil || endErr != nil || !start.Before(end) || repeatErr != nil || repeats < 1 || repeats > 20 {
		t.Fatal("invalid time range or repeat count")
	}
	service, logType, region, tenant := os.Getenv("DEMO_QUERY_SERVICE"), os.Getenv("DEMO_QUERY_TYPE"), os.Getenv("DEMO_QUERY_REGION"), os.Getenv("DEMO_QUERY_TENANT")
	emit("scheme", map[string]any{"message": "Selecting matching records and rebuilding the HMF root from the pinned source"})
	sizes := []int{2500000, 2500000, 2500000, 2500000}
	layout, err := newFairLayout(sizes, 1, 8192)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(os.Getenv("FAIR_DATASET_PATH"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	digest := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(source, digest))
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	leaves := make([][32]byte, 0, layout.total())
	var matches []hpp.PhysicalAddress
	ordinals := make([]int, 0)
	for scanner.Scan() {
		ordinal := len(leaves)
		if ordinal >= layout.total() {
			t.Fatal("source has more than 10 million records")
		}
		var record struct {
			fairCloudDemoRecord
			RawLog string `json:"raw_log"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("decode source record %d: %v", ordinal, err)
		}
		leaves = append(leaves, sha256.Sum256([]byte(record.RawLog)))
		if record.RegionID != region || record.ServiceID != service || record.LogType != logType ||
			(tenant != "*" && tenant != record.TenantID) {
			continue
		}
		when, err := time.Parse(time.RFC3339Nano, record.EventTime)
		if err != nil {
			t.Fatalf("source record %d event time: %v", ordinal, err)
		}
		if !when.Before(start) && when.Before(end) {
			matches = append(matches, layout.address(ordinal))
			ordinals = append(ordinals, ordinal)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(leaves) != layout.total() || hex.EncodeToString(digest.Sum(nil)) != "a8fa53db3327ce5b21cc61b249276817d81b2ee29a6facf64f48619d215dba82" {
		t.Fatal("the source does not match the pinned 10-million-record cloud ingest")
	}
	if path := os.Getenv("DEMO_BATCH_OUT"); path != "" {
		payload, err := json.Marshal(ordinals)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	emit("batch", map[string]any{"count": len(matches), "message": fmt.Sprintf("%d matching records in the pinned Spark source", len(matches))})
	if len(matches) == 0 {
		emit("result", map[string]any{"status": "VALID", "message": "No matching records in the pinned Spark source"})
		return
	}

	forest, err := newFairForest(layout, leaves)
	if err != nil {
		t.Fatal(err)
	}
	forest.trees, forest.metadata = nil, hpp.HierarchyMetadata{}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(os.Getenv("FAIR_POSTGRES_DSN"))
	if err != nil {
		t.Fatal("invalid cloud PostgreSQL configuration")
	}
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("cannot open cloud PostgreSQL connection")
	}
	defer pool.Close()
	port, err := strconv.Atoi(os.Getenv("FAIR_CASSANDRA_PORT"))
	if err != nil {
		t.Fatal("invalid cloud Cassandra port")
	}
	session, err := cassandrastore.NewSession(ctx, cassandrastore.Config{
		Hosts: []string{os.Getenv("FAIR_CASSANDRA_HOST")}, Port: port,
		Keyspace: "hmf_audit", Datacenter: "datacenter1",
	})
	if err != nil {
		t.Fatalf("connect cloud Cassandra: %v", err)
	}
	defer session.Close()
	reader, err := cassandrastore.NewHPPReader(session, 8)
	if err != nil {
		t.Fatal(err)
	}
	forest.service, err = hpp.NewService(reader, reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &persistentFairHMFFixture{forest: forest, postgres: pool, trustedRoot: forest.root}
	timings := make([]float64, 0, repeats)
	for run := 0; run <= repeats; run++ {
		message := "Verifying matching cloud records (warm-up)"
		if run > 0 {
			message = fmt.Sprintf("Timed run %d/%d", run, repeats)
		}
		emit("trial", map[string]any{"current": run, "total": repeats, "message": message})
		started := time.Now()
		for batch := range slices.Chunk(matches, 1024) {
			if _, err := fixture.verify(ctx, batch); err != nil {
				t.Fatalf("cloud proof verification failed: %v", err)
			}
		}
		if run > 0 {
			timings = append(timings, float64(time.Since(started))/float64(time.Millisecond))
		}
	}
	slices.Sort(timings)
	median := (timings[(repeats-1)/2] + timings[repeats/2]) / 2
	emit("result", map[string]any{"status": "VALID", "milliseconds": median,
		"message": fmt.Sprintf("Verified %d cloud records against the source-derived HMF root", len(matches))})
}
