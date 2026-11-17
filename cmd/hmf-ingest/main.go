// Command hmf-ingest loads a log dataset through the real HMF-Audit write path
// so that the logs can be queried by attribute and audited.
//
// For every record it seals the log (AES-256-GCM), stores the ciphertext row in
// PostgreSQL, submits the log's digest to the hierarchy manager (which places
// it in a segment, shard, region and the global tree) and records the
// attributes -> physical address mapping in the Authenticated Log Locator
// (ALL). It then publishes the hierarchy and locator state to Cassandra and
// finalizes one checkpoint that binds the locator root and the global root.
//
// It accepts exactly two dataset sizes (100,000 and 10,000,000 records) and
// only a local database.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
	"uuid"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
	"github.com/SirojWongpitakroj/hmf-audit/internal/auditlog"
	"github.com/SirojWongpitakroj/hmf-audit/internal/checkpoint"
	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hm"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
	cassandrastore "github.com/SirojWongpitakroj/hmf-audit/internal/storage/cassandra"
	"github.com/SirojWongpitakroj/hmf-audit/internal/storage/postgresql"
	"github.com/jackc/pgx/v5"
)

const (
	locatorOrder          = 128
	locatorPagesPerBucket = 512
	copyBatchRows         = 5000
)

var allowedRecordCounts = map[int]bool{100_000: true, 10_000_000: true}

var cassandraTables = []string{
	"all_pages", "all_tree_state", "merkle_segment_nodes", "hmf_segments_by_shard",
	"shard_tree_frontiers", "upper_merkle_nodes", "tree_state_by_id", "checkpoint_roots", "finality_state",
}

type record struct {
	LogID     string `json:"logID"`
	RawLog    string `json:"raw_log"`
	RegionID  string `json:"region_id"`
	TenantID  string `json:"tenant_id"`
	ServiceID string `json:"service_id"`
	LogType   string `json:"log_type"`
	EventTime string `json:"event_time"`
}

func (r record) log() (domain.Log, error) {
	id, err := uuid.Parse(r.LogID)
	if err != nil {
		return domain.Log{}, fmt.Errorf("logID %q: %w", r.LogID, err)
	}
	when, err := time.Parse(time.RFC3339, r.EventTime)
	if err != nil {
		return domain.Log{}, fmt.Errorf("event_time %q: %w", r.EventTime, err)
	}
	if r.RegionID == "" || r.TenantID == "" || r.ServiceID == "" || r.LogType == "" {
		return domain.Log{}, fmt.Errorf("record %s: region_id, tenant_id, service_id and log_type are required", r.LogID)
	}
	return domain.Log{LogID: id, EventTime: when.UTC(), RegionID: r.RegionID,
		TenantID: r.TenantID, ServiceID: r.ServiceID, LogType: r.LogType}, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	dataset := flag.String("dataset", "", "JSONL dataset (exactly 100000 or 10000000 records)")
	postgresDSN := flag.String("postgres-dsn", "postgres://fair:fairdev@127.0.0.1:55432/fair_benchmark?sslmode=disable&search_path=hmfq",
		"local PostgreSQL URL; its search_path must select the schema holding encrypted_logs")
	host := flag.String("cassandra-host", "127.0.0.1", "local Cassandra host")
	port := flag.Int("cassandra-port", 19042, "Cassandra port")
	keyspace := flag.String("keyspace", "hmf_audit_q", "Cassandra keyspace")
	keyFile := flag.String("key-file", "", "AES-256 key file (created if missing)")
	systemID := flag.String("system-id", "hmf-audit-q", "checkpoint system ID")
	segmentLeaves := flag.Int("segment-leaves", 8192, "leaves per segment")
	reset := flag.Bool("reset", false, "empty this tool's PostgreSQL table and Cassandra keyspace first")
	flag.Parse()

	if *dataset == "" || *keyFile == "" {
		return fmt.Errorf("-dataset and -key-file are required")
	}
	if err := auditlog.RequireLoopbackHost(*host); err != nil {
		return err
	}
	if err := auditlog.RequireLoopbackDSN(*postgresDSN); err != nil {
		return err
	}

	// Pass 1: validate the dataset, enforce the two allowed sizes, learn the regions.
	regions, regionCounts, total, err := scanDataset(*dataset)
	if err != nil {
		return err
	}
	if !allowedRecordCounts[total] {
		return fmt.Errorf("rejected: dataset has %d records; only 100000 (100k) and 10000000 (10 million) are allowed", total)
	}
	fmt.Fprintf(os.Stderr, "dataset ok: %d records in regions %v\n", total, regions)

	key, created, err := loadOrCreateKey(*keyFile)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(os.Stderr, "created encryption key %s (keep it private; never commit it)\n", *keyFile)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
	defer cancel()
	pool, err := postgresql.NewClient(ctx, *postgresDSN)
	if err != nil {
		return fmt.Errorf("connect PostgreSQL: %w", err)
	}
	defer pool.Close()
	session, err := cassandrastore.NewSession(ctx, cassandrastore.Config{
		Hosts: []string{*host}, Port: *port, Keyspace: *keyspace, Datacenter: "datacenter1",
	})
	if err != nil {
		return fmt.Errorf("connect Cassandra keyspace %s: %w", *keyspace, err)
	}
	defer session.Close()

	if *reset {
		if _, err := pool.Exec(ctx, "TRUNCATE TABLE encrypted_logs RESTART IDENTITY"); err != nil {
			return fmt.Errorf("reset PostgreSQL: %w", err)
		}
		for _, table := range cassandraTables {
			if err := session.Query("TRUNCATE " + table).ExecContext(ctx); err != nil {
				return fmt.Errorf("reset Cassandra table %s: %w", table, err)
			}
		}
	}
	var existing int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM encrypted_logs").Scan(&existing); err != nil {
		return fmt.Errorf("count stored logs: %w", err)
	}
	if existing != 0 {
		return fmt.Errorf("encrypted_logs already holds %d rows; rerun with -reset to replace them", existing)
	}

	forest, err := hmf.NewHMF(hmf.HMFConfig{RegionIDs: regions, NumShardsPerRegion: 1, MaxSegmentLeaves: *segmentLeaves})
	if err != nil {
		return err
	}
	manager, err := hm.NewManager(forest, *segmentLeaves, 24*time.Hour)
	if err != nil {
		return err
	}
	locatorService, err := locator.NewALL(locatorOrder, locatorPagesPerBucket)
	if err != nil {
		return err
	}
	manager.SetALL(locatorService)
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	go locatorService.Run(runCtx)

	// ALL emits one update per insert; the final tree is persisted as one
	// snapshot, so the per-insert updates are only counted.
	var locatorUpdates atomic.Int64
	go func() {
		for range locatorService.Updates() {
			locatorUpdates.Add(1)
		}
	}()
	// Sealed segments are persisted as the hierarchy produces them.
	expectedSegments := 0
	for _, count := range regionCounts {
		expectedSegments += (count + *segmentLeaves - 1) / *segmentLeaves
	}
	var segmentsPersisted atomic.Int64
	persistErrors := make(chan error, 1)
	hmfWriter := cassandrastore.NewHMFUpdateWriter(session)
	go func() {
		for update := range manager.Updates() {
			if err := hmfWriter.PersistSealedUpdate(ctx, update); err != nil {
				select {
				case persistErrors <- fmt.Errorf("persist sealed segment: %w", err):
				default:
				}
				return
			}
			segmentsPersisted.Add(1)
		}
	}()

	// Pass 2: seal, store, and submit every log.
	started := time.Now()
	if err := ingest(ctx, *dataset, key, manager, pool, total, persistErrors); err != nil {
		return err
	}
	for _, region := range regions {
		if err := manager.StopWorker(ctx, region, 0); err != nil {
			return fmt.Errorf("stop worker %s: %w", region, err)
		}
	}
	if err := waitFor(ctx, persistErrors, "locator updates", func() bool { return locatorUpdates.Load() >= int64(total) }); err != nil {
		return err
	}
	if err := waitFor(ctx, persistErrors, "sealed segments", func() bool { return segmentsPersisted.Load() >= int64(expectedSegments) }); err != nil {
		return err
	}
	if err := locatorService.Stop(ctx); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "ingested %d logs, %d segments in %s; persisting the locator tree\n",
		total, expectedSegments, time.Since(started).Round(time.Second))

	locatorWriter, err := cassandrastore.NewALLUpdateWriter(session, locator.LocatorTreeID, locatorOrder, locatorPagesPerBucket)
	if err != nil {
		return err
	}
	if err := locatorWriter.PersistSnapshot(ctx, locatorService.LocatorTree); err != nil {
		return fmt.Errorf("persist locator tree: %w", err)
	}

	store, err := cassandrastore.NewCheckpointStore(session, locator.LocatorTreeID)
	if err != nil {
		return err
	}
	service, err := checkpoint.NewService(*systemID, rootSource{locator: locatorService, forest: forest},
		checkpoint.NewMockAnchor(0), store)
	if err != nil {
		return err
	}
	final, err := service.Finalize(ctx)
	if err != nil {
		return fmt.Errorf("finalize checkpoint: %w", err)
	}
	fmt.Printf("checkpoint %d finalized for system %q\n", final.Sequence, final.SystemID)
	fmt.Printf("  locator root R_L: %s\n  global root  R_G: %s\n  commitment   C:   %s\n",
		hex.EncodeToString(final.LocatorRoot[:]), hex.EncodeToString(final.GlobalHMFRoot[:]),
		hex.EncodeToString(final.StateCommitment[:]))
	return nil
}

// rootSource snapshots the locator and global roots together, after ingestion
// has stopped, so the checkpoint binds one coordinated state.
type rootSource struct {
	locator *locator.ALL
	forest  *hmf.HMF
}

func (source rootSource) Snapshot(context.Context) (checkpoint.RootSnapshot, error) {
	return checkpoint.RootSnapshot{
		LocatorTreeID: locator.LocatorTreeID,
		LocatorRoot:   source.locator.LocatorTree.RootHash,
		GlobalHMFRoot: source.forest.Root(),
	}, nil
}

func ingest(ctx context.Context, path string, key []byte, manager *hm.Manager, pool interface {
	CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error)
}, total int, persistErrors <-chan error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)

	rows := make([][]any, 0, copyBatchRows)
	flush := func() error {
		if len(rows) == 0 {
			return nil
		}
		_, err := pool.CopyFrom(ctx, pgx.Identifier{"encrypted_logs"},
			[]string{"log_id", "ciphertext", "nonce", "auth_tag", "associated_data"}, pgx.CopyFromRows(rows))
		rows = rows[:0]
		return err
	}
	for count := 0; scanner.Scan(); count++ {
		select {
		case err := <-persistErrors:
			return err
		default:
		}
		var input record
		if err := json.Unmarshal(scanner.Bytes(), &input); err != nil {
			return fmt.Errorf("record %d: %w", count, err)
		}
		entry, err := input.log()
		if err != nil {
			return fmt.Errorf("record %d: %w", count, err)
		}
		entry.AD = domain.EncodeAD(&entry)
		entry.Ciphertext, entry.Tag, entry.Nonce, err = auditlog.Seal(key, []byte(input.RawLog), entry.AD)
		if err != nil {
			return err
		}
		entry.Digest = auditlog.Digest(entry.Ciphertext, entry.Tag, entry.Nonce, entry.AD)
		if err := manager.SubmitLog(ctx, 0, entry); err != nil {
			return fmt.Errorf("record %d: %w", count, err)
		}
		rows = append(rows, []any{entry.LogID, entry.Ciphertext, entry.Nonce, entry.Tag, entry.AD})
		if len(rows) == copyBatchRows {
			if err := flush(); err != nil {
				return fmt.Errorf("store logs: %w", err)
			}
		}
		if (count+1)%10000 == 0 {
			fmt.Fprintf(os.Stderr, "  %d / %d logs\n", count+1, total)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := flush(); err != nil {
		return fmt.Errorf("store logs: %w", err)
	}
	return nil
}

func waitFor(ctx context.Context, failures <-chan error, what string, done func() bool) error {
	deadline := time.Now().Add(30 * time.Minute)
	for !done() {
		select {
		case err := <-failures:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s", what)
		}
	}
	return nil
}

// scanDataset counts the records and the records per region (in order of first
// appearance) and checks that every line has the attributes the locator needs.
func scanDataset(path string) (regions []string, counts map[string]int, total int, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, err
	}
	defer file.Close()
	counts = map[string]int{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		var input record
		if err := json.Unmarshal(scanner.Bytes(), &input); err != nil {
			return nil, nil, 0, fmt.Errorf("record %d: %w", total, err)
		}
		if _, err := input.log(); err != nil {
			return nil, nil, 0, fmt.Errorf("record %d: %w", total, err)
		}
		if counts[input.RegionID] == 0 {
			regions = append(regions, input.RegionID)
		}
		counts[input.RegionID]++
		total++
	}
	return regions, counts, total, scanner.Err()
}

func loadOrCreateKey(path string) (key []byte, created bool, err error) {
	if data, err := os.ReadFile(path); err == nil {
		decoded, err := hex.DecodeString(string(trimSpace(data)))
		if err != nil || len(decoded) != auditlog.KeySize {
			return nil, false, fmt.Errorf("key file %s is not a %d-byte hex key", path, auditlog.KeySize)
		}
		return decoded, false, nil
	} else if !os.IsNotExist(err) {
		return nil, false, err
	}
	key = make([]byte, auditlog.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

func trimSpace(data []byte) []byte {
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r' || data[len(data)-1] == ' ') {
		data = data[:len(data)-1]
	}
	return data
}
