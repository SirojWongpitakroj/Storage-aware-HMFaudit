package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
	cassandrastore "github.com/SirojWongpitakroj/hmf-audit/internal/storage/cassandra"
	"github.com/SirojWongpitakroj/hmf-audit/internal/storage/postgresql"
	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"
)

type persistentFairHMFFixture struct {
	forest         *syntheticForest
	postgres       *pgxpool.Pool
	cassandra      *gocql.Session
	localizer      *localization.Service
	tampered       []hpp.PhysicalAddress
	trustedRoot    [32]byte
	hppConcurrency int
}

// TestMain closes the shared fixture's connections once every benchmark in
// the process has finished. A per-benchmark cleanup cannot do it: the fixture
// outlives the benchmark that happened to seed it.
func TestMain(m *testing.M) {
	code := m.Run()
	if fixture := fairHMFShared.fixture; fixture != nil {
		fixture.postgres.Close()
		fixture.cassandra.Close()
	}
	os.Exit(code)
}

// fairHMFShared holds the persisted HMF fixture for the whole test process.
// Hashing the dataset, building the forest and writing it to PostgreSQL and
// Cassandra is setup, not part of any measured request, so it runs once and
// is shared by both benchmark functions and by every -count repetition.
var fairHMFShared struct {
	once    sync.Once
	fixture *persistentFairHMFFixture
	err     error
}

func sharedFairHMFFixture(b *testing.B) *persistentFairHMFFixture {
	b.Helper()
	fairHMFShared.once.Do(func() {
		fairHMFShared.fixture, fairHMFShared.err = newPersistentFairHMFFixture(b)
	})
	if fairHMFShared.err != nil {
		b.Fatal(fairHMFShared.err)
	}
	return fairHMFShared.fixture
}

func newPersistentFairHMFFixture(b *testing.B) (*persistentFairHMFFixture, error) {
	b.Helper()
	if os.Getenv("FAIR_PERSISTENCE") != "1" {
		b.Fatal("FAIR_PERSISTENCE=1 is required; use systems/run-fair-benchmarks.ps1")
	}
	leaves, regionSizes := loadFairHMFLeaves(b)
	layout, err := newFairLayout(regionSizes,
		fairHMFLayoutSetting(b, "FAIR_HMF_SHARDS_PER_REGION", 1),
		fairHMFLayoutSetting(b, "FAIR_HMF_SEGMENT_LEAVES", 1<<13))
	if err != nil {
		b.Fatal(err)
	}
	forest, err := newFairForest(layout, leaves)
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	postgresDSN := os.Getenv("FAIR_POSTGRES_DSN")
	if postgresDSN == "" {
		b.Fatal("FAIR_POSTGRES_DSN is unset")
	}
	pool, err := postgresql.NewClient(ctx, postgresDSN)
	if err != nil {
		b.Fatalf("connect PostgreSQL: %v", err)
	}

	port, err := strconv.Atoi(os.Getenv("FAIR_CASSANDRA_PORT"))
	if err != nil || port <= 0 {
		b.Fatalf("invalid FAIR_CASSANDRA_PORT: %q", os.Getenv("FAIR_CASSANDRA_PORT"))
	}
	host := os.Getenv("FAIR_CASSANDRA_HOST")
	if host == "" {
		b.Fatal("FAIR_CASSANDRA_HOST is unset")
	}
	session, err := cassandrastore.NewSession(ctx, cassandrastore.Config{
		Hosts: []string{host}, Port: port, Keyspace: "hmf_audit", Datacenter: "datacenter1",
	})
	if err != nil {
		b.Fatalf("connect Cassandra: %v", err)
	}

	hppConcurrency := fairHMFLayoutSetting(b, "FAIR_HMF_HPP_CONCURRENCY", 8)
	fixture := &persistentFairHMFFixture{
		forest: forest, postgres: pool, cassandra: session, trustedRoot: forest.root,
		hppConcurrency: hppConcurrency,
	}
	if err := fixture.seed(ctx); err != nil {
		return nil, fmt.Errorf("seed persistent HMF fixture: %w", err)
	}
	reader, err := cassandrastore.NewHPPReader(session, hppConcurrency)
	if err != nil {
		b.Fatal(err)
	}
	service, err := hpp.NewService(reader, reader)
	if err != nil {
		b.Fatal(err)
	}
	fixture.forest.service = service
	fixture.localizer, err = localization.NewService(service)
	if err != nil {
		b.Fatal(err)
	}
	// Cassandra is now the only hierarchy/proof source used by requests.
	// Release the setup-only in-memory tree and metadata.
	fixture.forest.trees = nil
	fixture.forest.metadata = hpp.HierarchyMetadata{}
	return fixture, nil
}

func (fixture *persistentFairHMFFixture) seed(ctx context.Context) error {
	if _, err := fixture.postgres.Exec(ctx, "TRUNCATE TABLE hmf.encrypted_logs RESTART IDENTITY"); err != nil {
		return fmt.Errorf("truncate PostgreSQL logs: %w", err)
	}
	// Re-read the dataset and stream it into COPY: the benchmark keeps leaf
	// hashes, not the records themselves.
	if err := fixture.copyLogsFromDataset(ctx); err != nil {
		return err
	}

	for _, table := range []string{"merkle_segment_nodes", "hmf_segments_by_shard", "upper_merkle_nodes", "tree_state_by_id"} {
		if err := fixture.cassandra.Query("TRUNCATE " + table).ExecContext(ctx); err != nil {
			return fmt.Errorf("truncate Cassandra table %s: %w", table, err)
		}
	}
	segmentRepo := cassandrastore.NewSegmentRepo(fixture.cassandra)
	hmfRepo := cassandrastore.NewHMFRepo(fixture.cassandra)
	now := time.Now().UTC()
	// Segment trees are independent partitions; write them concurrently so
	// setup is not one round trip at a time.
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(16)
	for tree, data := range fixture.forest.trees {
		switch tree.Layer {
		case hpp.LayerSegment:
			group.Go(func() error {
				leafIndex := tree.SegmentID
				sealedAt := now
				root := data.root()
				if err := segmentRepo.UpsertSegment(groupCtx, cassandrastore.SegmentMetadata{
					RegionID: tree.RegionID, ShardID: tree.ShardID, SegmentID: tree.SegmentID,
					SegmentRoot: root[:], LeafCount: int64(len(data.levels[0])),
					ShardLeafIndex: &leafIndex, MaxLeaves: int32(len(data.levels[0])),
					Sealed: true, CreatedAt: now, SealedAt: &sealedAt,
				}); err != nil {
					return err
				}
				nodes := make([]cassandrastore.SegmentNode, 0, 128)
				flush := func() error {
					if len(nodes) == 0 {
						return nil
					}
					if err := segmentRepo.UpsertNodes(groupCtx, nodes); err != nil {
						return err
					}
					nodes = nodes[:0]
					return nil
				}
				for level, hashes := range data.levels {
					for index, hash := range hashes {
						nodes = append(nodes, cassandrastore.SegmentNode{
							RegionID: tree.RegionID, ShardID: tree.ShardID, SegmentID: tree.SegmentID,
							Level: int32(level), NodeIndex: int64(index), NodeHash: append([]byte(nil), hash[:]...),
						})
						if len(nodes) == cap(nodes) {
							if err := flush(); err != nil {
								return err
							}
						}
					}
				}
				return flush()
			})
		case hpp.LayerShard, hpp.LayerRegion, hpp.LayerGlobal:
			scopeType, scopeID, treeID, treeType, parentIndex := fairHMFUpperIdentity(tree)
			var nodes []cassandrastore.HMFNode
			for level, hashes := range data.levels {
				for index, hash := range hashes {
					nodes = append(nodes, cassandrastore.HMFNode{
						ScopeType: scopeType, ScopeID: scopeID, Level: int32(level),
						NodeIndex: int64(index), NodeHash: append([]byte(nil), hash[:]...),
					})
				}
			}
			if err := hmfRepo.UpsertNodes(ctx, nodes); err != nil {
				return err
			}
			root := data.root()
			if err := hmfRepo.UpsertTreeState(ctx, cassandrastore.HMFTreeState{
				TreeID: treeID, TreeType: treeType, CurrentRoot: root[:],
				LeafCount: int64(len(data.levels[0])), TreeHeight: int32(len(data.levels) - 1),
				ParentLeafIndex: parentIndex, UpdatedAt: now,
			}); err != nil {
				return err
			}
		}
	}
	return group.Wait()
}

// copyLogsFromDataset streams the shared dataset into hmf.encrypted_logs in
// dataset order, giving record `ordinal` the deterministic ID
// fairHMFUUID(ordinal) that requests derive from a physical address.
func (fixture *persistentFairHMFFixture) copyLogsFromDataset(ctx context.Context) error {
	file, err := os.Open(os.Getenv("FAIR_DATASET_PATH"))
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	ordinal := 0
	_, err = fixture.postgres.CopyFrom(ctx, pgx.Identifier{"hmf", "encrypted_logs"},
		[]string{"log_id", "ciphertext", "nonce", "auth_tag", "associated_data"},
		pgx.CopyFromFunc(func() ([]any, error) {
			if !scanner.Scan() {
				return nil, scanner.Err()
			}
			var record fairHMFRecord
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				return nil, fmt.Errorf("decode shared dataset record %d: %w", ordinal, err)
			}
			row := []any{fairHMFUUID(ordinal), []byte(record.RawLog),
				[]byte{0}, []byte{0}, []byte(record.SourceID)}
			ordinal++
			return row, nil
		}))
	if err != nil {
		return fmt.Errorf("copy PostgreSQL logs: %w", err)
	}
	if ordinal != fixture.forest.layout.total() {
		return fmt.Errorf("copied %d logs, want %d", ordinal, fixture.forest.layout.total())
	}
	return nil
}

func (fixture *persistentFairHMFFixture) verify(ctx context.Context,
	addresses []hpp.PhysicalAddress) (hpp.VerificationResult, error) {
	proof, err := fixture.proofWithCurrentLogs(ctx, addresses)
	if err != nil {
		return hpp.VerificationResult{}, err
	}
	root, err := hpp.VerifyHMFProofAgainstRoot(proof, addresses, fixture.trustedRoot)
	if err != nil {
		return hpp.VerificationResult{}, err
	}
	return hpp.VerificationResult{CalculatedGlobalRoot: root, Proof: proof}, nil
}

// proofWithCurrentLogs is the auditor's evidence acquisition. It reads the
// requested encrypted logs from PostgreSQL while the HMF proof is built from
// Cassandra (the two reads are independent), then binds the proof to the
// current log hashes.
func (fixture *persistentFairHMFFixture) proofWithCurrentLogs(ctx context.Context,
	addresses []hpp.PhysicalAddress) (hpp.HMFProof, error) {
	type logResult struct {
		hashes map[hpp.PhysicalAddress][32]byte
		err    error
	}
	logs := make(chan logResult, 1)
	go func() {
		hashes, err := fixture.currentLogHashes(ctx, addresses)
		logs <- logResult{hashes: hashes, err: err}
	}()
	proof, proofErr := fixture.forest.service.BuildProof(ctx, addresses)
	current := <-logs
	if current.err != nil {
		return hpp.HMFProof{}, current.err
	}
	if proofErr != nil {
		return hpp.HMFProof{}, proofErr
	}
	for index := range proof.Leaves {
		proof.Leaves[index].Hash = current.hashes[proof.Leaves[index].Address]
	}
	return proof, nil
}

func (fixture *persistentFairHMFFixture) currentLogHashes(ctx context.Context,
	addresses []hpp.PhysicalAddress) (map[hpp.PhysicalAddress][32]byte, error) {
	ids := make([]uuid.UUID, len(addresses))
	addressByID := make(map[uuid.UUID]hpp.PhysicalAddress, len(addresses))
	for index, address := range addresses {
		id, err := fixture.logID(address)
		if err != nil {
			return nil, err
		}
		ids[index] = id
		addressByID[id] = address
	}
	rows, err := fixture.postgres.Query(ctx,
		"SELECT log_id, ciphertext FROM hmf.encrypted_logs WHERE log_id = ANY($1)", ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hashes := make(map[hpp.PhysicalAddress][32]byte, len(addresses))
	for rows.Next() {
		var id uuid.UUID
		var ciphertext []byte
		if err := rows.Scan(&id, &ciphertext); err != nil {
			return nil, err
		}
		hashes[addressByID[id]] = sha256.Sum256(ciphertext)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(hashes) != len(addresses) {
		return nil, fmt.Errorf("PostgreSQL returned %d of %d requested logs", len(hashes), len(addresses))
	}
	return hashes, nil
}

func (fixture *persistentFairHMFFixture) setTampered(ctx context.Context,
	address hpp.PhysicalAddress) error {
	return fixture.setTamperedMany(ctx, []hpp.PhysicalAddress{address})
}

func (fixture *persistentFairHMFFixture) setTamperedMany(ctx context.Context,
	addresses []hpp.PhysicalAddress) error {
	if err := fixture.clearTamper(ctx); err != nil {
		return err
	}
	flipped := make([]hpp.PhysicalAddress, 0, len(addresses))
	for _, address := range addresses {
		if err := fixture.togglePersistedCiphertext(ctx, address); err != nil {
			for index := len(flipped) - 1; index >= 0; index-- {
				_ = fixture.togglePersistedCiphertext(ctx, flipped[index])
			}
			return err
		}
		flipped = append(flipped, address)
	}
	fixture.tampered = append([]hpp.PhysicalAddress(nil), flipped...)
	return nil
}

// logID is the PostgreSQL ID of the record at address, derived from its
// dataset ordinal rather than a per-record map.
func (fixture *persistentFairHMFFixture) logID(address hpp.PhysicalAddress) (uuid.UUID, error) {
	ordinal, ok := fixture.forest.layout.ordinal(address)
	if !ok {
		return uuid.UUID{}, fmt.Errorf("no PostgreSQL log ID for address %+v", address)
	}
	return fairHMFUUID(ordinal), nil
}

func (fixture *persistentFairHMFFixture) togglePersistedCiphertext(ctx context.Context,
	address hpp.PhysicalAddress) error {
	id, err := fixture.logID(address)
	if err != nil {
		return err
	}
	var ciphertext []byte
	if err = fixture.postgres.QueryRow(ctx,
		"SELECT ciphertext FROM hmf.encrypted_logs WHERE log_id = $1", id).Scan(&ciphertext); err != nil {
		return err
	}
	if len(ciphertext) == 0 {
		return fmt.Errorf("empty persisted ciphertext for address %+v", address)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	_, err = fixture.postgres.Exec(ctx,
		"UPDATE hmf.encrypted_logs SET ciphertext = $1 WHERE log_id = $2", ciphertext, id)
	return err
}

// clearTamper restores the honest ciphertext, so a later benchmark function
// in this process starts from storage that matches the anchored root.
func (fixture *persistentFairHMFFixture) clearTamper(ctx context.Context) error {
	for index := len(fixture.tampered) - 1; index >= 0; index-- {
		if err := fixture.togglePersistedCiphertext(ctx, fixture.tampered[index]); err != nil {
			fixture.tampered = fixture.tampered[:index+1]
			return err
		}
	}
	fixture.tampered = nil
	return nil
}

func (fixture *persistentFairHMFFixture) localize(ctx context.Context,
	addresses []hpp.PhysicalAddress) (localization.Result, error) {
	proof, auditorRoot, err := fixture.currentProof(ctx, addresses)
	if err != nil {
		return localization.Result{}, err
	}
	if auditorRoot == fixture.trustedRoot {
		return localization.Result{}, fmt.Errorf("persisted tamper did not change the HMF root")
	}
	return fixture.localizer.Localize(ctx, localization.Request{
		Addresses: addresses, AuditorGlobalRoot: auditorRoot, FailedProof: proof,
		AnchoredGlobalRoot: fixture.trustedRoot, K: localization.DefaultJumpLevels,
	})
}

func (fixture *persistentFairHMFFixture) currentProof(ctx context.Context,
	addresses []hpp.PhysicalAddress) (hpp.HMFProof, [32]byte, error) {
	proof, err := fixture.proofWithCurrentLogs(ctx, addresses)
	if err != nil {
		return hpp.HMFProof{}, [32]byte{}, err
	}
	root, err := hpp.VerifyHMFProof(proof, addresses)
	return proof, root, err
}

// fairHMFLayoutSetting reads a positive layout setting from the environment
// (set by the shared runner), falling back to the v4/v5 layout: one shard per
// region and 4,096-leaf segments.
func fairHMFLayoutSetting(b testing.TB, name string, fallback int) int {
	b.Helper()
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		b.Fatalf("invalid %s %q", name, value)
	}
	return parsed
}

// loadFairHMFLeaves reads the shared region-grouped dataset (R0, R1, ... in
// order, regions of any size) and returns the records' leaf hashes and each
// region's record count. The records themselves are not kept: seeding
// re-reads the file and streams it into PostgreSQL.
func loadFairHMFLeaves(b testing.TB) ([][32]byte, []int) {
	b.Helper()
	path := os.Getenv("FAIR_DATASET_PATH")
	if path == "" {
		b.Fatal("FAIR_DATASET_PATH is unset; run the shared benchmark runner")
	}
	file, err := os.Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()
	var leaves [][32]byte
	var regionSizes []int
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		var record fairHMFRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			b.Fatalf("decode shared dataset record %d: %v", len(leaves), err)
		}
		if record.RawLog == "" || record.SourceID == "" || record.TenantID == "" {
			b.Fatalf("invalid shared dataset record %d", len(leaves))
		}
		if record.RegionID != fmt.Sprintf("R%d", len(regionSizes)-1) {
			if record.RegionID != fmt.Sprintf("R%d", len(regionSizes)) {
				b.Fatalf("shared dataset record %d has region %q; records must be grouped R0, R1, ... in order",
					len(leaves), record.RegionID)
			}
			regionSizes = append(regionSizes, 0)
		}
		regionSizes[len(regionSizes)-1]++
		leaves = append(leaves, sha256.Sum256([]byte(record.RawLog)))
	}
	if err := scanner.Err(); err != nil {
		b.Fatal(err)
	}
	if len(leaves) == 0 {
		b.Fatal("shared dataset is empty")
	}
	return leaves, regionSizes
}

func fairHMFUUID(ordinal int) uuid.UUID {
	var id uuid.UUID
	copy(id[:8], []byte("HMF-FAIR"))
	binary.BigEndian.PutUint64(id[8:], uint64(ordinal+1))
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id
}

func fairHMFUpperIdentity(tree hpp.TreeRef) (scopeType, scopeID, treeID, treeType string,
	parentIndex *int64) {
	switch tree.Layer {
	case hpp.LayerShard:
		index := tree.ShardID
		return "SHARD", fmt.Sprintf("%s:S%d", tree.RegionID, tree.ShardID),
			fmt.Sprintf("SHARD:%s:S%d", tree.RegionID, tree.ShardID), "SHARD", &index
	case hpp.LayerRegion:
		regionIndex, _ := strconv.ParseInt(tree.RegionID[1:], 10, 64)
		return "REGION", tree.RegionID, "REGION:" + tree.RegionID, "REGION", &regionIndex
	default:
		return "GLOBAL", "GLOBAL", "GLOBAL", "GLOBAL", nil
	}
}
