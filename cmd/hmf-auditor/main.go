// Command hmf-auditor is an auditor-side client for HMF-Audit. Given the five
// locator attributes (tenant, service, log type, region and a time range) it
// finds the matching logs, verifies them, and reports every log as VALID or
// REJECTED.
//
// Steps:
//  1. Read the current finalized checkpoint (trusted locator root R_L and
//     global root R_G).
//  2. Resolve the attribute query through the Authenticated Log Locator and
//     verify its range proof against R_L. The proof also shows that no
//     matching log was left out.
//  3. For the authenticated addresses, rebuild each log's digest from what
//     PostgreSQL stores now, build the HMF proof from Cassandra, and check
//     that the reconstructed root equals R_G. If a group fails, it is split
//     until the rejected logs are isolated.
//
// A log is VALID only if its stored row hashes to the leaf committed under the
// anchored root and its stored attributes match the locator entry. It talks to
// the local database only.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
	"github.com/SirojWongpitakroj/hmf-audit/internal/auditlog"
	"github.com/SirojWongpitakroj/hmf-audit/internal/checkpoint"
	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	"github.com/SirojWongpitakroj/hmf-audit/internal/localization"
	cassandrastore "github.com/SirojWongpitakroj/hmf-audit/internal/storage/cassandra"
	"github.com/SirojWongpitakroj/hmf-audit/internal/storage/postgresql"
)

type verdict struct {
	LogID     string `json:"log_id"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	TenantID  string `json:"tenant_id"`
	ServiceID string `json:"service_id"`
	LogType   string `json:"log_type"`
	RegionID  string `json:"region_id"`
	Time      string `json:"event_time"`
	Shard     int64  `json:"shard"`
	Segment   int64  `json:"segment"`
	Leaf      int64  `json:"leaf"`
	RawLog    string `json:"raw_log,omitempty"`

	// For REJECTED logs only: the digest the hierarchy committed for this log
	// (what it should be), the digest of the row stored now, and, when a key is
	// given, the stored row decrypted WITHOUT authentication (hex). The last is
	// only for showing what a failed log contains; it is not trustworthy.
	CommittedDigest  string `json:"committed_digest,omitempty"`
	StoredDigest     string `json:"stored_digest,omitempty"`
	StoredContentHex string `json:"stored_content_hex,omitempty"`
}

type candidate struct {
	entry   locator.LocatorEntry
	address hpp.PhysicalAddress
	digest  [32]byte
	// committed is the leaf the hierarchy holds for this log (from Cassandra).
	committed    [32]byte
	hasCommitted bool
	// failure is set when the log cannot even take part in the proof.
	failure string
	sealed  storedRow
}

type storedRow struct{ ciphertext, nonce, tag, ad []byte }

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

func run() (int, error) {
	tenant := flag.String("tenant", "", "tenant_id (required)")
	service := flag.String("service", "", "service_id (required)")
	logType := flag.String("log-type", "", "log_type (required)")
	region := flag.String("region", "", "region_id (required)")
	start := flag.String("start", "", "range start, RFC 3339 (inclusive)")
	end := flag.String("end", "", "range end, RFC 3339 (exclusive)")
	at := flag.String("at", "", "one instant, RFC 3339: shorthand for [at, at+1s)")
	postgresDSN := flag.String("postgres-dsn", "postgres://fair:fairdev@127.0.0.1:55432/fair_benchmark?sslmode=disable&search_path=hmfq", "local PostgreSQL URL")
	host := flag.String("cassandra-host", "127.0.0.1", "local Cassandra host")
	port := flag.Int("cassandra-port", 19042, "Cassandra port")
	keyspace := flag.String("keyspace", "hmf_audit_q", "Cassandra keyspace")
	systemID := flag.String("system-id", "hmf-audit-q", "checkpoint system ID")
	keyFile := flag.String("key-file", "", "AES-256 key file; with it, VALID logs are shown decrypted")
	limit := flag.Int("limit", 20, "rows to print in table mode (the summary always counts all)")
	asJSON := flag.Bool("json", false, "print every log as one JSON line")
	repeats := flag.Int("repeats", 0, "after the normal run (the warm-up), repeat steps 2-3 silently this many times and print the median time; connection set-up is not timed")
	reuseLocator := flag.Bool("reuse-locator", false, "reuse the initial authenticated locator result in timed runs and print verification progress")
	localize := flag.Bool("localize", false, "detect and localize failed proofs with the HMF localization service")
	flag.Parse()
	if *localize {
		*reuseLocator = true
	}

	if *tenant == "" || *service == "" || *logType == "" || *region == "" {
		return 0, fmt.Errorf("-tenant, -service, -log-type and -region are required")
	}
	query, err := buildQuery(*tenant, *service, *logType, *region, *start, *end, *at)
	if err != nil {
		return 0, err
	}
	if err := auditlog.RequireLoopbackHost(*host); err != nil {
		return 0, err
	}
	if err := auditlog.RequireLoopbackDSN(*postgresDSN); err != nil {
		return 0, err
	}
	var encryptionKey []byte
	if *keyFile != "" {
		data, err := os.ReadFile(*keyFile)
		if err != nil {
			return 0, err
		}
		encryptionKey, err = hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(encryptionKey) != auditlog.KeySize {
			return 0, fmt.Errorf("key file %s is not a %d-byte hex key", *keyFile, auditlog.KeySize)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	pool, err := postgresql.NewClient(ctx, *postgresDSN)
	if err != nil {
		return 0, fmt.Errorf("connect PostgreSQL: %w", err)
	}
	defer pool.Close()
	session, err := cassandrastore.NewSession(ctx, cassandrastore.Config{
		Hosts: []string{*host}, Port: *port, Keyspace: *keyspace, Datacenter: "datacenter1",
	})
	if err != nil {
		return 0, fmt.Errorf("connect Cassandra keyspace %s: %w", *keyspace, err)
	}
	defer session.Close()

	// 1. Trusted checkpoint.
	store, err := cassandrastore.NewCheckpointStore(session, locator.LocatorTreeID)
	if err != nil {
		return 0, err
	}
	reader, err := checkpoint.NewReader(*systemID, store)
	if err != nil {
		return 0, err
	}
	trusted, err := reader.Current(ctx)
	if err != nil {
		return 0, fmt.Errorf("read the finalized checkpoint (has anything been ingested?): %w", err)
	}

	// 2. Attribute query through the locator, verified against R_L.
	if *reuseLocator {
		fmt.Println("progress: authenticating the ALL locator range")
	}
	result, err := cassandrastore.NewALLRepo(session).ResolveLocatorQuery(ctx, trusted.LocatorTreeID, trusted.LocatorRoot, query)
	if err != nil {
		return 0, fmt.Errorf("resolve the locator query: %w", err)
	}
	if err := locator.VerifyLocatorQueryResult(query, result, trusted.LocatorRoot); err != nil {
		fmt.Printf("REJECTED: the locator proof does not verify against checkpoint %d: %v\n", trusted.Sequence, err)
		fmt.Println("The address list cannot be trusted, so no log is reported VALID.")
		return 1, nil
	}
	fmt.Printf("checkpoint %d  (R_L %s...  R_G %s...)\n", trusted.Sequence,
		hex.EncodeToString(trusted.LocatorRoot[:4]), hex.EncodeToString(trusted.GlobalHMFRoot[:4]))
	fmt.Printf("query: tenant=%s service=%s log_type=%s region=%s time=[%s, %s)\n", query.TenantID, query.ServiceID,
		query.LogType, query.RegionID, query.StartTime.Format(time.RFC3339), query.EndTime.Format(time.RFC3339))
	// The tenant leads the key order, so the verified range holds only this tenant's logs.
	entries := result.Entries
	fmt.Printf("locator proof verified: %d matching log(s), none omitted\n", len(entries))
	if *reuseLocator {
		fmt.Printf("progress: ALL authenticated %d log ID(s) at checkpoint %d\n", len(entries), trusted.Sequence)
	}
	if len(entries) == 0 {
		return 0, nil
	}

	// 3. Evidence: current stored rows, then the HMF proof.
	if *localize {
		fmt.Println("progress: detecting and localizing tampering (warm-up)")
	} else if *reuseLocator {
		fmt.Println("progress: verifying the stored logs (warm-up)")
	}
	candidates, err := collect(ctx, postgresql.NewLogRepository(pool), entries)
	if err != nil {
		return 0, err
	}
	hppReader, err := cassandrastore.NewHPPReader(session, 8)
	if err != nil {
		return 0, err
	}
	hppService, err := hpp.NewService(hppReader, hppReader)
	if err != nil {
		return 0, err
	}
	auditor := &groupVerifier{service: hppService, trustedRoot: trusted.GlobalHMFRoot}
	var provable []*candidate
	for _, item := range candidates {
		if item.failure == "" {
			provable = append(provable, item)
		}
	}
	verifyBatch := (*groupVerifier).verify
	if *localize {
		verifyBatch = (*groupVerifier).localize
	}
	if err := verifyBatch(auditor, ctx, provable); err != nil {
		return 0, err
	}

	timingLine := ""
	if *repeats > 0 {
		runs := make([]float64, 0, *repeats)
		for trial := range *repeats {
			if *reuseLocator {
				fmt.Printf("progress: timed run %d/%d\n", trial+1, *repeats)
			}
			begin := time.Now()
			timedEntries := entries
			if !*reuseLocator {
				again, err := cassandrastore.NewALLRepo(session).ResolveLocatorQuery(ctx, trusted.LocatorTreeID, trusted.LocatorRoot, query)
				if err != nil {
					return 0, err
				}
				if err := locator.VerifyLocatorQueryResult(query, again, trusted.LocatorRoot); err != nil {
					return 0, err
				}
				timedEntries = again.Entries
			}
			rows, err := collect(ctx, postgresql.NewLogRepository(pool), timedEntries)
			if err != nil {
				return 0, err
			}
			var usable []*candidate
			for _, item := range rows {
				if item.failure == "" {
					usable = append(usable, item)
				}
			}
			if err := verifyBatch(&groupVerifier{service: hppService, trustedRoot: trusted.GlobalHMFRoot}, ctx, usable); err != nil {
				return 0, err
			}
			runs = append(runs, float64(time.Since(begin).Microseconds())/1000)
			if *reuseLocator {
				for index, row := range rows {
					if (row.failure == "") != (candidates[index].failure == "") {
						return 0, fmt.Errorf("verification outcome changed between runs for log %s", row.entry.Key.LogID)
					}
				}
			}
		}
		sorted := slices.Clone(runs)
		slices.Sort(sorted)
		timingLine = fmt.Sprintf("timing: median_ms=%.3f repeats=%d runs_ms=%v", sorted[len(sorted)/2], *repeats, runs)
	}
	if *reuseLocator {
		current, err := reader.Current(ctx)
		if err != nil {
			return 0, err
		}
		if current.Sequence != trusted.Sequence || current.StateCommitment != trusted.StateCommitment {
			return 0, fmt.Errorf("checkpoint changed during verification")
		}
	}

	verdicts := make([]verdict, 0, len(candidates))
	rejected := 0
	for _, item := range candidates {
		status := "VALID"
		reason := item.failure
		if reason != "" {
			status = "REJECTED"
			rejected++
		}
		key := item.entry.Key
		out := verdict{LogID: key.LogID.String(), Status: status, Reason: reason,
			TenantID: key.TenantID, ServiceID: key.ServiceID, LogType: key.LogType, RegionID: key.RegionID,
			Time: key.EventTime.Format(time.RFC3339), Shard: item.address.ShardID,
			Segment: item.address.SegmentID, Leaf: item.address.LeafID}
		if status == "VALID" && encryptionKey != nil {
			if plain, err := auditlog.Open(encryptionKey, item.sealed.ciphertext, item.sealed.tag, item.sealed.nonce, item.sealed.ad); err == nil {
				out.RawLog = string(plain)
			}
		}
		if status == "REJECTED" {
			if item.hasCommitted {
				out.CommittedDigest = hex.EncodeToString(item.committed[:])
			}
			if item.sealed.ciphertext != nil {
				out.StoredDigest = hex.EncodeToString(item.digest[:])
				if encryptionKey != nil {
					if shown, err := auditlog.OpenUnauthenticated(encryptionKey, item.sealed.ciphertext, item.sealed.nonce); err == nil {
						out.StoredContentHex = hex.EncodeToString(shown)
					}
				}
			}
		}
		verdicts = append(verdicts, out)
	}
	print(verdicts, *asJSON, *limit)
	fmt.Printf("\n%d log(s): %d VALID, %d REJECTED  (%d HMF proof(s) built)\n",
		len(verdicts), len(verdicts)-rejected, rejected, auditor.proofs)
	if timingLine != "" {
		fmt.Println(timingLine)
	}
	if rejected > 0 {
		fmt.Printf("BATCH: FAIL   (%d of %d log(s) rejected)\n", rejected, len(verdicts))
		return 1, nil
	}
	fmt.Printf("BATCH: VALID  (all %d log(s) verified against the anchored root of checkpoint %d)\n",
		len(verdicts), trusted.Sequence)
	return 0, nil
}

func buildQuery(tenant, service, logType, region, start, end, at string) (locator.LocatorQuery, error) {
	query := locator.LocatorQuery{TenantID: tenant, ServiceID: service, LogType: logType, RegionID: region}
	parse := func(name, value string) (time.Time, error) {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("-%s %q: want RFC 3339 such as 2015-09-01T18:14:40Z", name, value)
		}
		return parsed.UTC(), nil
	}
	var err error
	switch {
	case at != "" && (start != "" || end != ""):
		return query, fmt.Errorf("use either -at or -start/-end, not both")
	case at != "":
		if query.StartTime, err = parse("at", at); err != nil {
			return query, err
		}
		query.EndTime = query.StartTime.Add(time.Second)
	case start != "" && end != "":
		if query.StartTime, err = parse("start", start); err != nil {
			return query, err
		}
		if query.EndTime, err = parse("end", end); err != nil {
			return query, err
		}
	default:
		return query, fmt.Errorf("give a time: -at T, or both -start and -end")
	}
	if _, _, err := query.Bounds(); err != nil {
		return query, err
	}
	return query, nil
}

// collect reads each authenticated entry's current stored row and derives the
// digest the auditor will place in the proof.
func collect(ctx context.Context, repo *postgresql.LogRepository, entries []locator.LocatorEntry) ([]*candidate, error) {
	candidates := make([]*candidate, len(entries))
	ids := make([]uuid.UUID, len(entries))
	byID := make(map[uuid.UUID]*candidate, len(entries))
	for index, entry := range entries {
		item := &candidate{entry: entry}
		candidates[index] = item
		ids[index] = entry.Key.LogID
		byID[entry.Key.LogID] = item
		address, err := physicalAddress(entry.Value)
		if err != nil {
			item.failure = "locator entry has no usable address: " + err.Error()
			continue
		}
		item.address = address
	}
	rows, err := repo.GetByLogID(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("read stored logs: %w", err)
	}
	defer rows.Close()
	found := make(map[uuid.UUID]bool, len(entries))
	for rows.Next() {
		var id uuid.UUID
		var stored storedRow
		if err := rows.Scan(&id, &stored.ciphertext, &stored.nonce, &stored.tag, &stored.ad); err != nil {
			return nil, err
		}
		item := byID[id]
		if item == nil {
			continue
		}
		found[id] = true
		item.sealed = stored
		item.digest = auditlog.Digest(stored.ciphertext, stored.tag, stored.nonce, stored.ad)
		expected := domain.Log{LogID: item.entry.Key.LogID, EventTime: item.entry.Key.EventTime,
			RegionID: item.entry.Key.RegionID, TenantID: item.entry.Key.TenantID,
			ServiceID: item.entry.Key.ServiceID, LogType: item.entry.Key.LogType}
		if string(domain.EncodeAD(&expected)) != string(stored.ad) && item.failure == "" {
			item.failure = "stored attributes differ from the authenticated locator entry"
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, item := range candidates {
		if !found[item.entry.Key.LogID] && item.failure == "" {
			item.failure = "log is missing from the database"
		}
	}
	return candidates, nil
}

func physicalAddress(value *locator.LocatorValue) (hpp.PhysicalAddress, error) {
	if value == nil {
		return hpp.PhysicalAddress{}, fmt.Errorf("no value")
	}
	parse := func(name, text string) (int64, error) {
		number, err := strconv.ParseInt(text, 10, 64)
		if err != nil || number < 0 {
			return 0, fmt.Errorf("%s %q", name, text)
		}
		return number, nil
	}
	shard, err := parse("shard", value.ShardID)
	if err != nil {
		return hpp.PhysicalAddress{}, err
	}
	segment, err := parse("segment", value.SegmentID)
	if err != nil {
		return hpp.PhysicalAddress{}, err
	}
	leaf, err := parse("leaf", value.LeafID)
	if err != nil {
		return hpp.PhysicalAddress{}, err
	}
	return hpp.PhysicalAddress{RegionID: value.RegionID, ShardID: shard, SegmentID: segment, LeafID: leaf}, nil
}

type groupVerifier struct {
	service     *hpp.Service
	trustedRoot [32]byte
	proofs      int
}

// verify checks the group against the anchored root. A failing group is split
// in half and each half is checked again, so the rejected logs are isolated
// with about k*log2(n) proofs for k rejected logs.
func (verifier *groupVerifier) verify(ctx context.Context, group []*candidate) error {
	if len(group) == 0 {
		return nil
	}
	accepted, err := verifier.check(ctx, group)
	if err != nil {
		return err
	}
	if accepted {
		return nil
	}
	if len(group) == 1 {
		group[0].failure = "stored log does not match the digest committed under the anchored root"
		return nil
	}
	middle := len(group) / 2
	if err := verifier.verify(ctx, group[:middle]); err != nil {
		return err
	}
	return verifier.verify(ctx, group[middle:])
}

func (verifier *groupVerifier) check(ctx context.Context, group []*candidate) (bool, error) {
	proof, addresses, err := verifier.proofForStoredRows(ctx, group)
	if err != nil {
		return false, err
	}
	if _, err := hpp.VerifyHMFProofAgainstRoot(proof, addresses, verifier.trustedRoot); err != nil {
		return false, nil
	}
	return true, nil
}

func (verifier *groupVerifier) localize(ctx context.Context, group []*candidate) error {
	if len(group) == 0 {
		return nil
	}
	proof, addresses, err := verifier.proofForStoredRows(ctx, group)
	if err != nil {
		return err
	}
	root, err := hpp.VerifyHMFProof(proof, addresses)
	if err != nil || root == verifier.trustedRoot {
		return err
	}
	service, err := localization.NewService(verifier.service)
	if err != nil {
		return err
	}
	result, err := service.Localize(ctx, localization.Request{
		Addresses: addresses, AuditorGlobalRoot: root, FailedProof: proof, AnchoredGlobalRoot: verifier.trustedRoot,
	})
	if err != nil {
		return err
	}
	if err := localization.VerifyProof(result.Proof, addresses, verifier.trustedRoot); err != nil {
		return err
	}
	byAddress := make(map[hpp.PhysicalAddress]*candidate, len(group))
	for _, item := range group {
		byAddress[item.address] = item
	}
	for _, suspect := range result.Proof.Suspects {
		if suspect.Address == nil || suspect.Classification != localization.LeafMismatch {
			return fmt.Errorf("localization found %s outside the requested log leaves", suspect.Classification)
		}
		item := byAddress[*suspect.Address]
		if item == nil {
			return fmt.Errorf("localization found an unrequested log address: %+v", *suspect.Address)
		}
		item.failure = "stored log does not match the digest committed under the anchored root"
	}
	if len(result.Proof.Suspects) == 0 {
		return fmt.Errorf("localization did not identify any mismatched leaves")
	}
	return nil
}

func (verifier *groupVerifier) proofForStoredRows(ctx context.Context, group []*candidate) (hpp.HMFProof, []hpp.PhysicalAddress, error) {
	addresses := make([]hpp.PhysicalAddress, len(group))
	digests := make(map[hpp.PhysicalAddress][32]byte, len(group))
	byAddress := make(map[hpp.PhysicalAddress]*candidate, len(group))
	for index, item := range group {
		addresses[index] = item.address
		digests[item.address] = item.digest
		byAddress[item.address] = item
	}
	proof, err := verifier.service.BuildProof(ctx, addresses)
	verifier.proofs++
	if err != nil {
		return hpp.HMFProof{}, nil, fmt.Errorf("build HMF proof: %w", err)
	}
	for index := range proof.Leaves {
		digest, ok := digests[proof.Leaves[index].Address]
		if !ok {
			return hpp.HMFProof{}, nil, fmt.Errorf("proof contains unrequested address %+v", proof.Leaves[index].Address)
		}
		// The leaf the proof arrives with is the one the hierarchy committed;
		// keep it for the report, then substitute the stored row's digest.
		byAddress[proof.Leaves[index].Address].committed = proof.Leaves[index].Hash
		byAddress[proof.Leaves[index].Address].hasCommitted = true
		proof.Leaves[index].Hash = digest
	}
	return proof, addresses, nil
}

func print(verdicts []verdict, asJSON bool, limit int) {
	if asJSON {
		encoder := json.NewEncoder(os.Stdout)
		for _, item := range verdicts {
			_ = encoder.Encode(item)
		}
		return
	}
	fmt.Println()
	shown := 0
	for _, item := range verdicts {
		if limit >= 0 && shown >= limit {
			fmt.Printf("... %d more (use -limit -1 or -json for all)\n", len(verdicts)-shown)
			break
		}
		shown++
		text := item.RawLog
		if len(text) > 90 {
			text = text[:90] + "..."
		}
		line := fmt.Sprintf("%-8s %s  tenant=%s service=%s type=%s region=%s time=%s  @%d/%d/%d",
			item.Status, item.LogID, item.TenantID, item.ServiceID, item.LogType, item.RegionID, item.Time,
			item.Shard, item.Segment, item.Leaf)
		if item.Reason != "" {
			line += "  -- " + item.Reason
		} else if text != "" {
			line += "  | " + text
		}
		fmt.Println(line)
	}
}
