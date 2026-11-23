package exp2b

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Row statuses. Only StatusOK rows contribute latency to the summary; every
// other row is still written to raw.csv and counted.
const (
	StatusOK        = "ok"
	StatusFallback  = "fallback"  // ACHP was requested but fixed-depth produced the proof
	StatusIncorrect = "incorrect" // the localized set differs from the injected set
	StatusUnproven  = "unverified"
	StatusError     = "error"
)

// RawRow is one measured operation.
type RawRow struct {
	Algorithm         string // ACHP, FIXED, EVSEB
	RequestedStrategy string
	ExecutedStrategy  string
	QueryID           string
	// QueryLocality describes the audited batch; Locality is the corruption
	// locality of this case (common for m = 1). They are different concepts.
	QueryLocality     string
	QuerySegments     int
	CorruptionCount   int
	Locality          string
	ActualLocality    string
	Repetition        int
	Seed              uint64
	CorruptedOrdinals []int
	// CorruptedAddresses are the corrupted records' HMF addresses.
	CorruptedAddresses string
	DistinctSegments   int
	DistinctShards     int
	DistinctRegions    int
	// RecordsPerSegment is "region/shard/segment:records;...".
	RecordsPerSegment string

	LatencyMS float64

	PartitionReads     int
	DistinctPartitions int
	CassandraReads     int64 // successful partition queries seen by the Cassandra reader; -1 when unavailable
	MetadataReads      int
	RetrievalRounds    int
	PruningRounds      int
	NodesRetrieved     int
	EvidenceBytes      int64
	RetrievalMS        float64
	PlanningMS         float64 // ACHP only; -1 when not applicable
	SuspectBranches    int
	ConfirmedLeaves    int

	Fallback       bool
	FallbackReason string
	Correct        bool
	FalsePositives int
	Missed         int
	NonLeaf        int // suspects that are not a requested record (authentication or topology nodes)
	Unresolved     int
	ProofVerified  bool
	Status         string
	Error          string
}

// RawHeader is raw.csv's header row.
var RawHeader = []string{
	"algorithm", "requested_strategy", "executed_strategy", "query_id", "query_locality", "query_segments",
	"corruption_count", "corruption_locality", "actual_corruption_locality", "repetition", "seed",
	"corrupted_ordinals", "corrupted_addresses", "distinct_segments", "distinct_shards", "distinct_regions",
	"records_per_segment", "latency_ms",
	"partition_reads", "distinct_partitions", "cassandra_reads_observed", "metadata_reads",
	"retrieval_rounds", "pruning_rounds", "nodes_retrieved", "evidence_bytes", "retrieval_ms",
	"planning_ms", "suspect_branches", "confirmed_leaves", "fallback", "fallback_reason",
	"correct", "false_positives", "missed", "non_leaf_suspects", "unresolved", "proof_verified",
	"status", "error",
}

func optional(value float64) string {
	if value < 0 {
		return ""
	}
	return strconv.FormatFloat(value, 'f', 6, 64)
}

// Fields renders the row; a measurement that does not apply is an empty cell,
// never a zero.
func (row RawRow) Fields() []string {
	ordinals := make([]string, len(row.CorruptedOrdinals))
	for index, ordinal := range row.CorruptedOrdinals {
		ordinals[index] = strconv.Itoa(ordinal)
	}
	cassandra := ""
	if row.CassandraReads >= 0 {
		cassandra = strconv.FormatInt(row.CassandraReads, 10)
	}
	latency := ""
	if row.Status != StatusError {
		latency = strconv.FormatFloat(row.LatencyMS, 'f', 6, 64)
	}
	return []string{
		row.Algorithm, row.RequestedStrategy, row.ExecutedStrategy, row.QueryID,
		row.QueryLocality, strconv.Itoa(row.QuerySegments),
		strconv.Itoa(row.CorruptionCount), row.Locality, row.ActualLocality, strconv.Itoa(row.Repetition),
		strconv.FormatUint(row.Seed, 10), strings.Join(ordinals, ";"), row.CorruptedAddresses,
		strconv.Itoa(row.DistinctSegments), strconv.Itoa(row.DistinctShards), strconv.Itoa(row.DistinctRegions),
		row.RecordsPerSegment, latency, strconv.Itoa(row.PartitionReads), strconv.Itoa(row.DistinctPartitions), cassandra,
		strconv.Itoa(row.MetadataReads), strconv.Itoa(row.RetrievalRounds), strconv.Itoa(row.PruningRounds),
		strconv.Itoa(row.NodesRetrieved), strconv.FormatInt(row.EvidenceBytes, 10),
		optional(row.RetrievalMS), optional(row.PlanningMS), strconv.Itoa(row.SuspectBranches),
		strconv.Itoa(row.ConfirmedLeaves), strconv.FormatBool(row.Fallback), row.FallbackReason,
		strconv.FormatBool(row.Correct), strconv.Itoa(row.FalsePositives), strconv.Itoa(row.Missed),
		strconv.Itoa(row.NonLeaf), strconv.Itoa(row.Unresolved), strconv.FormatBool(row.ProofVerified),
		row.Status, row.Error,
	}
}

// RawWriter streams rows to raw.csv, so a long cloud run keeps what it has
// measured if it stops.
type RawWriter struct {
	writer *csv.Writer
}

func NewRawWriter(w io.Writer) (*RawWriter, error) {
	writer := csv.NewWriter(w)
	if err := writer.Write(RawHeader); err != nil {
		return nil, err
	}
	writer.Flush()
	return &RawWriter{writer: writer}, writer.Error()
}

func (w *RawWriter) Write(row RawRow) error {
	if err := w.writer.Write(row.Fields()); err != nil {
		return err
	}
	w.writer.Flush()
	return w.writer.Error()
}

// Percentile is the nearest-rank percentile (p in (0, 100]); it is NaN for an
// empty sample.
func Percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return math.NaN()
	}
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	rank := int(math.Ceil(p / 100 * float64(len(ordered))))
	return ordered[min(max(rank, 1), len(ordered))-1]
}

// SummaryHeader is summary.csv's header row.
var SummaryHeader = []string{
	"algorithm", "corruption_count", "corruption_locality", "query_locality", "actual_corruption_locality",
	"queries", "attempted", "valid", "error_count", "incorrect_count", "unverified_count", "fallback_count",
	"unresolved_count", "false_positive_total", "missed_total", "p50_latency_ms", "p95_latency_ms",
	"mean_partition_reads", "mean_distinct_partitions", "mean_retrieval_rounds", "mean_pruning_rounds",
	"mean_nodes_retrieved", "mean_evidence_bytes", "mean_retrieval_ms", "mean_planning_ms",
	"mean_suspect_branches", "mean_confirmed_leaves", "mean_distinct_segments", "mean_distinct_shards",
	"mean_distinct_regions",
}

type summaryKey struct {
	algorithm string
	count     int
	locality  string
}

type accumulator struct {
	attempted, valid, errors, incorrect, unverified, fallbacks, unresolved, falsePositives, missed      int
	latency, partitions, distinct, rounds, pruning, nodes, bytes, retrieval, planning, suspects, leaves []float64
	// Workload description, over every attempted row: it says what was run, not what was measured.
	segments, shards, regions []float64
	queries                   map[string]struct{}
	queryLocalities, actual   map[string]struct{}
}

func single(values map[string]struct{}) string {
	switch len(values) {
	case 0:
		return ""
	case 1:
		for value := range values {
			return value
		}
	}
	return "mixed"
}

func mean(values []float64) string {
	if len(values) == 0 {
		return ""
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return strconv.FormatFloat(sum/float64(len(values)), 'f', 6, 64)
}

func quantile(values []float64, p float64) string {
	if len(values) == 0 {
		return ""
	}
	return strconv.FormatFloat(Percentile(values, p), 'f', 6, 64)
}

// Summarize groups rows by corruption count, corruption locality and algorithm.
// m = 1 has only the common locality, so its measurements are counted once, never
// once per locality. Latency
// percentiles and the mean I/O, transfer, round and planning figures use only
// valid rows: a correct, verified localization by the strategy that was asked
// for. Errors, fallbacks, incorrect and unverified runs are counted separately
// and never enter a latency statistic, and a missing measurement is never
// replaced by zero.
func Summarize(rows []RawRow) [][]string {
	groups := map[summaryKey]*accumulator{}
	var keys []summaryKey
	for _, row := range rows {
		key := summaryKey{row.Algorithm, row.CorruptionCount, row.Locality}
		acc, ok := groups[key]
		if !ok {
			acc = &accumulator{queries: map[string]struct{}{}, queryLocalities: map[string]struct{}{}, actual: map[string]struct{}{}}
			groups[key] = acc
			keys = append(keys, key)
		}
		acc.attempted++
		acc.queries[row.QueryID] = struct{}{}
		acc.queryLocalities[row.QueryLocality] = struct{}{}
		acc.actual[row.ActualLocality] = struct{}{}
		acc.segments = append(acc.segments, float64(row.DistinctSegments))
		acc.shards = append(acc.shards, float64(row.DistinctShards))
		acc.regions = append(acc.regions, float64(row.DistinctRegions))
		acc.unresolved += row.Unresolved
		acc.falsePositives += row.FalsePositives
		acc.missed += row.Missed
		switch row.Status {
		case StatusOK:
			acc.valid++
			acc.latency = append(acc.latency, row.LatencyMS)
			acc.partitions = append(acc.partitions, float64(row.PartitionReads))
			acc.distinct = append(acc.distinct, float64(row.DistinctPartitions))
			acc.rounds = append(acc.rounds, float64(row.RetrievalRounds))
			acc.pruning = append(acc.pruning, float64(row.PruningRounds))
			acc.nodes = append(acc.nodes, float64(row.NodesRetrieved))
			acc.bytes = append(acc.bytes, float64(row.EvidenceBytes))
			acc.retrieval = append(acc.retrieval, row.RetrievalMS)
			if row.PlanningMS >= 0 {
				acc.planning = append(acc.planning, row.PlanningMS)
			}
			acc.suspects = append(acc.suspects, float64(row.SuspectBranches))
			acc.leaves = append(acc.leaves, float64(row.ConfirmedLeaves))
		case StatusFallback:
			acc.fallbacks++
		case StatusIncorrect:
			acc.incorrect++
		case StatusUnproven:
			acc.unverified++
		default:
			acc.errors++
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.count != b.count {
			return a.count < b.count
		}
		if a.locality != b.locality {
			return a.locality < b.locality
		}
		return a.algorithm < b.algorithm
	})
	table := make([][]string, 0, len(keys))
	for _, key := range keys {
		acc := groups[key]
		table = append(table, []string{
			key.algorithm, strconv.Itoa(key.count), key.locality, single(acc.queryLocalities), single(acc.actual),
			strconv.Itoa(len(acc.queries)), strconv.Itoa(acc.attempted), strconv.Itoa(acc.valid),
			strconv.Itoa(acc.errors), strconv.Itoa(acc.incorrect), strconv.Itoa(acc.unverified),
			strconv.Itoa(acc.fallbacks), strconv.Itoa(acc.unresolved), strconv.Itoa(acc.falsePositives),
			strconv.Itoa(acc.missed), quantile(acc.latency, 50), quantile(acc.latency, 95),
			mean(acc.partitions), mean(acc.distinct), mean(acc.rounds), mean(acc.pruning), mean(acc.nodes),
			mean(acc.bytes), mean(acc.retrieval), mean(acc.planning), mean(acc.suspects), mean(acc.leaves),
			mean(acc.segments), mean(acc.shards), mean(acc.regions),
		})
	}
	return table
}

// WriteSummary writes summary.csv.
func WriteSummary(w io.Writer, rows []RawRow) error {
	writer := csv.NewWriter(w)
	if err := writer.Write(SummaryHeader); err != nil {
		return err
	}
	for _, record := range Summarize(rows) {
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}
