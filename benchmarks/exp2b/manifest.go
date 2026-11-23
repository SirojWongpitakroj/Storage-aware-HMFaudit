// Package exp2b implements Experiment 2B: how corruption density (the number of
// corrupted records, m) and physical distribution (clustered or scattered) change
// post-mismatch localization cost, for ACHP and for fixed-depth HMF.
//
// The package is deliberately free of any database. It owns the deterministic
// query and corruption manifests, the measurement protocol, the result rows and
// their summary; an Environment supplies the storage (Cassandra and PostgreSQL in
// the cloud run, an in-memory forest in the dry run).
package exp2b

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
)

// Corruption patterns. m = 1 has no meaningful distribution, so it uses one
// common case shared by every algorithm.
const (
	PatternCommon    = "common"
	PatternClustered = "clustered"
	PatternScattered = "scattered"

	PhaseWarmup   = "warmup"
	PhaseMeasured = "measured"

	// ManifestVersion changes when the manifest generation rules change, so a
	// stale manifest is never reused under new rules.
	ManifestVersion = 1
)

// SegmentSpan is one HMF Segment: a run of Leaves consecutive dataset ordinals
// starting at First.
type SegmentSpan struct {
	Region  string `json:"region"`
	Shard   int64  `json:"shard"`
	Segment int64  `json:"segment"`
	First   int    `json:"first_ordinal"`
	Leaves  int    `json:"leaves"`
}

// Params fixes the whole experiment. DefaultParams is the Experiment 2B
// specification; tests and the dry run scale it down.
type Params struct {
	MasterSeed uint64 `json:"master_seed"`
	QueryCount int    `json:"query_count"`
	// Q is the audit size: every query holds exactly Q distinct records.
	Q int `json:"q"`
	// A query holds DenseSegments segments with DensePerSegment consecutive
	// requested records each (what clustered corruption needs) and the rest of
	// its Q records spread SparsePerSegment at a time over many more segments
	// (what scattered corruption needs).
	DenseSegments    int `json:"dense_segments"`
	DensePerSegment  int `json:"dense_per_segment"`
	SparsePerSegment int `json:"sparse_per_segment"`
	// CorruptionCounts is m.
	CorruptionCounts []int `json:"corruption_counts"`
	Warmups          int   `json:"warmups"`
	Repetitions      int   `json:"repetitions"`
}

// DefaultParams is the Experiment 2B specification: five fixed queries of 4,096
// records, m in {1, 4, 16, 64}, three warm-ups and twenty measured repetitions.
// Each query has 8 dense segments x 256 records and 128 sparse segments x 16
// records, so m = 64 can be clustered (256 >= 64 in one segment) and scattered
// (136 >= 64 distinct segments).
func DefaultParams() Params {
	return Params{
		MasterSeed: 20261123, QueryCount: 5, Q: 4096,
		DenseSegments: 8, DensePerSegment: 256, SparsePerSegment: 16,
		CorruptionCounts: []int{1, 4, 16, 64}, Warmups: 3, Repetitions: 20,
	}
}

// SparseSegments is the number of sparse segments per query.
func (p Params) SparseSegments() int {
	if p.SparsePerSegment <= 0 {
		return 0
	}
	return (p.Q - p.DenseSegments*p.DensePerSegment) / p.SparsePerSegment
}

// MaxCount is the largest corruption count.
func (p Params) MaxCount() int {
	maxCount := 0
	for _, count := range p.CorruptionCounts {
		maxCount = max(maxCount, count)
	}
	return maxCount
}

// Validate rejects parameters that cannot produce the specified workload. It
// never adjusts them.
func (p Params) Validate() error {
	switch {
	case p.QueryCount <= 0 || p.Q <= 0 || p.Warmups < 0 || p.Repetitions <= 0:
		return fmt.Errorf("exp2b: query count, q and repetitions must be positive and warm-ups non-negative")
	case p.DenseSegments <= 0 || p.DensePerSegment <= 0 || p.SparsePerSegment <= 0:
		return fmt.Errorf("exp2b: dense and sparse segment shapes must be positive")
	case p.DenseSegments*p.DensePerSegment >= p.Q:
		return fmt.Errorf("exp2b: dense segments hold %d records, leaving none of the %d for sparse segments",
			p.DenseSegments*p.DensePerSegment, p.Q)
	case (p.Q-p.DenseSegments*p.DensePerSegment)%p.SparsePerSegment != 0:
		return fmt.Errorf("exp2b: %d sparse records are not a multiple of %d per segment",
			p.Q-p.DenseSegments*p.DensePerSegment, p.SparsePerSegment)
	case len(p.CorruptionCounts) == 0:
		return fmt.Errorf("exp2b: no corruption counts")
	}
	if !sort.IntsAreSorted(p.CorruptionCounts) {
		return fmt.Errorf("exp2b: corruption counts must be ascending")
	}
	for index, count := range p.CorruptionCounts {
		if count <= 0 || (index > 0 && count == p.CorruptionCounts[index-1]) {
			return fmt.Errorf("exp2b: corruption counts must be distinct and positive, got %v", p.CorruptionCounts)
		}
	}
	if p.MaxCount() > p.DensePerSegment {
		return fmt.Errorf("exp2b: m = %d cannot be clustered: a dense segment holds %d requested records",
			p.MaxCount(), p.DensePerSegment)
	}
	if segments := p.DenseSegments + p.SparseSegments(); p.MaxCount() > segments {
		return fmt.Errorf("exp2b: m = %d cannot be scattered: a query spans only %d segments", p.MaxCount(), segments)
	}
	return nil
}

// Record is one requested record and where it lives.
type Record struct {
	Ordinal int    `json:"ordinal"`
	Region  string `json:"region"`
	Shard   int64  `json:"shard"`
	Segment int64  `json:"segment"`
	Leaf    int    `json:"leaf"`
}

// QuerySegment summarises one segment of a query.
type QuerySegment struct {
	Region  string `json:"region"`
	Shard   int64  `json:"shard"`
	Segment int64  `json:"segment"`
	Kind    string `json:"kind"` // "dense" or "sparse"
	Records int    `json:"records"`
}

// Query is one fixed audit batch: exactly Q distinct dataset ordinals, ascending.
type Query struct {
	ID       string         `json:"id"`
	Seed     uint64         `json:"seed"`
	Ordinals []int          `json:"ordinals"`
	Segments []QuerySegment `json:"segments"`
}

// QueryManifest is queries.json.
type QueryManifest struct {
	Version    int     `json:"version"`
	Params     Params  `json:"params"`
	LayoutHash string  `json:"layout_sha256"`
	Records    int     `json:"layout_records"`
	Segments   int     `json:"layout_segments"`
	Queries    []Query `json:"queries"`
}

// Layout indexes the segments of the dataset by ordinal.
type Layout struct {
	spans []SegmentSpan
	total int
	hash  string
}

// NewLayout accepts segments in ascending, gap-free ordinal order.
func NewLayout(spans []SegmentSpan) (*Layout, error) {
	if len(spans) == 0 {
		return nil, fmt.Errorf("exp2b: layout has no segments")
	}
	hasher := sha256.New()
	next := 0
	for _, span := range spans {
		if span.Leaves <= 0 || span.First != next {
			return nil, fmt.Errorf("exp2b: segment %s/%d/%d starts at %d with %d leaves, want a gap-free layout from %d",
				span.Region, span.Shard, span.Segment, span.First, span.Leaves, next)
		}
		next += span.Leaves
		fmt.Fprintf(hasher, "%s|%d|%d|%d|%d\n", span.Region, span.Shard, span.Segment, span.First, span.Leaves)
	}
	return &Layout{spans: slices.Clone(spans), total: next, hash: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func (layout *Layout) Total() int             { return layout.total }
func (layout *Layout) SegmentCount() int      { return len(layout.spans) }
func (layout *Layout) Hash() string           { return layout.hash }
func (layout *Layout) Span(i int) SegmentSpan { return layout.spans[i] }

// Locate returns the segment index and leaf offset of an ordinal.
func (layout *Layout) Locate(ordinal int) (segment, leaf int, ok bool) {
	if ordinal < 0 || ordinal >= layout.total {
		return 0, 0, false
	}
	segment = sort.Search(len(layout.spans), func(i int) bool { return layout.spans[i].First > ordinal }) - 1
	return segment, ordinal - layout.spans[segment].First, true
}

// Record describes an ordinal.
func (layout *Layout) Record(ordinal int) (Record, error) {
	segment, leaf, ok := layout.Locate(ordinal)
	if !ok {
		return Record{}, fmt.Errorf("exp2b: ordinal %d is outside the %d-record layout", ordinal, layout.total)
	}
	span := layout.spans[segment]
	return Record{Ordinal: ordinal, Region: span.Region, Shard: span.Shard, Segment: span.Segment, Leaf: leaf}, nil
}

// DeriveSeed is the deterministic per-case seed: a hash of the master seed and
// the case's identity, so a case's randomness never depends on what else ran.
func DeriveSeed(master uint64, parts ...any) uint64 {
	hasher := sha256.New()
	fmt.Fprintf(hasher, "exp2b/%d", master)
	for _, part := range parts {
		fmt.Fprintf(hasher, "|%v", part)
	}
	sum := hasher.Sum(nil)
	var seed uint64
	for _, b := range sum[:8] {
		seed = seed<<8 | uint64(b)
	}
	return seed
}

func newRand(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
}

// GenerateQueries builds the fixed query sets. The same parameters and layout
// always produce byte-identical manifests.
func GenerateQueries(params Params, layout *Layout) (QueryManifest, error) {
	if err := params.Validate(); err != nil {
		return QueryManifest{}, err
	}
	sparse := params.SparseSegments()
	var eligible []int // segments with room for a dense run
	for index, span := range layout.spans {
		if span.Leaves >= params.DensePerSegment && span.Leaves >= params.SparsePerSegment {
			eligible = append(eligible, index)
		}
	}
	need := params.DenseSegments + sparse
	if len(eligible) < need {
		return QueryManifest{}, fmt.Errorf("exp2b: the layout has %d segments with at least %d leaves, a query needs %d",
			len(eligible), params.DensePerSegment, need)
	}
	manifest := QueryManifest{
		Version: ManifestVersion, Params: params, LayoutHash: layout.hash,
		Records: layout.total, Segments: len(layout.spans),
	}
	for number := 1; number <= params.QueryCount; number++ {
		id := fmt.Sprintf("q%d", number)
		seed := DeriveSeed(params.MasterSeed, "query", id)
		rng := newRand(seed)
		order := slices.Clone(eligible)
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		query := Query{ID: id, Seed: seed}
		type pick struct {
			segment int
			kind    string
		}
		var picks []pick
		for _, segment := range order[:params.DenseSegments] {
			picks = append(picks, pick{segment, "dense"})
		}
		for _, segment := range order[params.DenseSegments:need] {
			picks = append(picks, pick{segment, "sparse"})
		}
		sort.Slice(picks, func(i, j int) bool { return picks[i].segment < picks[j].segment })
		for _, p := range picks {
			span := layout.spans[p.segment]
			var offsets []int
			if p.kind == "dense" {
				// A compact, contiguous run of requested records.
				start := rng.IntN(span.Leaves - params.DensePerSegment + 1)
				for i := range params.DensePerSegment {
					offsets = append(offsets, start+i)
				}
			} else {
				offsets = distinctOffsets(rng, span.Leaves, params.SparsePerSegment)
			}
			for _, offset := range offsets {
				query.Ordinals = append(query.Ordinals, span.First+offset)
			}
			query.Segments = append(query.Segments, QuerySegment{
				Region: span.Region, Shard: span.Shard, Segment: span.Segment, Kind: p.kind, Records: len(offsets),
			})
		}
		manifest.Queries = append(manifest.Queries, query)
	}
	if err := ValidateQueries(manifest, layout); err != nil {
		return QueryManifest{}, err
	}
	return manifest, nil
}

// distinctOffsets returns count distinct offsets in [0, n), ascending.
func distinctOffsets(rng *rand.Rand, n, count int) []int {
	chosen := make(map[int]struct{}, count)
	for len(chosen) < count {
		chosen[rng.IntN(n)] = struct{}{}
	}
	offsets := make([]int, 0, count)
	for offset := range chosen {
		offsets = append(offsets, offset)
	}
	sort.Ints(offsets)
	return offsets
}

// ValidateQueries checks a manifest against its parameters and layout.
func ValidateQueries(manifest QueryManifest, layout *Layout) error {
	params := manifest.Params
	if err := params.Validate(); err != nil {
		return err
	}
	if manifest.Version != ManifestVersion {
		return fmt.Errorf("exp2b: query manifest version %d, this build writes version %d", manifest.Version, ManifestVersion)
	}
	if manifest.LayoutHash != layout.hash {
		return fmt.Errorf("exp2b: the query manifest was built for a different dataset layout (%s, now %s)",
			manifest.LayoutHash, layout.hash)
	}
	if len(manifest.Queries) != params.QueryCount {
		return fmt.Errorf("exp2b: %d queries, want %d", len(manifest.Queries), params.QueryCount)
	}
	seen := map[string]bool{}
	for _, query := range manifest.Queries {
		if seen[query.ID] {
			return fmt.Errorf("exp2b: query %s is listed twice", query.ID)
		}
		seen[query.ID] = true
		if len(query.Ordinals) != params.Q {
			return fmt.Errorf("exp2b: query %s has %d records, want exactly %d", query.ID, len(query.Ordinals), params.Q)
		}
		perSegment := map[int]int{}
		for index, ordinal := range query.Ordinals {
			if index > 0 && ordinal <= query.Ordinals[index-1] {
				return fmt.Errorf("exp2b: query %s ordinals are not strictly ascending at %d", query.ID, index)
			}
			segment, _, ok := layout.Locate(ordinal)
			if !ok {
				return fmt.Errorf("exp2b: query %s ordinal %d is outside the layout", query.ID, ordinal)
			}
			perSegment[segment]++
		}
		dense, sparse := 0, 0
		for _, count := range perSegment {
			switch count {
			case params.DensePerSegment:
				dense++
			case params.SparsePerSegment:
				sparse++
			default:
				return fmt.Errorf("exp2b: query %s has a segment with %d records, want %d or %d",
					query.ID, count, params.DensePerSegment, params.SparsePerSegment)
			}
		}
		if dense != params.DenseSegments || sparse != params.SparseSegments() {
			return fmt.Errorf("exp2b: query %s has %d dense and %d sparse segments, want %d and %d",
				query.ID, dense, sparse, params.DenseSegments, params.SparseSegments())
		}
	}
	return nil
}

// Hash is the SHA-256 of the manifest's JSON, recorded in the corruption
// manifest so the two cannot drift apart.
func (manifest QueryManifest) Hash() string {
	encoded, _ := json.Marshal(manifest)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// Query returns a query by ID.
func (manifest QueryManifest) Query(id string) (Query, bool) {
	for _, query := range manifest.Queries {
		if query.ID == id {
			return query, true
		}
	}
	return Query{}, false
}
