package cassandra

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"golang.org/x/sync/errgroup"
)

type HPPReader struct {
	session        *gocql.Session
	maxConcurrency int

	// Stats is an optional benchmark-only hook that observes retrieval-call
	// counts. It is nil in production, so adding it does not change retrieval
	// behavior or cost; a benchmark sets HPPReader.Stats to count Cassandra
	// reads and partitions touched per FetchProofNodes/FetchProofNodesUngrouped
	// call without altering their query logic.
	Stats *ReadStats
}

// ReadStats accumulates benchmark-only Cassandra retrieval counters. Reads
// counts every query issued; Partitions counts the distinct partition keys
// those queries touched (several reads may share a partition, as in the
// NO_PARTITION_AWARE ablation's point-query retrieval). RequestedKeys counts
// every individual (level, node_index) key occurrence submitted across all
// queries' arguments, including exact duplicates within one query's IN list
// (the NO_DEDUP ablation's expanded requests); RowsReturned counts the actual
// distinct rows Cassandra scanned back. Comparing the two lets a caller state
// precisely when a duplicate request cost no extra physical I/O (Cassandra
// returning a matched row once regardless of how many times its key appears
// in an IN list) rather than assuming repeated requests mean repeated reads.
type ReadStats struct {
	mu            sync.Mutex
	Reads         int64
	RequestedKeys int64
	RowsReturned  int64
	partitions    map[string]struct{}
}

func (stats *ReadStats) addRead(partitionKey string, requestedKeys, rowsReturned int) {
	if stats == nil {
		return
	}
	stats.mu.Lock()
	stats.Reads++
	stats.RequestedKeys += int64(requestedKeys)
	stats.RowsReturned += int64(rowsReturned)
	if stats.partitions == nil {
		stats.partitions = make(map[string]struct{})
	}
	stats.partitions[partitionKey] = struct{}{}
	stats.mu.Unlock()
}

// Snapshot returns the current counters. Safe to call concurrently with
// retrieval; callers typically snapshot before and after one call and take
// the difference for Reads, RequestedKeys, and RowsReturned (Partitions is
// already the distinct count for this Stats instance's whole lifetime, so
// callers should use a fresh ReadStats per measured call rather than diffing
// Partitions).
func (stats *ReadStats) Snapshot() (reads, partitions, requestedKeys, rowsReturned int64) {
	if stats == nil {
		return 0, 0, 0, 0
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	return stats.Reads, int64(len(stats.partitions)), stats.RequestedKeys, stats.RowsReturned
}

func NewHPPReader(session *gocql.Session, maxConcurrency int) (*HPPReader, error) {
	if session == nil {
		return nil, fmt.Errorf("new HPP reader: Cassandra session is nil")
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 8
	}
	return &HPPReader{session: session, maxConcurrency: maxConcurrency}, nil
}

// LoadHierarchyMetadata reads the planner's metadata with one segment query
// per shard partition plus one query for every shard, region and global tree
// state, instead of one query per segment and per tree.
func (reader *HPPReader) LoadHierarchyMetadata(ctx context.Context,
	addresses []hpp.PhysicalAddress) (hpp.HierarchyMetadata, error) {

	segmentsByShard := make(map[hpp.ShardKey]map[int64]struct{})
	regions := make(map[string]struct{})
	for _, address := range addresses {
		shard := hpp.ShardKey{RegionID: address.RegionID, ShardID: address.ShardID}
		if segmentsByShard[shard] == nil {
			segmentsByShard[shard] = make(map[int64]struct{})
		}
		segmentsByShard[shard][address.SegmentID] = struct{}{}
		regions[address.RegionID] = struct{}{}
	}
	treeIDs := []string{"GLOBAL"}
	for shard := range segmentsByShard {
		treeIDs = append(treeIDs, shardTreeID(shard))
	}
	for regionID := range regions {
		treeIDs = append(treeIDs, "REGION:"+regionID)
	}

	metadata := hpp.HierarchyMetadata{
		Segments: make(map[hpp.SegmentKey]hpp.SegmentMetadata),
		Shards:   make(map[hpp.ShardKey]hpp.UpperTreeMetadata),
		Regions:  make(map[string]hpp.UpperTreeMetadata),
	}
	states := make(map[string]treeStateRow, len(treeIDs))
	var mutex sync.Mutex
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(reader.maxConcurrency)
	for shard, segmentSet := range segmentsByShard {
		shard := shard
		segmentIDs := make([]int64, 0, len(segmentSet))
		for segmentID := range segmentSet {
			segmentIDs = append(segmentIDs, segmentID)
		}
		group.Go(func() error {
			segments, err := reader.readSegments(groupCtx, shard, segmentIDs)
			if err != nil {
				return err
			}
			mutex.Lock()
			for key, segment := range segments {
				metadata.Segments[key] = segment
			}
			mutex.Unlock()
			return nil
		})
	}
	group.Go(func() error {
		rows, err := reader.readTreeStates(groupCtx, treeIDs)
		if err != nil {
			return err
		}
		mutex.Lock()
		for treeID, row := range rows {
			states[treeID] = row
		}
		mutex.Unlock()
		return nil
	})
	if err := group.Wait(); err != nil {
		return hpp.HierarchyMetadata{}, fmt.Errorf("load HPP hierarchy metadata: %w", err)
	}

	for shard, segmentSet := range segmentsByShard {
		for segmentID := range segmentSet {
			key := hpp.SegmentKey{RegionID: shard.RegionID, ShardID: shard.ShardID, SegmentID: segmentID}
			if _, exists := metadata.Segments[key]; !exists {
				return hpp.HierarchyMetadata{}, fmt.Errorf("load HPP metadata: segment %+v not found", key)
			}
		}
		state, exists := states[shardTreeID(shard)]
		if !exists {
			return hpp.HierarchyMetadata{}, fmt.Errorf("load HPP metadata: shard %+v tree state not found", shard)
		}
		if state.parentLeafIndex == nil {
			return hpp.HierarchyMetadata{}, fmt.Errorf("load HPP metadata: shard %+v has no region leaf index", shard)
		}
		metadata.Shards[shard] = hpp.UpperTreeMetadata{LeafCount: state.leafCount, ParentLeafIndex: *state.parentLeafIndex}
	}
	for regionID := range regions {
		state, exists := states["REGION:"+regionID]
		if !exists {
			return hpp.HierarchyMetadata{}, fmt.Errorf("load HPP metadata: region %s tree state not found", regionID)
		}
		if state.parentLeafIndex == nil {
			return hpp.HierarchyMetadata{}, fmt.Errorf("load HPP metadata: region %s has no global leaf index", regionID)
		}
		metadata.Regions[regionID] = hpp.UpperTreeMetadata{LeafCount: state.leafCount, ParentLeafIndex: *state.parentLeafIndex}
	}
	global, exists := states["GLOBAL"]
	if !exists {
		return hpp.HierarchyMetadata{}, fmt.Errorf("load HPP metadata: global tree state not found")
	}
	metadata.Global = hpp.UpperTreeMetadata{LeafCount: global.leafCount}
	return metadata, nil
}

func shardTreeID(shard hpp.ShardKey) string {
	return fmt.Sprintf("SHARD:%s:S%d", shard.RegionID, shard.ShardID)
}

func (reader *HPPReader) readSegments(ctx context.Context, shard hpp.ShardKey,
	segmentIDs []int64) (map[hpp.SegmentKey]hpp.SegmentMetadata, error) {

	iter := reader.session.Query(`
		SELECT segment_id, leaf_count, shard_leaf_index, sealed
		FROM hmf_segments_by_shard
		WHERE region_id = ? AND shard_id = ? AND segment_id IN ?;
	`, shard.RegionID, shard.ShardID, segmentIDs).IterContext(ctx)
	result := make(map[hpp.SegmentKey]hpp.SegmentMetadata, len(segmentIDs))
	for {
		var segmentID, leafCount int64
		var shardLeafIndex *int64
		var sealed bool
		if !iter.Scan(&segmentID, &leafCount, &shardLeafIndex, &sealed) {
			break
		}
		key := hpp.SegmentKey{RegionID: shard.RegionID, ShardID: shard.ShardID, SegmentID: segmentID}
		if shardLeafIndex == nil {
			_ = iter.Close()
			return nil, fmt.Errorf("load HPP metadata: segment %+v has no shard leaf index", key)
		}
		result[key] = hpp.SegmentMetadata{LeafCount: leafCount, ShardLeafIndex: *shardLeafIndex, Sealed: sealed}
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	return result, nil
}

type treeStateRow struct {
	leafCount       int64
	parentLeafIndex *int64
}

func (reader *HPPReader) readTreeStates(ctx context.Context, treeIDs []string) (map[string]treeStateRow, error) {
	iter := reader.session.Query(`
		SELECT tree_id, leaf_count, parent_leaf_index
		FROM tree_state_by_id
		WHERE tree_id IN ?;
	`, treeIDs).IterContext(ctx)
	result := make(map[string]treeStateRow, len(treeIDs))
	for {
		var treeID string
		var row treeStateRow
		if !iter.Scan(&treeID, &row.leafCount, &row.parentLeafIndex) {
			break
		}
		result[treeID] = row
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	return result, nil
}

// FetchProofNodes reads each partition's planned nodes with one query. The
// plan lists nodes per tree level; querying per partition with a
// (level, node_index) IN relation keeps the reads identical while replacing
// one round trip per level with one per partition.
func (reader *HPPReader) FetchProofNodes(ctx context.Context, plan hpp.ProofPlan) ([]hpp.ProofNode, error) {
	var partitions []nodePartition
	segmentIndex := make(map[hpp.TreeRef]int)
	for _, request := range plan.SegmentRequests {
		index, exists := segmentIndex[request.Tree]
		if !exists {
			index = len(partitions)
			segmentIndex[request.Tree] = index
			partitions = append(partitions, nodePartition{
				tree: request.Tree, query: segmentPartitionQuery,
				keys: []interface{}{request.RegionID, request.ShardID, request.SegmentID},
			})
		}
		partitions[index].add(request.Level, request.NodeIndexes)
	}
	type upperKey struct {
		tree      hpp.TreeRef
		scopeType string
		scopeID   string
		bucketID  int64
	}
	upperIndex := make(map[upperKey]int)
	for _, request := range plan.UpperRequests {
		key := upperKey{tree: request.Tree, scopeType: request.ScopeType, scopeID: request.ScopeID, bucketID: request.BucketID}
		index, exists := upperIndex[key]
		if !exists {
			index = len(partitions)
			upperIndex[key] = index
			partitions = append(partitions, nodePartition{
				tree: request.Tree, query: upperPartitionQuery,
				keys: []interface{}{request.ScopeType, request.ScopeID, request.BucketID},
			})
		}
		partitions[index].add(request.Level, request.NodeIndexes)
	}

	results := make([][]hpp.ProofNode, len(partitions))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(reader.maxConcurrency)
	for index := range partitions {
		index := index
		group.Go(func() error {
			fetched, err := reader.fetchPartition(groupCtx, partitions[index])
			if err != nil {
				return err
			}
			results[index] = fetched
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, fmt.Errorf("fetch HPP proof nodes: %w", err)
	}
	// Every partition holds a different tree (or bucket of one), so the partitions' nodes are
	// disjoint; they are joined and put in canonical order here, not merged through a map. The
	// duplicate check below keeps the old behaviour for a reader that returned a node twice.
	total := 0
	for _, fetched := range results {
		total += len(fetched)
	}
	result := make([]hpp.ProofNode, 0, total)
	for _, fetched := range results {
		result = append(result, fetched...)
	}
	if !slices.IsSortedFunc(result, compareProofNodes) {
		slices.SortFunc(result, compareProofNodes)
	}
	result, err := dropIdenticalDuplicates(result)
	if err != nil {
		return nil, fmt.Errorf("fetch HPP proof nodes: %w", err)
	}
	return result, nil
}

// compareProofNodes is the canonical node order of a proof: tree layer, region, shard, segment, level, index.
func compareProofNodes(left, right hpp.ProofNode) int {
	if left.Ref.Tree.Layer != right.Ref.Tree.Layer {
		return cmp.Compare(left.Ref.Tree.Layer, right.Ref.Tree.Layer)
	}
	if left.Ref.Tree.RegionID != right.Ref.Tree.RegionID {
		return strings.Compare(left.Ref.Tree.RegionID, right.Ref.Tree.RegionID)
	}
	if left.Ref.Tree.ShardID != right.Ref.Tree.ShardID {
		return cmp.Compare(left.Ref.Tree.ShardID, right.Ref.Tree.ShardID)
	}
	if left.Ref.Tree.SegmentID != right.Ref.Tree.SegmentID {
		return cmp.Compare(left.Ref.Tree.SegmentID, right.Ref.Tree.SegmentID)
	}
	if left.Ref.Position.Level != right.Ref.Position.Level {
		return cmp.Compare(left.Ref.Position.Level, right.Ref.Position.Level)
	}
	return cmp.Compare(left.Ref.Position.Index, right.Ref.Position.Index)
}

// dropIdenticalDuplicates removes repeated nodes from a sorted list; two different hashes for one
// node are an error.
func dropIdenticalDuplicates(sorted []hpp.ProofNode) ([]hpp.ProofNode, error) {
	kept := sorted[:0]
	for _, node := range sorted {
		if last := len(kept) - 1; last >= 0 && kept[last].Ref == node.Ref {
			if kept[last].Hash != node.Hash {
				return nil, fmt.Errorf("conflicting proof node %+v", node.Ref)
			}
			continue
		}
		kept = append(kept, node)
	}
	return kept, nil
}

const segmentPartitionQuery = `
	SELECT level, node_index, node_hash
	FROM merkle_segment_nodes
	WHERE region_id = ? AND shard_id = ? AND segment_id = ?
	AND (level, node_index) IN ?;
`

const upperPartitionQuery = `
	SELECT level, node_index, node_hash
	FROM upper_merkle_nodes
	WHERE scope_type = ? AND scope_id = ? AND bucket_id = ?
	AND (level, node_index) IN ?;
`

// nodeKey is bound as one (level, node_index) tuple of the IN relation.
type nodeKey struct {
	Level int32
	Index int64
}

// nodePartition collects every planned node of one Cassandra partition.
type nodePartition struct {
	tree      hpp.TreeRef
	query     string
	keys      []interface{}
	positions []nodeKey
}

func (partition *nodePartition) add(level int32, indexes []int64) {
	partition.positions = slices.Grow(partition.positions, len(indexes))
	for _, index := range indexes {
		partition.positions = append(partition.positions, nodeKey{Level: level, Index: index})
	}
}

// nodePageSize is the smallest page a partition read asks for. The driver's default of 5,000 rows
// splits a large answer into several sequential round trips; a page as large as the request returns
// the whole answer in one.
const nodePageSize = 5000

func (reader *HPPReader) fetchPartition(ctx context.Context, partition nodePartition) ([]hpp.ProofNode, error) {
	arguments := append(append(make([]interface{}, 0, len(partition.keys)+1), partition.keys...), partition.positions)
	iter := reader.session.Query(partition.query, arguments...).
		PageSize(max(len(partition.positions), nodePageSize)).IterContext(ctx)
	nodes := make([]hpp.ProofNode, 0, len(partition.positions))
	var level int32
	var index int64
	var hash []byte // the driver refills this slice for every row, so one buffer serves them all
	for iter.Scan(&level, &index, &hash) {
		converted, err := proofHash(hash)
		if err != nil {
			_ = iter.Close()
			return nil, err
		}
		nodes = append(nodes, hpp.ProofNode{
			Ref:  hpp.NodeRef{Tree: partition.tree, Position: hpp.NodePosition{Level: level, Index: index}},
			Hash: converted,
		})
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	if err := partition.checkAllPresent(nodes); err != nil {
		return nil, err
	}
	if reader.Stats != nil {
		reader.Stats.addRead(fmt.Sprintf("%s|%v", partition.query, partition.keys), len(partition.positions), len(nodes))
	}
	return nodes, nil
}

// checkAllPresent reports the first requested position that has no returned row. Both lists are
// walked in (level, index) order, so no lookup set is built; a repeated position needs one row.
func (partition nodePartition) checkAllPresent(nodes []hpp.ProofNode) error {
	less := func(a, b hpp.NodePosition) int {
		if a.Level != b.Level {
			return cmp.Compare(a.Level, b.Level)
		}
		return cmp.Compare(a.Index, b.Index)
	}
	byPosition := func(a, b hpp.ProofNode) int { return less(a.Ref.Position, b.Ref.Position) }
	if !slices.IsSortedFunc(nodes, byPosition) {
		nodes = slices.Clone(nodes)
		slices.SortFunc(nodes, byPosition)
	}
	positions := partition.positions
	byKey := func(a, b nodeKey) int {
		return less(hpp.NodePosition{Level: a.Level, Index: a.Index}, hpp.NodePosition{Level: b.Level, Index: b.Index})
	}
	if !slices.IsSortedFunc(positions, byKey) {
		positions = slices.Clone(positions)
		slices.SortFunc(positions, byKey)
	}
	next := 0
	for _, position := range positions {
		want := hpp.NodePosition{Level: position.Level, Index: position.Index}
		for next < len(nodes) && less(nodes[next].Ref.Position, want) < 0 {
			next++
		}
		if next == len(nodes) || nodes[next].Ref.Position != want {
			return fmt.Errorf("proof node missing for tree %+v at level %d index %d",
				partition.tree, position.Level, position.Index)
		}
	}
	return nil
}

func proofHash(value []byte) ([32]byte, error) {
	if len(value) != 32 {
		return [32]byte{}, fmt.Errorf("proof node hash has %d bytes, want 32", len(value))
	}
	var result [32]byte
	copy(result[:], value)
	return result, nil
}
