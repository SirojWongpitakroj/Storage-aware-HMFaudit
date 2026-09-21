package cassandra

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"golang.org/x/sync/errgroup"
)

type HPPReader struct {
	session        *gocql.Session
	maxConcurrency int
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

	nodes := make(map[hpp.NodeRef][32]byte)
	var mutex sync.Mutex
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(reader.maxConcurrency)
	for _, partition := range partitions {
		partition := partition
		group.Go(func() error {
			fetched, err := reader.fetchPartition(groupCtx, partition)
			if err != nil {
				return err
			}
			return mergeProofNodes(&mutex, nodes, fetched)
		})
	}
	if err := group.Wait(); err != nil {
		return nil, fmt.Errorf("fetch HPP proof nodes: %w", err)
	}
	result := make([]hpp.ProofNode, 0, len(nodes))
	for ref, hash := range nodes {
		result = append(result, hpp.ProofNode{Ref: ref, Hash: hash})
	}
	sort.Slice(result, func(left, right int) bool {
		leftRef := result[left].Ref
		rightRef := result[right].Ref
		if leftRef.Tree.Layer != rightRef.Tree.Layer {
			return leftRef.Tree.Layer < rightRef.Tree.Layer
		}
		if leftRef.Tree.RegionID != rightRef.Tree.RegionID {
			return leftRef.Tree.RegionID < rightRef.Tree.RegionID
		}
		if leftRef.Tree.ShardID != rightRef.Tree.ShardID {
			return leftRef.Tree.ShardID < rightRef.Tree.ShardID
		}
		if leftRef.Tree.SegmentID != rightRef.Tree.SegmentID {
			return leftRef.Tree.SegmentID < rightRef.Tree.SegmentID
		}
		if leftRef.Position.Level != rightRef.Position.Level {
			return leftRef.Position.Level < rightRef.Position.Level
		}
		return leftRef.Position.Index < rightRef.Position.Index
	})
	return result, nil
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
	for _, index := range indexes {
		partition.positions = append(partition.positions, nodeKey{Level: level, Index: index})
	}
}

func (reader *HPPReader) fetchPartition(ctx context.Context, partition nodePartition) ([]hpp.ProofNode, error) {
	arguments := append(append([]interface{}(nil), partition.keys...), partition.positions)
	iter := reader.session.Query(partition.query, arguments...).IterContext(ctx)
	nodes := make([]hpp.ProofNode, 0, len(partition.positions))
	seen := make(map[nodeKey]bool, len(partition.positions))
	for {
		var level int32
		var index int64
		var hash []byte
		if !iter.Scan(&level, &index, &hash) {
			break
		}
		converted, err := proofHash(hash)
		if err != nil {
			_ = iter.Close()
			return nil, err
		}
		seen[nodeKey{Level: level, Index: index}] = true
		nodes = append(nodes, hpp.ProofNode{
			Ref:  hpp.NodeRef{Tree: partition.tree, Position: hpp.NodePosition{Level: level, Index: index}},
			Hash: converted,
		})
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	for _, position := range partition.positions {
		if !seen[position] {
			return nil, fmt.Errorf("proof node missing for tree %+v at level %d index %d",
				partition.tree, position.Level, position.Index)
		}
	}
	return nodes, nil
}

func mergeProofNodes(mutex *sync.Mutex, destination map[hpp.NodeRef][32]byte,
	nodes []hpp.ProofNode) error {

	mutex.Lock()
	defer mutex.Unlock()
	for _, node := range nodes {
		if existing, duplicate := destination[node.Ref]; duplicate && existing != node.Hash {
			return fmt.Errorf("conflicting proof node %+v", node.Ref)
		}
		destination[node.Ref] = node.Hash
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
