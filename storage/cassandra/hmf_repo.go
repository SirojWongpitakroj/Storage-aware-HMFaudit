package cassandra

import (
	"context"
	"fmt"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

type HMFNode struct {
	ScopeType string
	ScopeID   string
	BucketID  int64
	Level     int32
	NodeIndex int64
	NodeHash  []byte
}

const (
	ShardNodesPerBucket int64 = 1 << 15
	shardBucketLevel          = 15
)

func hmfBucketID(scopeType string, level int32, nodeIndex int64) int64 {
	if scopeType != "SHARD" {
		return 0
	}

	//determine bucketID for shard internal node and leaf
	//level = nodeIndex x 2^(level - 15)
	if level < shardBucketLevel {
		return nodeIndex >> (shardBucketLevel - level)
	}

	return nodeIndex << (level - shardBucketLevel)
}

type HMFTreeState struct { //tree_state_by_id
	TreeID           string
	TreeType         string
	RegionID         *string
	ShardID          *int64
	SegmentID        *int64
	CurrentRoot      []byte
	CurrentSegmentID *int64
	NextSegmentID    *int64
	LeafCount        int64
	TreeHeight       int32
	ParentLeafIndex  *int64
	UpdatedAt        time.Time
}

type HMFRepo struct {
	session *gocql.Session
}

func NewHMFRepo(session *gocql.Session) *HMFRepo {
	return &HMFRepo{
		session: session,
	}
}

func (r *HMFRepo) UpsertNode(ctx context.Context, node HMFNode) error {
	query := `
		INSERT INTO upper_merkle_nodes (
			scope_type,
			scope_id,
			bucket_id,
			level,
			node_index,
			node_hash
		)
		VALUES (?, ?, ?, ?, ?, ?);
	`

	err := r.session.Query(
		query,
		node.ScopeType,
		node.ScopeID,
		hmfBucketID(node.ScopeType, node.Level, node.NodeIndex),
		node.Level,
		node.NodeIndex,
		node.NodeHash,
	).ExecContext(ctx)

	if err != nil {
		return fmt.Errorf("upsert HMF node %d: %w", node.NodeIndex, err)
	}

	return nil
}

func (r *HMFRepo) UpsertNodes(ctx context.Context, nodes []HMFNode) error {
	if len(nodes) == 0 {
		return nil
	}

	type partitionKey struct {
		scopeType string
		scopeID   string
		bucketID  int64
	}

	partitions := make(map[partitionKey][]HMFNode)
	for _, node := range nodes {
		key := partitionKey{
			scopeType: node.ScopeType,
			scopeID:   node.ScopeID,
			bucketID:  hmfBucketID(node.ScopeType, node.Level, node.NodeIndex),
		}
		partitions[key] = append(partitions[key], node)
	}

	query := `
		INSERT INTO upper_merkle_nodes (
			scope_type,
			scope_id,
			bucket_id,
			level,
			node_index,
			node_hash
		)
		VALUES (?, ?, ?, ?, ?, ?);
	`

	results := make(chan error, len(partitions))

	for _, partitionNodes := range partitions {
		go func(partitionNodes []HMFNode) {
			batch := r.session.Batch(gocql.UnloggedBatch)

			for _, node := range partitionNodes {
				batch = batch.Query(
					query,
					node.ScopeType,
					node.ScopeID,
					hmfBucketID(node.ScopeType, node.Level, node.NodeIndex),
					node.Level,
					node.NodeIndex,
					node.NodeHash,
				)
			}

			results <- batch.ExecContext(ctx)
		}(partitionNodes)
	}

	var firstErr error
	for range partitions {
		if err := <-results; err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		return fmt.Errorf("upsert HMF nodes: %w", firstErr)
	}

	return nil
}

func (r *HMFRepo) GetNode(ctx context.Context, scopeType, scopeID string,
	level int32, nodeIndex int64) (HMFNode, error) {

	node := HMFNode{}

	query := `
	SELECT
			scope_type,
			scope_id,
			bucket_id,
			level,
			node_index,
			node_hash
		FROM upper_merkle_nodes
		WHERE scope_type = ?
		AND scope_id = ?
		AND bucket_id = ?
		AND level = ?
		AND node_index = ?;
	`

	err := r.session.Query(
		query,
		scopeType,
		scopeID,
		hmfBucketID(scopeType, level, nodeIndex),
		level,
		nodeIndex,
	).ScanContext(
		ctx,
		&node.ScopeType,
		&node.ScopeID,
		&node.BucketID,
		&node.Level,
		&node.NodeIndex,
		&node.NodeHash,
	)

	if err != nil {
		return HMFNode{}, fmt.Errorf("get HMF node %d: %w", nodeIndex, err)
	}

	return node, nil
}

func (r *HMFRepo) GetNodes(ctx context.Context,
	scopeType, scopeID string, bucketID int64) ([]HMFNode, error) {

	query := `
		SELECT
			scope_type,
			scope_id,
			bucket_id,
			level,
			node_index,
			node_hash
		FROM upper_merkle_nodes
		WHERE scope_type = ?
		AND scope_id = ?
		AND bucket_id = ?;
	`

	iter := r.session.Query(
		query,
		scopeType,
		scopeID,
		bucketID,
	).IterContext(ctx)

	nodes := make([]HMFNode, 0)
	for {
		node := HMFNode{}
		if !iter.Scan(
			&node.ScopeType,
			&node.ScopeID,
			&node.BucketID,
			&node.Level,
			&node.NodeIndex,
			&node.NodeHash,
		) {
			break
		}
		nodes = append(nodes, node)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("get HMF nodes: %w", err)
	}

	return nodes, nil
}

func (r *HMFRepo) UpsertTreeState(ctx context.Context, state HMFTreeState) error {
	query := `
		INSERT INTO tree_state_by_id (
			tree_id,
			tree_type,
			region_id,
			shard_id,
			segment_id,
			current_root,
			current_segment_id,
			next_segment_id,
			leaf_count,
			tree_height,
			parent_leaf_index,
			updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	err := r.session.Query(
		query,
		state.TreeID,
		state.TreeType,
		state.RegionID,
		state.ShardID,
		state.SegmentID,
		state.CurrentRoot,
		state.CurrentSegmentID,
		state.NextSegmentID,
		state.LeafCount,
		state.TreeHeight,
		state.ParentLeafIndex,
		state.UpdatedAt,
	).ExecContext(ctx)

	if err != nil {
		return fmt.Errorf("upsert HMF tree state %s: %w", state.TreeID, err)
	}

	return nil
}

func (r *HMFRepo) GetTreeState(ctx context.Context,
	treeID string) (HMFTreeState, error) {

	state := HMFTreeState{}

	query := `
		SELECT
			tree_id,
			tree_type,
			region_id,
			shard_id,
			segment_id,
			current_root,
			current_segment_id,
			next_segment_id,
			leaf_count,
			tree_height,
			parent_leaf_index,
			updated_at
		FROM tree_state_by_id
		WHERE tree_id = ?;
	`

	err := r.session.Query(
		query,
		treeID,
	).ScanContext(
		ctx,
		&state.TreeID,
		&state.TreeType,
		&state.RegionID,
		&state.ShardID,
		&state.SegmentID,
		&state.CurrentRoot,
		&state.CurrentSegmentID,
		&state.NextSegmentID,
		&state.LeafCount,
		&state.TreeHeight,
		&state.ParentLeafIndex,
		&state.UpdatedAt,
	)

	if err != nil {
		return HMFTreeState{}, fmt.Errorf("get HMF tree state %s: %w", treeID, err)
	}

	return state, nil
}
