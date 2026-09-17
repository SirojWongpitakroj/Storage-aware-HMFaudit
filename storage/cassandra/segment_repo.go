package cassandra

import (
	"context"
	"fmt"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

type SegmentNode struct {
	RegionID  string
	ShardID   int64
	SegmentID int64
	Level     int32
	NodeIndex int64
	NodeHash  []byte
}

type SegmentMetadata struct {
	RegionID       string
	ShardID        int64
	SegmentID      int64
	SegmentRoot    []byte
	LeafCount      int64
	ShardLeafIndex *int64
	MaxLeaves      int32
	MaxAgeMS       int64
	StartTS        *time.Time
	EndTS          *time.Time
	Sealed         bool
	CreatedAt      time.Time
	SealedAt       *time.Time
	UpdatedAt      time.Time
}

type SegmentRepo struct {
	session *gocql.Session
}

func NewSegmentRepo(session *gocql.Session) *SegmentRepo {
	return &SegmentRepo{
		session: session,
	}
}

// segment nodes inserted will be in the same partition every call

func (r *SegmentRepo) UpsertNodes(ctx context.Context, nodes []SegmentNode) error {
	//IMPORTANT: nodes must be from the same segment
	// one segment = 1 partition

	if len(nodes) == 0 {
		return nil
	}

	query := `
		INSERT INTO merkle_segment_nodes (
			region_id,
			shard_id,
			segment_id,
			level,
			node_index,
			node_hash
		)
		VALUES (?, ?, ?, ?, ?, ?);
	`

	batch := r.session.Batch(gocql.UnloggedBatch)

	for _, node := range nodes {
		batch = batch.Query(
			query,
			node.RegionID,
			node.ShardID,
			node.SegmentID,
			node.Level,
			node.NodeIndex,
			node.NodeHash,
		)
	}

	if err := batch.ExecContext(ctx); err != nil {
		return fmt.Errorf("upsert segment nodes: %w", err)
	}

	return nil
}

func (r *SegmentRepo) GetNode(ctx context.Context, regionID string,
	shardID, segmentID int64, level int32, nodeIndex int64) (SegmentNode, error) {

	node := SegmentNode{}

	query := `
		SELECT
			region_id,
			shard_id,
			segment_id,
			level,
			node_index,
			node_hash
		FROM merkle_segment_nodes
		WHERE region_id = ?
		AND shard_id = ?
		AND segment_id = ?
		AND level = ?
		AND node_index = ?;
	`

	err := r.session.Query(
		query,
		regionID,
		shardID,
		segmentID,
		level,
		nodeIndex,
	).ScanContext(
		ctx,
		&node.RegionID,
		&node.ShardID,
		&node.SegmentID,
		&node.Level,
		&node.NodeIndex,
		&node.NodeHash,
	)

	if err != nil {
		return SegmentNode{}, fmt.Errorf("get segment node %d: %w", nodeIndex, err)
	}

	return node, nil
}

func (r *SegmentRepo) GetNodes(ctx context.Context, regionID string,
	shardID, segmentID int64) ([]SegmentNode, error) {

	query := `
		SELECT
			region_id,
			shard_id,
			segment_id,
			level,
			node_index,
			node_hash
		FROM merkle_segment_nodes
		WHERE region_id = ?
		AND shard_id = ?
		AND segment_id = ?;
	`

	iter := r.session.Query(
		query,
		regionID,
		shardID,
		segmentID,
	).IterContext(ctx)

	nodes := make([]SegmentNode, 0)
	for {
		node := SegmentNode{}
		if !iter.Scan(
			&node.RegionID,
			&node.ShardID,
			&node.SegmentID,
			&node.Level,
			&node.NodeIndex,
			&node.NodeHash,
		) {
			break
		}
		nodes = append(nodes, node)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("get segment nodes: %w", err)
	}

	return nodes, nil
}

func (r *SegmentRepo) UpsertSegment(ctx context.Context, segment SegmentMetadata) error {
	query := `
		INSERT INTO hmf_segments_by_shard (
			region_id,
			shard_id,
			segment_id,
			segment_root,
			leaf_count,
			shard_leaf_index,
			max_leaves,
			max_age_ms,
			start_ts,
			end_ts,
			sealed,
			created_at,
			sealed_at,
			updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
	`

	err := r.session.Query(
		query,
		segment.RegionID,
		segment.ShardID,
		segment.SegmentID,
		segment.SegmentRoot,
		segment.LeafCount,
		segment.ShardLeafIndex,
		segment.MaxLeaves,
		segment.MaxAgeMS,
		segment.StartTS,
		segment.EndTS,
		segment.Sealed,
		segment.CreatedAt,
		segment.SealedAt,
		segment.UpdatedAt,
	).ExecContext(ctx)

	if err != nil {
		return fmt.Errorf("upsert segment %d: %w", segment.SegmentID, err)
	}

	return nil
}

func (r *SegmentRepo) GetSegment(ctx context.Context, regionID string,
	shardID, segmentID int64) (SegmentMetadata, error) {

	segment := SegmentMetadata{}

	query := `
		SELECT
			region_id,
			shard_id,
			segment_id,
			segment_root,
			leaf_count,
			shard_leaf_index,
			max_leaves,
			max_age_ms,
			start_ts,
			end_ts,
			sealed,
			created_at,
			sealed_at,
			updated_at
		FROM hmf_segments_by_shard
		WHERE region_id = ?
		AND shard_id = ?
		AND segment_id = ?;
	`

	err := r.session.Query(
		query,
		regionID,
		shardID,
		segmentID,
	).ScanContext(
		ctx,
		&segment.RegionID,
		&segment.ShardID,
		&segment.SegmentID,
		&segment.SegmentRoot,
		&segment.LeafCount,
		&segment.ShardLeafIndex,
		&segment.MaxLeaves,
		&segment.MaxAgeMS,
		&segment.StartTS,
		&segment.EndTS,
		&segment.Sealed,
		&segment.CreatedAt,
		&segment.SealedAt,
		&segment.UpdatedAt,
	)

	if err != nil {
		return SegmentMetadata{}, fmt.Errorf("get segment %d: %w", segmentID, err)
	}

	return segment, nil
}

func (r *SegmentRepo) GetSegments(ctx context.Context, regionID string,
	shardID int64) ([]SegmentMetadata, error) {

	query := `
		SELECT
			region_id,
			shard_id,
			segment_id,
			segment_root,
			leaf_count,
			shard_leaf_index,
			max_leaves,
			max_age_ms,
			start_ts,
			end_ts,
			sealed,
			created_at,
			sealed_at,
			updated_at
		FROM hmf_segments_by_shard
		WHERE region_id = ?
		AND shard_id = ?;
	`

	iter := r.session.Query(
		query,
		regionID,
		shardID,
	).IterContext(ctx)

	segments := make([]SegmentMetadata, 0)
	for {
		segment := SegmentMetadata{}
		if !iter.Scan(
			&segment.RegionID,
			&segment.ShardID,
			&segment.SegmentID,
			&segment.SegmentRoot,
			&segment.LeafCount,
			&segment.ShardLeafIndex,
			&segment.MaxLeaves,
			&segment.MaxAgeMS,
			&segment.StartTS,
			&segment.EndTS,
			&segment.Sealed,
			&segment.CreatedAt,
			&segment.SealedAt,
			&segment.UpdatedAt,
		) {
			break
		}
		segments = append(segments, segment)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("get shard segments: %w", err)
	}

	return segments, nil
}
