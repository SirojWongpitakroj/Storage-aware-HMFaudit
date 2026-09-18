package cassandra

import (
	"context"
	"fmt"

	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

// ShardFrontier is one active frontier node in a shard tree.
type ShardFrontier struct {
	Level     int32
	NodeIndex int64
	NodeHash  []byte
}

type ShardRepo struct {
	session *gocql.Session
}

func NewShardRepo(session *gocql.Session) *ShardRepo {
	return &ShardRepo{session: session}
}

// UpsertFrontiers saves the current frontier nodes for one shard.
func (r *ShardRepo) UpsertFrontiers(ctx context.Context, regionID string,
	shardID int64, frontiers []ShardFrontier) error {

	if len(frontiers) == 0 {
		return nil
	}

	query := `
		INSERT INTO shard_tree_frontiers (
			region_id,
			shard_id,
			level,
			node_index,
			node_hash
		)
		VALUES (?, ?, ?, ?, ?);
	`

	batch := r.session.Batch(gocql.UnloggedBatch)
	for _, frontier := range frontiers {
		batch = batch.Query(
			query,
			regionID,
			shardID,
			frontier.Level,
			frontier.NodeIndex,
			frontier.NodeHash,
		)
	}

	if err := batch.ExecContext(ctx); err != nil {
		return fmt.Errorf("upsert shard frontiers: %w", err)
	}

	return nil
}

// ReplaceFrontiers replaces every frontier row for one shard with one snapshot.
func (r *ShardRepo) ReplaceFrontiers(ctx context.Context, regionID string,
	shardID int64, frontiers []ShardFrontier) error {

	batch := r.session.Batch(gocql.LoggedBatch)
	batch = batch.Query(`
		DELETE FROM shard_tree_frontiers
		WHERE region_id = ? AND shard_id = ?;
	`, regionID, shardID)

	query := `
		INSERT INTO shard_tree_frontiers (
			region_id,
			shard_id,
			level,
			node_index,
			node_hash
		)
		VALUES (?, ?, ?, ?, ?);
	`
	for _, frontier := range frontiers {
		batch = batch.Query(
			query,
			regionID,
			shardID,
			frontier.Level,
			frontier.NodeIndex,
			frontier.NodeHash,
		)
	}

	if err := batch.ExecContext(ctx); err != nil {
		return fmt.Errorf("replace shard frontiers: %w", err)
	}

	return nil
}

// GetFrontiers returns every persisted frontier row for one shard.
func (r *ShardRepo) GetFrontiers(ctx context.Context, regionID string,
	shardID int64) ([]ShardFrontier, error) {

	query := `
		SELECT level, node_index, node_hash
		FROM shard_tree_frontiers
		WHERE region_id = ?
		AND shard_id = ?;
	`

	iter := r.session.Query(query, regionID, shardID).IterContext(ctx)
	frontiers := make([]ShardFrontier, 0)

	for {
		frontier := ShardFrontier{}
		if !iter.Scan(&frontier.Level, &frontier.NodeIndex, &frontier.NodeHash) {
			break
		}
		frontiers = append(frontiers, frontier)
	}

	if err := iter.Close(); err != nil {
		return nil, fmt.Errorf("get shard frontiers: %w", err)
	}

	return frontiers, nil
}
