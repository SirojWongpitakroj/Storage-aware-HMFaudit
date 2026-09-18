package cassandra

import (
	"context"
	"fmt"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

// HMFUpdateWriter persists one sealed segment and every HMF node changed by it.
type HMFUpdateWriter struct {
	segments *SegmentRepo
	shards   *ShardRepo
	hmf      *HMFRepo
}

func NewHMFUpdateWriter(session *gocql.Session) *HMFUpdateWriter {
	return &HMFUpdateWriter{
		segments: NewSegmentRepo(session),
		shards:   NewShardRepo(session),
		hmf:      NewHMFRepo(session),
	}
}

// PersistSealedUpdate writes immutable segment data before publishing the
// mutable shard, region, global, frontier, and tree-state updates.
func (w *HMFUpdateWriter) PersistSealedUpdate(ctx context.Context, update hmf.HMFUpdate) error {
	if update.SegmentTreeID.Type != hmf.TreeSegment {
		return fmt.Errorf("persist sealed update: segment tree ID is required")
	}
	if update.SegmentLeaves == 0 {
		return fmt.Errorf("persist sealed update: segment must contain leaves")
	}

	segmentID := update.SegmentTreeID
	regionID := segmentID.RegionID
	shardID := segmentID.ShardID
	segmentIDValue := segmentID.SegmentID
	shardLeafIndex := update.ShardLeafIndex

	if err := w.segments.UpsertNodes(ctx, segmentNodes(segmentID, update.SegmentNodes)); err != nil {
		return err
	}
	if err := w.segments.UpsertSegment(ctx, SegmentMetadata{
		RegionID:       regionID,
		ShardID:        shardID,
		SegmentID:      segmentIDValue,
		SegmentRoot:    hashBytes(update.SegmentRoot),
		LeafCount:      update.SegmentLeaves,
		ShardLeafIndex: &shardLeafIndex,
		MaxLeaves:      int32(update.SegmentMaxLeaves),
		MaxAgeMS:       update.SegmentMaxAge.Milliseconds(),
		StartTS:        timePointer(update.SegmentStartedAt),
		EndTS:          timePointer(update.SegmentEndedAt),
		Sealed:         true,
		CreatedAt:      update.SegmentCreatedAt,
		SealedAt:       timePointer(update.SegmentSealedAt),
	}); err != nil {
		return err
	}

	shardScopeID := fmt.Sprintf("%s:S%d", regionID, shardID)
	if err := w.hmf.UpsertNodes(ctx, hmfNodes("SHARD", shardScopeID, update.ShardNodes)); err != nil {
		return err
	}
	if err := w.hmf.UpsertNodes(ctx, hmfNodes("REGION", regionID, update.RegionNodes)); err != nil {
		return err
	}
	if err := w.hmf.UpsertNodes(ctx, hmfNodes("GLOBAL", "GLOBAL", update.GlobalNodes)); err != nil {
		return err
	}
	if err := w.shards.ReplaceFrontiers(ctx, regionID, shardID, shardFrontiers(update.ShardFrontiers)); err != nil {
		return err
	}

	return w.persistTreeStates(ctx, update)
}

// PersistUpdates consumes Manager.Updates until the context is cancelled or
// persistence fails. Run it in one goroutine so updates stay ordered.
func (w *HMFUpdateWriter) PersistUpdates(ctx context.Context, updates <-chan hmf.HMFUpdate) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case update, ok := <-updates:
			if !ok {
				return nil
			}
			if err := w.PersistSealedUpdate(ctx, update); err != nil {
				return err
			}
		}
	}
}

func (w *HMFUpdateWriter) persistTreeStates(ctx context.Context, update hmf.HMFUpdate) error {
	regionID := update.SegmentTreeID.RegionID
	shardID := update.SegmentTreeID.ShardID
	segmentID := update.SegmentTreeID.SegmentID
	nextSegmentID := segmentID + 1
	shardParentIndex := update.RegionParentLeafIndex
	regionParentIndex := update.GlobalParentLeafIndex

	states := []HMFTreeState{
		{
			TreeID:          fmt.Sprintf("SEGMENT:%s:S%d:%d", regionID, shardID, segmentID),
			TreeType:        "SEGMENT",
			RegionID:        &regionID,
			ShardID:         &shardID,
			SegmentID:       &segmentID,
			CurrentRoot:     hashBytes(update.SegmentRoot),
			LeafCount:       update.SegmentLeaves,
			TreeHeight:      int32(update.SegmentHeight),
			ParentLeafIndex: &update.ShardLeafIndex,
			UpdatedAt:       update.SegmentSealedAt,
		},
		{
			TreeID:          fmt.Sprintf("SHARD:%s:S%d", regionID, shardID),
			TreeType:        "SHARD",
			RegionID:        &regionID,
			ShardID:         &shardID,
			CurrentRoot:     hashBytes(update.ShardRoot),
			NextSegmentID:   &nextSegmentID,
			LeafCount:       update.ShardLeaves,
			TreeHeight:      int32(update.ShardHeight),
			ParentLeafIndex: &shardParentIndex,
			UpdatedAt:       update.SegmentSealedAt,
		},
		{
			TreeID:          fmt.Sprintf("REGION:%s", regionID),
			TreeType:        "REGION",
			RegionID:        &regionID,
			CurrentRoot:     hashBytes(update.RegionRoot),
			LeafCount:       update.RegionLeaves,
			TreeHeight:      int32(update.RegionHeight),
			ParentLeafIndex: &regionParentIndex,
			UpdatedAt:       update.SegmentSealedAt,
		},
		{
			TreeID:      "GLOBAL",
			TreeType:    "GLOBAL",
			CurrentRoot: hashBytes(update.GlobalRoot),
			LeafCount:   update.GlobalLeaves,
			TreeHeight:  int32(update.GlobalHeight),
			UpdatedAt:   update.SegmentSealedAt,
		},
	}

	for _, state := range states {
		if err := w.hmf.UpsertTreeState(ctx, state); err != nil {
			return err
		}
	}
	return nil
}

func segmentNodes(treeID hmf.TreeID, nodes []hmf.MerkleNode) []SegmentNode {
	persisted := make([]SegmentNode, 0, len(nodes))
	for _, node := range nodes {
		persisted = append(persisted, SegmentNode{
			RegionID:  treeID.RegionID,
			ShardID:   treeID.ShardID,
			SegmentID: treeID.SegmentID,
			Level:     int32(node.Level),
			NodeIndex: node.Index,
			NodeHash:  hashBytes(node.Hash),
		})
	}
	return persisted
}

func hmfNodes(scopeType, scopeID string, nodes []hmf.MerkleNode) []HMFNode {
	persisted := make([]HMFNode, 0, len(nodes))
	for _, node := range nodes {
		persisted = append(persisted, HMFNode{
			ScopeType: scopeType,
			ScopeID:   scopeID,
			Level:     int32(node.Level),
			NodeIndex: node.Index,
			NodeHash:  hashBytes(node.Hash),
		})
	}
	return persisted
}

func shardFrontiers(nodes []hmf.MerkleNode) []ShardFrontier {
	persisted := make([]ShardFrontier, 0, len(nodes))
	for _, node := range nodes {
		persisted = append(persisted, ShardFrontier{
			Level:     int32(node.Level),
			NodeIndex: node.Index,
			NodeHash:  hashBytes(node.Hash),
		})
	}
	return persisted
}

func hashBytes(hash [32]byte) []byte {
	return append([]byte(nil), hash[:]...)
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}
