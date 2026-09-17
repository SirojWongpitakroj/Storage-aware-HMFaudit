package cassandra_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	cassandrastore "github.com/SirojWongpitakroj/hmf-audit/storage/cassandra"
	gocql "github.com/apache/cassandra-gocql-driver/v2"
)

func TestCassandraRepositories(t *testing.T) {
	session := newCassandraSession(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := cassandrastore.Ping(ctx, session); err != nil {
		t.Fatalf("ping Cassandra: %v", err)
	}

	t.Run("ALL repository", func(t *testing.T) {
		testALLRepo(t, session)
	})

	t.Run("segment repository", func(t *testing.T) {
		testSegmentRepo(t, session)
	})

	t.Run("HMF repository", func(t *testing.T) {
		testHMFRepo(t, session)
	})

	t.Run("checkpoint repository", func(t *testing.T) {
		testCheckpointRepo(t, session)
	})
}

func testALLRepo(t *testing.T, session *gocql.Session) {
	ctx := context.Background()
	repo := cassandrastore.NewALLRepo(session)
	treeID := "test-all:" + gocql.TimeUUID().String()
	pagesPerBucket := int64(2)

	cleanupQuery(t, session,
		"DELETE FROM all_pages WHERE tree_id = ? AND bucket_id = ?",
		treeID, int64(0),
	)
	cleanupQuery(t, session,
		"DELETE FROM all_pages WHERE tree_id = ? AND bucket_id = ?",
		treeID, int64(1),
	)
	cleanupQuery(t, session,
		"DELETE FROM all_tree_state WHERE tree_id = ?",
		treeID,
	)

	nextPageID := int64(1)
	parentPageID := int64(0)
	pages := []cassandrastore.ALLPage{
		{
			TreeID:        treeID,
			BucketID:      0,
			PageID:        0,
			IsLeaf:        true,
			NextPageID:    &nextPageID,
			PageData:      []byte("page-0"),
			FormatVersion: 1,
			PageHash:      testHash("page-0"),
		},
		{
			TreeID:        treeID,
			BucketID:      0,
			PageID:        1,
			IsLeaf:        true,
			ParentPageID:  &parentPageID,
			PageData:      []byte("page-1"),
			FormatVersion: 1,
			PageHash:      testHash("page-1"),
		},
		{
			TreeID:        treeID,
			BucketID:      1,
			PageID:        2,
			IsLeaf:        false,
			PageData:      []byte("page-2"),
			FormatVersion: 1,
			PageHash:      testHash("page-2"),
		},
	}

	if err := repo.UpsertPages(ctx, pages); err != nil {
		t.Fatalf("upsert ALL pages: %v", err)
	}

	page, err := repo.GetPage(ctx, treeID, 0, pagesPerBucket)
	if err != nil {
		t.Fatalf("get ALL page: %v", err)
	}
	if page.PageID != 0 || !bytes.Equal(page.PageHash, pages[0].PageHash) {
		t.Fatalf("unexpected ALL page: %+v", page)
	}

	requestedIDs := []int64{2, 0, 1}
	gotPages, err := repo.GetPages(ctx, treeID, requestedIDs, pagesPerBucket)
	if err != nil {
		t.Fatalf("get ALL pages: %v", err)
	}
	if len(gotPages) != len(requestedIDs) {
		t.Fatalf("got %d ALL pages, want %d", len(gotPages), len(requestedIDs))
	}
	for index, pageID := range requestedIDs {
		if gotPages[index].PageID != pageID {
			t.Fatalf("page at index %d has ID %d, want %d", index, gotPages[index].PageID, pageID)
		}
	}

	updatedAt := time.Now().UTC().Truncate(time.Millisecond)
	state := cassandrastore.ALLTreeState{
		TreeID:         treeID,
		RootPageID:     2,
		RootHash:       testHash("ALL-root"),
		NextPageID:     3,
		TreeHeight:     1,
		TreeOrder:      4,
		RecordCount:    2,
		PageCount:      3,
		PagesPerBucket: int32(pagesPerBucket),
		UpdatedAt:      updatedAt,
	}
	if err := repo.UpsertTreeState(ctx, state); err != nil {
		t.Fatalf("upsert ALL tree state: %v", err)
	}

	gotState, err := repo.GetTreeState(ctx, treeID)
	if err != nil {
		t.Fatalf("get ALL tree state: %v", err)
	}
	if gotState.RootPageID != state.RootPageID ||
		!bytes.Equal(gotState.RootHash, state.RootHash) ||
		gotState.PageCount != state.PageCount {
		t.Fatalf("unexpected ALL tree state: %+v", gotState)
	}

}

func testSegmentRepo(t *testing.T, session *gocql.Session) {
	ctx := context.Background()
	repo := cassandrastore.NewSegmentRepo(session)
	regionID := "test-region:" + gocql.TimeUUID().String()
	shardID := int64(10)
	segmentID := int64(20)
	secondSegmentID := int64(21)

	cleanupQuery(t, session, `
		DELETE FROM merkle_segment_nodes
		WHERE region_id = ? AND shard_id = ? AND segment_id = ?
	`, regionID, shardID, segmentID)
	cleanupQuery(t, session, `
		DELETE FROM merkle_segment_nodes
		WHERE region_id = ? AND shard_id = ? AND segment_id = ?
	`, regionID, shardID, secondSegmentID)
	cleanupQuery(t, session, `
		DELETE FROM hmf_segments_by_shard
		WHERE region_id = ? AND shard_id = ? AND segment_id = ?
	`, regionID, shardID, segmentID)

	nodes := []cassandrastore.SegmentNode{
		{RegionID: regionID, ShardID: shardID, SegmentID: segmentID, Level: 0, NodeIndex: 0, NodeHash: testHash("segment-leaf-0")},
		{RegionID: regionID, ShardID: shardID, SegmentID: segmentID, Level: 0, NodeIndex: 1, NodeHash: testHash("segment-leaf-1")},
		{RegionID: regionID, ShardID: shardID, SegmentID: segmentID, Level: 1, NodeIndex: 0, NodeHash: testHash("segment-root")},
		{RegionID: regionID, ShardID: shardID, SegmentID: secondSegmentID, Level: 0, NodeIndex: 0, NodeHash: testHash("second-segment-leaf")},
	}

	if err := repo.UpsertNodes(ctx, nodes); err != nil {
		t.Fatalf("upsert segment nodes: %v", err)
	}

	gotNode, err := repo.GetNode(ctx, regionID, shardID, segmentID, 1, 0)
	if err != nil {
		t.Fatalf("get segment node: %v", err)
	}
	if !bytes.Equal(gotNode.NodeHash, nodes[2].NodeHash) {
		t.Fatalf("segment node hash = %x, want %x", gotNode.NodeHash, nodes[2].NodeHash)
	}
	secondNode, err := repo.GetNode(ctx, regionID, shardID, secondSegmentID, 0, 0)
	if err != nil {
		t.Fatalf("get node from second segment partition: %v", err)
	}
	if !bytes.Equal(secondNode.NodeHash, nodes[3].NodeHash) {
		t.Fatalf("second segment node hash = %x, want %x", secondNode.NodeHash, nodes[3].NodeHash)
	}

	gotNodes, err := repo.GetNodes(ctx, regionID, shardID, segmentID)
	if err != nil {
		t.Fatalf("get segment nodes: %v", err)
	}
	if len(gotNodes) != 3 {
		t.Fatalf("got %d segment nodes, want 3", len(gotNodes))
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	startTS := now.Add(-time.Minute)
	endTS := now
	sealedAt := now
	shardLeafIndex := int64(3)
	segment := cassandrastore.SegmentMetadata{
		RegionID:       regionID,
		ShardID:        shardID,
		SegmentID:      segmentID,
		SegmentRoot:    nodes[2].NodeHash,
		LeafCount:      2,
		ShardLeafIndex: &shardLeafIndex,
		MaxLeaves:      16384,
		MaxAgeMS:       60000,
		StartTS:        &startTS,
		EndTS:          &endTS,
		Sealed:         true,
		CreatedAt:      startTS,
		SealedAt:       &sealedAt,
		UpdatedAt:      now,
	}

	if err := repo.UpsertSegment(ctx, segment); err != nil {
		t.Fatalf("upsert segment: %v", err)
	}

	gotSegment, err := repo.GetSegment(ctx, regionID, shardID, segmentID)
	if err != nil {
		t.Fatalf("get segment: %v", err)
	}
	if gotSegment.SegmentID != segmentID ||
		gotSegment.LeafCount != segment.LeafCount ||
		!bytes.Equal(gotSegment.SegmentRoot, segment.SegmentRoot) {
		t.Fatalf("unexpected segment: %+v", gotSegment)
	}

	gotSegments, err := repo.GetSegments(ctx, regionID, shardID)
	if err != nil {
		t.Fatalf("get segments: %v", err)
	}
	if len(gotSegments) != 1 || gotSegments[0].SegmentID != segmentID {
		t.Fatalf("unexpected shard segments: %+v", gotSegments)
	}
}

func testHMFRepo(t *testing.T, session *gocql.Session) {
	ctx := context.Background()
	repo := cassandrastore.NewHMFRepo(session)
	suffix := gocql.TimeUUID().String()
	scopeType := "SHARD"
	scopeID := "test-scope:" + suffix
	secondScopeID := "test-scope-2:" + suffix
	treeID := "SHARD:" + suffix

	cleanupQuery(t, session, `
		DELETE FROM upper_merkle_nodes
		WHERE scope_type = ? AND scope_id = ? AND bucket_id = ?
	`, scopeType, scopeID, 0)
	cleanupQuery(t, session, `
		DELETE FROM upper_merkle_nodes
		WHERE scope_type = ? AND scope_id = ? AND bucket_id = ?
	`, scopeType, secondScopeID, 0)
	cleanupQuery(t, session,
		"DELETE FROM tree_state_by_id WHERE tree_id = ?",
		treeID,
	)

	nodes := []cassandrastore.HMFNode{
		{ScopeType: scopeType, ScopeID: scopeID, Level: 0, NodeIndex: 0, NodeHash: testHash("HMF-leaf-0")},
		{ScopeType: scopeType, ScopeID: scopeID, Level: 0, NodeIndex: 1, NodeHash: testHash("HMF-leaf-1")},
		{ScopeType: scopeType, ScopeID: scopeID, Level: 1, NodeIndex: 0, NodeHash: testHash("HMF-root")},
		{ScopeType: scopeType, ScopeID: secondScopeID, Level: 0, NodeIndex: 0, NodeHash: testHash("second-HMF-leaf")},
	}

	if err := repo.UpsertNodes(ctx, nodes); err != nil {
		t.Fatalf("upsert HMF nodes: %v", err)
	}

	gotNode, err := repo.GetNode(ctx, scopeType, scopeID, 1, 0)
	if err != nil {
		t.Fatalf("get HMF node: %v", err)
	}
	if !bytes.Equal(gotNode.NodeHash, nodes[2].NodeHash) {
		t.Fatalf("HMF node hash = %x, want %x", gotNode.NodeHash, nodes[2].NodeHash)
	}
	secondNode, err := repo.GetNode(ctx, scopeType, secondScopeID, 0, 0)
	if err != nil {
		t.Fatalf("get node from second HMF partition: %v", err)
	}
	if !bytes.Equal(secondNode.NodeHash, nodes[3].NodeHash) {
		t.Fatalf("second HMF node hash = %x, want %x", secondNode.NodeHash, nodes[3].NodeHash)
	}

	gotNodes, err := repo.GetNodes(ctx, scopeType, scopeID, 0)
	if err != nil {
		t.Fatalf("get HMF nodes: %v", err)
	}
	if len(gotNodes) != 3 {
		t.Fatalf("got %d HMF nodes, want 3", len(gotNodes))
	}

	regionID := "test-region"
	shardID := int64(10)
	currentSegmentID := int64(20)
	nextSegmentID := int64(21)
	parentLeafIndex := int64(4)
	state := cassandrastore.HMFTreeState{
		TreeID:           treeID,
		TreeType:         scopeType,
		RegionID:         &regionID,
		ShardID:          &shardID,
		CurrentRoot:      nodes[2].NodeHash,
		CurrentSegmentID: &currentSegmentID,
		NextSegmentID:    &nextSegmentID,
		LeafCount:        2,
		TreeHeight:       1,
		ParentLeafIndex:  &parentLeafIndex,
		UpdatedAt:        time.Now().UTC().Truncate(time.Millisecond),
	}

	if err := repo.UpsertTreeState(ctx, state); err != nil {
		t.Fatalf("upsert HMF tree state: %v", err)
	}

	gotState, err := repo.GetTreeState(ctx, treeID)
	if err != nil {
		t.Fatalf("get HMF tree state: %v", err)
	}
	if gotState.TreeID != treeID ||
		gotState.LeafCount != state.LeafCount ||
		!bytes.Equal(gotState.CurrentRoot, state.CurrentRoot) {
		t.Fatalf("unexpected HMF tree state: %+v", gotState)
	}

	_, err = repo.GetNode(ctx, scopeType, scopeID, 0, 0)
	if !errors.Is(err, gocql.ErrNotFound) {
		t.Fatalf("get deleted HMF node error = %v, want %v", err, gocql.ErrNotFound)
	}
}

func testCheckpointRepo(t *testing.T, session *gocql.Session) {
	ctx := context.Background()
	repo := cassandrastore.NewCheckpointRepo(session)
	systemID := "test-system:" + gocql.TimeUUID().String()
	oldCheckpointID := gocql.UUIDFromTime(time.Now().Add(-time.Minute))
	checkpointID := gocql.UUIDFromTime(time.Now())

	cleanupQuery(t, session, `
		DELETE FROM checkpoint_roots
		WHERE system_id = ? AND checkpoint_sequence = ?
	`, systemID, 1)
	cleanupQuery(t, session, `
		DELETE FROM checkpoint_roots
		WHERE system_id = ? AND checkpoint_sequence = ?
	`, systemID, 2)
	cleanupQuery(t, session,
		"DELETE FROM finality_state WHERE system_id = ?",
		systemID,
	)

	now := time.Now().UTC().Truncate(time.Millisecond)
	transactionHash := "0xtest"
	blockHeight := int64(100)
	checkpoint := cassandrastore.CheckpointRoot{
		SystemID:              systemID,
		CheckpointID:          checkpointID,
		CheckpointSequence:    2,
		LocatorRoot:           testHash("locator-root"),
		GlobalHMFRoot:         testHash("global-root"),
		StateCommitment:       testHash("state-commitment"),
		BlockchainTxHash:      &transactionHash,
		BlockchainBlockHeight: &blockHeight,
		AnchoredAt:            &now,
		FinalizedAt:           &now,
		CreatedAt:             now,
	}
	oldCheckpoint := checkpoint
	oldCheckpoint.CheckpointID = oldCheckpointID
	oldCheckpoint.CheckpointSequence = 1

	if err := repo.UpsertCheckpoint(ctx, oldCheckpoint); err != nil {
		t.Fatalf("upsert old checkpoint: %v", err)
	}
	if err := repo.UpsertCheckpoint(ctx, checkpoint); err != nil {
		t.Fatalf("upsert checkpoint: %v", err)
	}

	gotCheckpoint, err := repo.GetCheckpoint(ctx, systemID, checkpoint.CheckpointSequence)
	if err != nil {
		t.Fatalf("get checkpoint: %v", err)
	}
	if gotCheckpoint.CheckpointID != checkpointID ||
		gotCheckpoint.CheckpointSequence != checkpoint.CheckpointSequence ||
		!bytes.Equal(gotCheckpoint.StateCommitment, checkpoint.StateCommitment) {
		t.Fatalf("unexpected checkpoint: %+v", gotCheckpoint)
	}

	latestCheckpoint, err := repo.GetLatestCheckpoint(ctx, systemID)
	if err != nil {
		t.Fatalf("get latest checkpoint: %v", err)
	}
	if latestCheckpoint.CheckpointID != checkpointID {
		t.Fatalf("latest checkpoint ID = %s, want %s", latestCheckpoint.CheckpointID, checkpointID)
	}

	state := cassandrastore.FinalityState{
		SystemID:              systemID,
		FinalizedCheckpointID: checkpointID,
		CheckpointSequence:    checkpoint.CheckpointSequence,
		LocatorTreeID:         "test-locator",
		LocatorRoot:           checkpoint.LocatorRoot,
		GlobalHMFRoot:         checkpoint.GlobalHMFRoot,
		StateCommitment:       checkpoint.StateCommitment,
		BlockchainTxHash:      transactionHash,
		BlockchainBlockHeight: blockHeight,
		AnchoredAt:            now,
		FinalizedAt:           now,
		UpdatedAt:             now,
	}
	if err := repo.UpsertFinalityState(ctx, state); err != nil {
		t.Fatalf("upsert finality state: %v", err)
	}

	gotState, err := repo.GetFinalityState(ctx, systemID)
	if err != nil {
		t.Fatalf("get finality state: %v", err)
	}
	if gotState.FinalizedCheckpointID != checkpointID ||
		gotState.CheckpointSequence != state.CheckpointSequence ||
		!bytes.Equal(gotState.StateCommitment, state.StateCommitment) {
		t.Fatalf("unexpected finality state: %+v", gotState)
	}
}

func newCassandraSession(t *testing.T) *gocql.Session {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	session, err := cassandrastore.NewSession(ctx, cassandrastore.Config{
		Hosts:      []string{"127.0.0.1"},
		Keyspace:   "hmf_audit",
		Datacenter: "datacenter1",
		Port:       9042,
	})
	if err != nil {
		t.Fatalf("connect to Cassandra: %v", err)
	}

	t.Cleanup(session.Close)
	return session
}

func cleanupQuery(t *testing.T, session *gocql.Session,
	query string, values ...interface{}) {

	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := session.Query(query, values...).ExecContext(ctx); err != nil {
			t.Errorf("clean up Cassandra test data: %v", err)
		}
	})
}

func testHash(value string) []byte {
	hash := sha256.Sum256([]byte(value))
	return hash[:]
}
