// Package hm coordinates HMF hierarchy management.
package hm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
)

type activeSegment struct {
	Tree      *hmf.SegmentTree
	CreatedAt time.Time
	StartedAt time.Time
	EndedAt   time.Time
	SealedAt  time.Time
}

type segmentWorker struct {
	requests chan appendRequest
	stop     chan struct{}
	done     chan struct{}
}

type Manager struct {
	*hmf.HMF

	MaxSegmentLeaves int
	SegmentDuration  time.Duration

	//Tracks the active SegmentID for each (RegionID, ShardID)
	ActiveSegments map[hmf.TreeID]*activeSegment
	stateMu        sync.Mutex
	hmfMu          sync.Mutex
	nextSegmentIDs map[hmf.TreeID]int64

	//segment workers
	workerMu sync.Mutex
	workers  map[hmf.TreeID]*segmentWorker
	updates  chan hmf.HMFUpdate
}

func NewManager(forest *hmf.HMF, maxSegmentLeaves int, segmentDuration time.Duration) (*Manager, error) {
	if forest == nil {
		return nil, fmt.Errorf("new manager: HMF is nil")
	}
	if maxSegmentLeaves <= 0 {
		return nil, fmt.Errorf("new manager: max segment leaves must be positive")
	}
	if segmentDuration <= 0 {
		return nil, fmt.Errorf("new manager: segment duration must be positive")
	}

	return &Manager{
		HMF:              forest,
		MaxSegmentLeaves: maxSegmentLeaves,
		SegmentDuration:  segmentDuration,
		ActiveSegments:   make(map[hmf.TreeID]*activeSegment),
		nextSegmentIDs:   make(map[hmf.TreeID]int64),
		workers:          make(map[hmf.TreeID]*segmentWorker),
		updates:          make(chan hmf.HMFUpdate, 256),
	}, nil
}

func (hm *Manager) openSegment(regionID string, shardID, segmentID int64) (*hmf.SegmentTree, error) {
	//check valid shardTree exist?
	shardTreeID := hmf.TreeID{
		Type:     hmf.TreeShard,
		RegionID: regionID,
		ShardID:  shardID,
	}
	if _, exists := hm.ShardTrees[shardTreeID]; !exists {
		return nil, fmt.Errorf("open segment: shard %d does not exist in region %s", shardID, regionID)
	}

	hm.stateMu.Lock()
	defer hm.stateMu.Unlock()

	if _, exists := hm.ActiveSegments[shardTreeID]; exists {
		return nil, fmt.Errorf("open segment: segment %d already active", segmentID)
	}
	segment := hmf.NewSegmentTree(regionID, shardID, segmentID, hm.MaxSegmentLeaves)
	if hm.ActiveSegments == nil {
		hm.ActiveSegments = make(map[hmf.TreeID]*activeSegment)
	}
	hm.ActiveSegments[shardTreeID] = &activeSegment{
		Tree:      segment,
		CreatedAt: time.Now().UTC(),
	}
	return segment, nil
}

func (hm *Manager) getActiveSegment(regionID string, shardID int64) (*activeSegment, error) {
	treeID := hmf.TreeID{
		Type:     hmf.TreeShard,
		RegionID: regionID,
		ShardID:  shardID,
	}

	hm.stateMu.Lock()
	active, exists := hm.ActiveSegments[treeID]
	hm.stateMu.Unlock()
	//does not exist and match
	if !exists {
		return nil, fmt.Errorf("get active segment by hm: active segment does not exist")
	}
	return active, nil
}

func (hm *Manager) closeSegment(regionID string, shardID int64) (hmf.HMFUpdate, error) {
	activeSegment, err := hm.getActiveSegment(regionID, shardID)
	if err != nil {
		return hmf.HMFUpdate{}, err
	}
	if activeSegment.SealedAt.IsZero() {
		activeSegment.SealedAt = time.Now().UTC()
	}

	segmentNodes, err := activeSegment.Tree.Seal()
	if err != nil {
		return hmf.HMFUpdate{}, err
	}

	hm.hmfMu.Lock()
	update, err := hm.AppendSealedSegment(regionID, shardID, activeSegment.Tree.Root)
	hm.hmfMu.Unlock()
	if err != nil {
		return hmf.HMFUpdate{}, err
	}
	update.SegmentTreeID = activeSegment.Tree.TreeID
	update.SegmentNodes = segmentNodes
	update.SegmentRoot = activeSegment.Tree.Root
	update.SegmentLeaves = activeSegment.Tree.LeafCount
	update.SegmentHeight = activeSegment.Tree.Height
	update.SegmentMaxLeaves = activeSegment.Tree.MaxLeaves
	update.SegmentMaxAge = hm.SegmentDuration
	update.SegmentCreatedAt = activeSegment.CreatedAt
	update.SegmentStartedAt = activeSegment.StartedAt
	update.SegmentEndedAt = activeSegment.EndedAt
	update.SegmentSealedAt = activeSegment.SealedAt

	shardTreeID := hmf.TreeID{Type: hmf.TreeShard, RegionID: regionID, ShardID: shardID}
	hm.stateMu.Lock()
	delete(hm.ActiveSegments, shardTreeID)
	hm.stateMu.Unlock()
	return update, nil
}

func (hm *Manager) nextSegmentID(regionID string, shardID int64) int64 {
	shardTreeID := hmf.TreeID{Type: hmf.TreeShard, RegionID: regionID, ShardID: shardID}

	hm.stateMu.Lock()
	segmentID := hm.nextSegmentIDs[shardTreeID]
	hm.nextSegmentIDs[shardTreeID] = segmentID + 1
	hm.stateMu.Unlock()
	return segmentID
}

func (hm *Manager) getOrStartWorker(
	regionID string,
	shardID int64,
) (*segmentWorker, error) {
	shardTreeID := hmf.TreeID{
		Type:     hmf.TreeShard,
		RegionID: regionID,
		ShardID:  shardID,
	}

	if _, exists := hm.ShardTrees[shardTreeID]; !exists {
		return nil, fmt.Errorf(
			"submit: shard %d does not exist in region %s",
			shardID,
			regionID,
		)
	}

	hm.workerMu.Lock()
	defer hm.workerMu.Unlock()

	if worker, exists := hm.workers[shardTreeID]; exists {
		return worker, nil
	}

	worker := &segmentWorker{
		requests: make(chan appendRequest, 1024),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	hm.workers[shardTreeID] = worker

	go func() {
		hm.runSegmentWorker(regionID, shardID, worker.requests, hm.updates, worker.stop)
		close(worker.done)

		hm.workerMu.Lock()
		if hm.workers[shardTreeID] == worker {
			delete(hm.workers, shardTreeID)
		}
		hm.workerMu.Unlock()
	}()

	return worker, nil
}

func (hm *Manager) Submit(
	regionID string,
	shardID int64,
	digest [32]byte,
	eventTime time.Time,
) error {
	return hm.SubmitContext(context.Background(), regionID, shardID, digest, eventTime)
}

func (hm *Manager) SubmitContext(
	ctx context.Context,
	regionID string,
	shardID int64,
	digest [32]byte,
	eventTime time.Time,
) error {
	return hm.SubmitLog(ctx, shardID, domain.Log{
		RegionID:  regionID,
		EventTime: eventTime,
		Digest:    digest,
	})
}

// SubmitLog submits a prepared log with its logical attributes to one shard.
func (hm *Manager) SubmitLog(ctx context.Context, shardID int64, log domain.Log) error {
	if log.RegionID == "" {
		return fmt.Errorf("submit log: region ID is required")
	}
	if log.EventTime.IsZero() {
		return fmt.Errorf("submit log: event time is required")
	}

	worker, err := hm.getOrStartWorker(log.RegionID, shardID)
	if err != nil {
		return err
	}

	result := make(chan error, 1)

	request := appendRequest{
		Log:    log,
		Result: result,
	}

	select {
	case worker.requests <- request:
	case <-worker.done:
		return fmt.Errorf("submit: segment worker stopped")
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-result:
		return err
	case <-worker.done:
		return fmt.Errorf("submit: segment worker stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (hm *Manager) propagateToALL(log domain.Log, segment *hmf.SegmentTree, leafID int64) error {
	// TODO: Create ALL LocatorKey from LogID, TenantID, ServiceID, LogType,
	// RegionID, and EventTime. Create LocatorValue from RegionID, ShardID,
	// SegmentID, and leafID. Insert the mapping into ALL and emit LocatorUpdate.
	return nil
}

func (hm *Manager) Updates() <-chan hmf.HMFUpdate {
	return hm.updates
}

func (hm *Manager) StopWorker(ctx context.Context, regionID string, shardID int64) error {
	shardTreeID := hmf.TreeID{Type: hmf.TreeShard, RegionID: regionID, ShardID: shardID}

	hm.workerMu.Lock()
	worker, exists := hm.workers[shardTreeID]
	if exists {
		delete(hm.workers, shardTreeID)
		close(worker.stop)
	}
	hm.workerMu.Unlock()
	if !exists {
		return nil
	}

	select {
	case <-worker.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
