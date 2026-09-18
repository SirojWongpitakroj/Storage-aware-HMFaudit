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
	segments       *SegmentRepo
	hmf            *HMFRepo
	maxConcurrency int
}

func NewHPPReader(session *gocql.Session, maxConcurrency int) (*HPPReader, error) {
	if session == nil {
		return nil, fmt.Errorf("new HPP reader: Cassandra session is nil")
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 8
	}
	return &HPPReader{
		session: session, segments: NewSegmentRepo(session), hmf: NewHMFRepo(session),
		maxConcurrency: maxConcurrency,
	}, nil
}

func (reader *HPPReader) LoadHierarchyMetadata(ctx context.Context,
	addresses []hpp.PhysicalAddress) (hpp.HierarchyMetadata, error) {

	segments := make(map[hpp.SegmentKey]struct{})
	shards := make(map[hpp.ShardKey]struct{})
	regions := make(map[string]struct{})
	for _, address := range addresses {
		segments[hpp.SegmentKey{RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}] = struct{}{}
		shards[hpp.ShardKey{RegionID: address.RegionID, ShardID: address.ShardID}] = struct{}{}
		regions[address.RegionID] = struct{}{}
	}
	metadata := hpp.HierarchyMetadata{
		Segments: make(map[hpp.SegmentKey]hpp.SegmentMetadata),
		Shards:   make(map[hpp.ShardKey]hpp.UpperTreeMetadata),
		Regions:  make(map[string]hpp.UpperTreeMetadata),
	}
	var mutex sync.Mutex
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(reader.maxConcurrency)

	for key := range segments {
		key := key
		group.Go(func() error {
			segment, err := reader.segments.GetSegment(groupCtx, key.RegionID, key.ShardID, key.SegmentID)
			if err != nil {
				return err
			}
			if segment.ShardLeafIndex == nil {
				return fmt.Errorf("load HPP metadata: segment %+v has no shard leaf index", key)
			}
			mutex.Lock()
			metadata.Segments[key] = hpp.SegmentMetadata{
				LeafCount: segment.LeafCount, ShardLeafIndex: *segment.ShardLeafIndex, Sealed: segment.Sealed,
			}
			mutex.Unlock()
			return nil
		})
	}
	for key := range shards {
		key := key
		group.Go(func() error {
			state, err := reader.hmf.GetTreeState(groupCtx, fmt.Sprintf("SHARD:%s:S%d", key.RegionID, key.ShardID))
			if err != nil {
				return err
			}
			if state.ParentLeafIndex == nil {
				return fmt.Errorf("load HPP metadata: shard %+v has no region leaf index", key)
			}
			mutex.Lock()
			metadata.Shards[key] = hpp.UpperTreeMetadata{
				LeafCount: state.LeafCount, ParentLeafIndex: *state.ParentLeafIndex,
			}
			mutex.Unlock()
			return nil
		})
	}
	for regionID := range regions {
		regionID := regionID
		group.Go(func() error {
			state, err := reader.hmf.GetTreeState(groupCtx, "REGION:"+regionID)
			if err != nil {
				return err
			}
			if state.ParentLeafIndex == nil {
				return fmt.Errorf("load HPP metadata: region %s has no global leaf index", regionID)
			}
			mutex.Lock()
			metadata.Regions[regionID] = hpp.UpperTreeMetadata{
				LeafCount: state.LeafCount, ParentLeafIndex: *state.ParentLeafIndex,
			}
			mutex.Unlock()
			return nil
		})
	}
	group.Go(func() error {
		state, err := reader.hmf.GetTreeState(groupCtx, "GLOBAL")
		if err != nil {
			return err
		}
		mutex.Lock()
		metadata.Global = hpp.UpperTreeMetadata{LeafCount: state.LeafCount}
		mutex.Unlock()
		return nil
	})
	if err := group.Wait(); err != nil {
		return hpp.HierarchyMetadata{}, fmt.Errorf("load HPP hierarchy metadata: %w", err)
	}
	return metadata, nil
}

func (reader *HPPReader) FetchProofNodes(ctx context.Context, plan hpp.ProofPlan) ([]hpp.ProofNode, error) {
	nodes := make(map[hpp.NodeRef][32]byte)
	var mutex sync.Mutex
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(reader.maxConcurrency)

	for _, request := range plan.SegmentRequests {
		request := request
		group.Go(func() error {
			fetched, err := reader.fetchSegmentRequest(groupCtx, request)
			if err != nil {
				return err
			}
			return mergeProofNodes(&mutex, nodes, fetched)
		})
	}
	for _, request := range plan.UpperRequests {
		request := request
		group.Go(func() error {
			fetched, err := reader.fetchUpperRequest(groupCtx, request)
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

func (reader *HPPReader) fetchSegmentRequest(ctx context.Context,
	request hpp.SegmentRequest) ([]hpp.ProofNode, error) {

	query := `
		SELECT node_index, node_hash
		FROM merkle_segment_nodes
		WHERE region_id = ? AND shard_id = ? AND segment_id = ?
		AND level = ? AND node_index IN ?;
	`
	iter := reader.session.Query(query, request.RegionID, request.ShardID, request.SegmentID,
		request.Level, request.NodeIndexes).IterContext(ctx)
	nodes := make([]hpp.ProofNode, 0, len(request.NodeIndexes))
	seen := make(map[int64]bool)
	for {
		var index int64
		var hash []byte
		if !iter.Scan(&index, &hash) {
			break
		}
		converted, err := proofHash(hash)
		if err != nil {
			_ = iter.Close()
			return nil, err
		}
		seen[index] = true
		nodes = append(nodes, hpp.ProofNode{
			Ref:  hpp.NodeRef{Tree: request.Tree, Position: hpp.NodePosition{Level: request.Level, Index: index}},
			Hash: converted,
		})
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	for _, index := range request.NodeIndexes {
		if !seen[index] {
			return nil, fmt.Errorf("segment proof node missing at level %d index %d", request.Level, index)
		}
	}
	return nodes, nil
}

func (reader *HPPReader) fetchUpperRequest(ctx context.Context,
	request hpp.UpperRequest) ([]hpp.ProofNode, error) {

	query := `
		SELECT node_index, node_hash
		FROM upper_merkle_nodes
		WHERE scope_type = ? AND scope_id = ? AND bucket_id = ?
		AND level = ? AND node_index IN ?;
	`
	iter := reader.session.Query(query, request.ScopeType, request.ScopeID, request.BucketID,
		request.Level, request.NodeIndexes).IterContext(ctx)
	nodes := make([]hpp.ProofNode, 0, len(request.NodeIndexes))
	seen := make(map[int64]bool)
	for {
		var index int64
		var hash []byte
		if !iter.Scan(&index, &hash) {
			break
		}
		converted, err := proofHash(hash)
		if err != nil {
			_ = iter.Close()
			return nil, err
		}
		seen[index] = true
		nodes = append(nodes, hpp.ProofNode{
			Ref:  hpp.NodeRef{Tree: request.Tree, Position: hpp.NodePosition{Level: request.Level, Index: index}},
			Hash: converted,
		})
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	for _, index := range request.NodeIndexes {
		if !seen[index] {
			return nil, fmt.Errorf("upper proof node missing at level %d index %d", request.Level, index)
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
