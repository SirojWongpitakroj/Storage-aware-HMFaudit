package cassandra

import (
	"context"
	"fmt"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
	gocql "github.com/apache/cassandra-gocql-driver/v2"
	"golang.org/x/sync/errgroup"
)

// FetchProofNodesUngrouped is a benchmark-only alternative to FetchProofNodes
// used to measure the NO_PARTITION_AWARE ablation. It retrieves exactly the
// same required nodes (the plan must already be the canonical, deduplicated
// plan FetchProofNodes would receive) but does not combine multiple node
// positions belonging to the same Cassandra partition into one grouped
// (level, node_index) IN query. Instead it issues one point query per
// required node position, bounded by the same maxConcurrency worker pool as
// FetchProofNodes, so the comparison isolates partition-aware batching from
// concurrency policy.
func (reader *HPPReader) FetchProofNodesUngrouped(ctx context.Context, plan hpp.ProofPlan) ([]hpp.ProofNode, error) {
	type point struct {
		ref   hpp.NodeRef
		query string
		keys  []interface{}
	}

	var points []point
	for _, request := range plan.SegmentRequests {
		tree := request.Tree
		for _, index := range request.NodeIndexes {
			points = append(points, point{
				ref:   hpp.NodeRef{Tree: tree, Position: hpp.NodePosition{Level: request.Level, Index: index}},
				query: segmentPointQuery,
				keys:  []interface{}{request.RegionID, request.ShardID, request.SegmentID, request.Level, index},
			})
		}
	}
	for _, request := range plan.UpperRequests {
		tree := request.Tree
		for _, index := range request.NodeIndexes {
			points = append(points, point{
				ref:   hpp.NodeRef{Tree: tree, Position: hpp.NodePosition{Level: request.Level, Index: index}},
				query: upperPointQuery,
				keys:  []interface{}{request.ScopeType, request.ScopeID, request.BucketID, request.Level, index},
			})
		}
	}

	nodes := make([]hpp.ProofNode, len(points))
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(reader.maxConcurrency)
	for index, requestPoint := range points {
		index, requestPoint := index, requestPoint
		group.Go(func() error {
			var hash []byte
			if err := reader.session.Query(requestPoint.query, requestPoint.keys...).
				ScanContext(groupCtx, &hash); err != nil {
				if err == gocql.ErrNotFound {
					return fmt.Errorf("proof node missing for %+v", requestPoint.ref)
				}
				return fmt.Errorf("fetch proof node %+v: %w", requestPoint.ref, err)
			}
			converted, err := proofHash(hash)
			if err != nil {
				return err
			}
			nodes[index] = hpp.ProofNode{Ref: requestPoint.ref, Hash: converted}
			partitionKeys := requestPoint.keys[:len(requestPoint.keys)-2]
			reader.Stats.addRead(fmt.Sprintf("%s|%v", requestPoint.query, partitionKeys), 1, 1)
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, fmt.Errorf("fetch HPP proof nodes (ungrouped): %w", err)
	}
	return nodes, nil
}

const segmentPointQuery = `
	SELECT node_hash
	FROM merkle_segment_nodes
	WHERE region_id = ? AND shard_id = ? AND segment_id = ?
	AND level = ? AND node_index = ?;
`

const upperPointQuery = `
	SELECT node_hash
	FROM upper_merkle_nodes
	WHERE scope_type = ? AND scope_id = ? AND bucket_id = ?
	AND level = ? AND node_index = ?;
`
