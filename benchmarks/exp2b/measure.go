package exp2b

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// NodeWireBytes is the size counted for one retrieved authentication node: its
// 32-byte hash. Identifiers and framing are not counted, so the figure is a
// lower bound on what crossed the network and the same for every algorithm.
const NodeWireBytes = 32

// Counters are the reference-store reads one localization performed.
type Counters struct {
	// RetrievalRounds is the number of node-retrieval calls (each one joint,
	// partition-grouped read), including calls that failed.
	RetrievalRounds int
	FailedRounds    int
	// MetadataReads is the number of hierarchy-metadata loads.
	MetadataReads int
	// PartitionReads is the number of partition queries those calls issue: one
	// per distinct Cassandra partition per call, counted from the request plan
	// before the call, so failed and repeated reads are included.
	PartitionReads int
	// DistinctPartitions is how many different partitions were read at least once.
	DistinctPartitions int
	NodesRetrieved     int
	EvidenceBytes      int64
	// RetrievalTime is the wall time spent inside retrieval and metadata calls.
	RetrievalTime time.Duration
}

// MeasuredReader wraps a reference-store reader and counts what passes through
// it. It changes no request and no answer.
type MeasuredReader struct {
	Metadata hpp.MetadataReader
	Nodes    hpp.ProofNodeReader

	mu         sync.Mutex
	counters   Counters
	partitions map[string]struct{}
}

// Reset clears the counters, before each measured operation.
func (reader *MeasuredReader) Reset() {
	reader.mu.Lock()
	reader.counters = Counters{}
	reader.partitions = nil
	reader.mu.Unlock()
}

// Snapshot returns the counters so far.
func (reader *MeasuredReader) Snapshot() Counters {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	counters := reader.counters
	counters.DistinctPartitions = len(reader.partitions)
	return counters
}

func (reader *MeasuredReader) LoadHierarchyMetadata(ctx context.Context,
	addresses []hpp.PhysicalAddress) (hpp.HierarchyMetadata, error) {
	started := time.Now()
	metadata, err := reader.Metadata.LoadHierarchyMetadata(ctx, addresses)
	elapsed := time.Since(started)
	reader.mu.Lock()
	reader.counters.MetadataReads++
	reader.counters.RetrievalTime += elapsed
	reader.mu.Unlock()
	return metadata, err
}

func (reader *MeasuredReader) FetchProofNodes(ctx context.Context, plan hpp.ProofPlan) ([]hpp.ProofNode, error) {
	keys := planPartitions(plan)
	started := time.Now()
	nodes, err := reader.Nodes.FetchProofNodes(ctx, plan)
	elapsed := time.Since(started)
	reader.mu.Lock()
	reader.counters.RetrievalRounds++
	reader.counters.RetrievalTime += elapsed
	reader.counters.PartitionReads += len(keys)
	if reader.partitions == nil {
		reader.partitions = make(map[string]struct{})
	}
	for key := range keys {
		reader.partitions[key] = struct{}{}
	}
	if err != nil {
		reader.counters.FailedRounds++
	} else {
		reader.counters.NodesRetrieved += len(nodes)
		reader.counters.EvidenceBytes += int64(len(nodes)) * NodeWireBytes
	}
	reader.mu.Unlock()
	return nodes, err
}

// planPartitions lists the Cassandra partitions a plan's requests read: one
// segment tree per segment request group and one (scope, bucket) per upper
// request group, which is how the Cassandra reader groups them.
func planPartitions(plan hpp.ProofPlan) map[string]struct{} {
	keys := make(map[string]struct{})
	for _, request := range plan.SegmentRequests {
		keys[fmt.Sprintf("segment|%s|%d|%d", request.RegionID, request.ShardID, request.SegmentID)] = struct{}{}
	}
	for _, request := range plan.UpperRequests {
		keys[fmt.Sprintf("upper|%s|%s|%d", request.ScopeType, request.ScopeID, request.BucketID)] = struct{}{}
	}
	return keys
}
