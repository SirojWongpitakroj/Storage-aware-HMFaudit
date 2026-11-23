package localization

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

// forestSpec describes a complete HMF forest built for tests.
type forestSpec struct {
	regions         int
	shardsPerRegion int
	// segments returns the number of segments of shard (region, shard).
	segments func(region, shard int) int
	// leaves returns the number of leaves of a segment.
	leaves func(region, shard, segment int) int
	// salt changes every leaf hash, so two forests with the same shape differ.
	salt string
}

// forest is a fully materialised HMF: every node of every tree.
type forest struct {
	spec      forestSpec
	metadata  hpp.HierarchyMetadata
	nodes     map[hpp.TreeRef]map[hpp.NodePosition][32]byte
	root      [32]byte
	addresses []hpp.PhysicalAddress
}

func defaultForestSpec() forestSpec {
	return forestSpec{
		regions: 3, shardsPerRegion: 3,
		segments: func(region, shard int) int { return 3 + (region+shard)%2 },
		leaves: func(region, shard, segment int) int {
			return []int{16, 13, 7, 21, 8, 11}[(region*5+shard*3+segment)%6]
		},
	}
}

func buildForest(t testing.TB, spec forestSpec) forest {
	t.Helper()
	result := forest{spec: spec, nodes: make(map[hpp.TreeRef]map[hpp.NodePosition][32]byte),
		metadata: hpp.HierarchyMetadata{
			Segments: make(map[hpp.SegmentKey]hpp.SegmentMetadata),
			Shards:   make(map[hpp.ShardKey]hpp.UpperTreeMetadata),
			Regions:  make(map[string]hpp.UpperTreeMetadata),
		}}
	var regionRoots [][32]byte
	for region := 0; region < spec.regions; region++ {
		regionID := fmt.Sprintf("R%d", region)
		var shardRoots [][32]byte
		for shard := 0; shard < spec.shardsPerRegion; shard++ {
			var segmentRoots [][32]byte
			segments := spec.segments(region, shard)
			for segment := 0; segment < segments; segment++ {
				count := spec.leaves(region, shard, segment)
				leaves := make([][32]byte, count)
				for leaf := range leaves {
					leaves[leaf] = digest(fmt.Sprintf("%s/%s/%d/%d/%d", spec.salt, regionID, shard, segment, leaf))
					result.addresses = append(result.addresses, hpp.PhysicalAddress{
						RegionID: regionID, ShardID: int64(shard), SegmentID: int64(segment), LeafID: int64(leaf)})
				}
				raw, nodes := makeTree(leaves)
				tree := hpp.TreeRef{Layer: hpp.LayerSegment, RegionID: regionID, ShardID: int64(shard), SegmentID: int64(segment)}
				result.nodes[tree] = nodes
				segmentRoots = append(segmentRoots, hmf.CommitSegmentRoot(regionID, int64(shard), int64(segment), int64(count), raw))
				result.metadata.Segments[hpp.SegmentKey{RegionID: regionID, ShardID: int64(shard), SegmentID: int64(segment)}] =
					hpp.SegmentMetadata{LeafCount: int64(count), ShardLeafIndex: int64(segment), Sealed: true}
			}
			raw, nodes := makeTree(segmentRoots)
			result.nodes[hpp.TreeRef{Layer: hpp.LayerShard, RegionID: regionID, ShardID: int64(shard)}] = nodes
			shardRoots = append(shardRoots, hmf.CommitShardRoot(regionID, int64(shard), int64(segments), raw))
			result.metadata.Shards[hpp.ShardKey{RegionID: regionID, ShardID: int64(shard)}] =
				hpp.UpperTreeMetadata{LeafCount: int64(segments), ParentLeafIndex: int64(shard)}
		}
		raw, nodes := makeTree(shardRoots)
		result.nodes[hpp.TreeRef{Layer: hpp.LayerRegion, RegionID: regionID}] = nodes
		regionRoots = append(regionRoots, hmf.CommitRegionRoot(regionID, int64(spec.shardsPerRegion), raw))
		result.metadata.Regions[regionID] = hpp.UpperTreeMetadata{
			LeafCount: int64(spec.shardsPerRegion), ParentLeafIndex: int64(region)}
	}
	raw, nodes := makeTree(regionRoots)
	result.nodes[hpp.TreeRef{Layer: hpp.LayerGlobal}] = nodes
	result.root = hmf.CommitGlobalRoot(int64(spec.regions), raw)
	result.metadata.Global = hpp.UpperTreeMetadata{LeafCount: int64(spec.regions)}
	return result
}

// store serves a forest the way the Cassandra reader does: it answers the
// SegmentRequests and UpperRequests of a plan, one partition at a time, and
// fails a whole call when a requested node is absent. It records every call so
// tests can inspect what was read.
type store struct {
	forest forest

	mu    sync.Mutex
	calls [][]hpp.NodeRef
	// omit makes a node absent; override makes the store return a different
	// hash for a node.
	omit     map[hpp.NodeRef]bool
	override map[hpp.NodeRef][32]byte
}

func newStore(f forest) *store {
	return &store{forest: f, omit: map[hpp.NodeRef]bool{}, override: map[hpp.NodeRef][32]byte{}}
}

func (s *store) LoadHierarchyMetadata(context.Context, []hpp.PhysicalAddress) (hpp.HierarchyMetadata, error) {
	return s.forest.metadata, nil
}

func (s *store) FetchProofNodes(_ context.Context, plan hpp.ProofPlan) ([]hpp.ProofNode, error) {
	var refs []hpp.NodeRef
	for _, request := range plan.SegmentRequests {
		for _, index := range request.NodeIndexes {
			refs = append(refs, hpp.NodeRef{Tree: request.Tree, Position: hpp.NodePosition{Level: request.Level, Index: index}})
		}
	}
	for _, request := range plan.UpperRequests {
		for _, index := range request.NodeIndexes {
			refs = append(refs, hpp.NodeRef{Tree: request.Tree, Position: hpp.NodePosition{Level: request.Level, Index: index}})
		}
	}
	s.mu.Lock()
	s.calls = append(s.calls, slices.Clone(refs))
	s.mu.Unlock()
	nodes := make([]hpp.ProofNode, 0, len(refs))
	for _, ref := range refs {
		if s.omit[ref] {
			return nil, fmt.Errorf("proof node missing for tree %+v at level %d index %d",
				ref.Tree, ref.Position.Level, ref.Position.Index)
		}
		hash, ok := s.forest.nodes[ref.Tree][ref.Position]
		if !ok {
			return nil, fmt.Errorf("store has no node %+v", ref)
		}
		if replacement, ok := s.override[ref]; ok {
			hash = replacement
		}
		nodes = append(nodes, hpp.ProofNode{Ref: ref, Hash: hash})
	}
	return nodes, nil
}

func (s *store) resetCalls() {
	s.mu.Lock()
	s.calls = nil
	s.mu.Unlock()
}

// fetchedRefs flattens the logged calls.
func (s *store) fetchedRefs() []hpp.NodeRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []hpp.NodeRef
	for _, call := range s.calls {
		all = append(all, call...)
	}
	return all
}

// scenario is one failed audit over a forest.
type scenario struct {
	forest    forest
	store     *store
	hpp       *hpp.Service
	addresses []hpp.PhysicalAddress
	reference hpp.VerificationResult
	failed    hpp.HMFProof
	auditor   [32]byte
}

// newScenario requests addresses, builds the reference proof from the store and
// derives the failed proof by corrupting the leaf hash of every tampered
// address.
func newScenario(t testing.TB, f forest, addresses, tampered []hpp.PhysicalAddress) scenario {
	t.Helper()
	st := newStore(f)
	service, err := hpp.NewService(st, st)
	if err != nil {
		t.Fatalf("new HPP service: %v", err)
	}
	reference, err := service.BuildAndVerify(context.Background(), addresses, f.root)
	if err != nil {
		t.Fatalf("build reference proof: %v", err)
	}
	failed := cloneProof(reference.Proof)
	for _, address := range tampered {
		changed := false
		for index := range failed.Leaves {
			if failed.Leaves[index].Address == address {
				failed.Leaves[index].Hash[0] ^= 0xff
				changed = true
			}
		}
		if !changed {
			t.Fatalf("tampered address %+v is not requested", address)
		}
	}
	root, err := hpp.VerifyHMFProof(failed, addresses)
	if err != nil {
		t.Fatalf("calculate failed root: %v", err)
	}
	st.resetCalls()
	return scenario{forest: f, store: st, hpp: service, addresses: addresses,
		reference: reference, failed: failed, auditor: root}
}

func (sc scenario) request(strategy Strategy) Request {
	return Request{Addresses: sc.addresses, AuditorGlobalRoot: sc.auditor, FailedProof: sc.failed,
		AnchoredGlobalRoot: sc.forest.root, Strategy: strategy}
}

// fixedClock never advances, which disables the observed-time calibration and
// makes every ACHP run reproducible.
func fixedClock() func() time.Time {
	epoch := time.Unix(0, 0)
	return func() time.Time { return epoch }
}

func deterministicService(t testing.TB, reference ReferenceBuilder, mutate func(*ACHPConfig)) *Service {
	t.Helper()
	config := DefaultACHPConfig()
	config.Now = fixedClock()
	if mutate != nil {
		mutate(&config)
	}
	service, err := NewService(reference, WithACHPConfig(config))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

func localizeOK(t testing.TB, service *Service, sc scenario, strategy Strategy) Result {
	t.Helper()
	result, err := service.Localize(context.Background(), sc.request(strategy))
	if err != nil {
		t.Fatalf("localize (%s): %v", strategy, err)
	}
	if err := VerifyProof(result.Proof, sc.addresses, sc.forest.root); err != nil {
		t.Fatalf("verify %s proof: %v", result.Proof.Strategy, err)
	}
	return result
}

// pickAddresses selects n addresses spread deterministically over the forest.
func pickAddresses(f forest, n, stride, offset int) []hpp.PhysicalAddress {
	var result []hpp.PhysicalAddress
	for index := 0; len(result) < n; index++ {
		result = append(result, f.addresses[(offset+index*stride)%len(f.addresses)])
	}
	slices.SortFunc(result, func(left, right hpp.PhysicalAddress) int {
		return slices.Compare(addressKey(left), addressKey(right))
	})
	return slices.CompactFunc(result, func(left, right hpp.PhysicalAddress) bool { return left == right })
}

func addressKey(a hpp.PhysicalAddress) []int64 {
	region := int64(0)
	for _, r := range a.RegionID {
		region = region*31 + int64(r)
	}
	return []int64{region, a.ShardID, a.SegmentID, a.LeafID}
}
