package hpp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
)

// This file pins the HPP proof builder and verifier: a deterministic forest, fixed address sets, and
// a digest of everything BuildAndVerify returns (plan, leaves, nodes, root). A change that only
// affects speed or allocation must leave every digest unchanged.

type forestFixture struct {
	metadata HierarchyMetadata
	nodes    map[TreeRef]map[NodePosition][32]byte
	root     [32]byte
	shuffle  bool // return fetched nodes in a scrambled order, as a reader that does not sort would
	sorted   bool // return fetched nodes in canonical order, as the Cassandra reader does
}

func (f forestFixture) LoadHierarchyMetadata(context.Context, []PhysicalAddress) (HierarchyMetadata, error) {
	return f.metadata, nil
}

func (f forestFixture) FetchProofNodes(_ context.Context, plan ProofPlan) ([]ProofNode, error) {
	var result []ProofNode
	for _, tree := range plan.Trees {
		for _, position := range tree.Required {
			result = append(result, ProofNode{Ref: NodeRef{Tree: tree.Tree, Position: position}, Hash: f.nodes[tree.Tree][position]})
		}
	}
	for _, address := range plan.Addresses {
		tree := TreeRef{Layer: LayerSegment, RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
		position := NodePosition{Level: 0, Index: address.LeafID}
		result = append(result, ProofNode{Ref: NodeRef{Tree: tree, Position: position}, Hash: f.nodes[tree][position]})
	}
	if f.sorted {
		slices.SortFunc(result, func(left, right ProofNode) int { return compareNodeRefs(left.Ref, right.Ref) })
	}
	if f.shuffle {
		random := rand.New(rand.NewSource(7))
		random.Shuffle(len(result), func(i, j int) { result[i], result[j] = result[j], result[i] })
	}
	return result, nil
}

func fixtureDigest(label string, index int64) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%s-%d", label, index)))
}

func buildTree(leaves [][32]byte) ([32]byte, map[NodePosition][32]byte) {
	nodes := make(map[NodePosition][32]byte, 2*len(leaves))
	current := append([][32]byte(nil), leaves...)
	for index, hash := range current {
		nodes[NodePosition{Level: 0, Index: int64(index)}] = hash
	}
	var level int32
	for len(current) > 1 {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for index := 0; index < len(current); index += 2 {
			hash := current[index]
			if index+1 < len(current) {
				hash = domain.HashPair("NODE", &current[index], &current[index+1])
			}
			next = append(next, hash)
			nodes[NodePosition{Level: level + 1, Index: int64(index / 2)}] = hash
		}
		current = next
		level++
	}
	return current[0], nodes
}

const (
	fixtureRegions         = 2
	fixtureShardsPerRegion = 2
	fixtureSegmentsPerShrd = 3
	fixtureLeavesPerSeg    = 1000 // not a power of two, so odd widths are covered
)

func newForestFixture() forestFixture {
	fixture := forestFixture{
		metadata: HierarchyMetadata{
			Segments: map[SegmentKey]SegmentMetadata{}, Shards: map[ShardKey]UpperTreeMetadata{},
			Regions: map[string]UpperTreeMetadata{},
		},
		nodes: map[TreeRef]map[NodePosition][32]byte{},
	}
	var regionRoots [][32]byte
	for region := 0; region < fixtureRegions; region++ {
		regionID := fmt.Sprintf("R%d", region)
		var shardRoots [][32]byte
		for shard := int64(0); shard < fixtureShardsPerRegion; shard++ {
			var segmentRoots [][32]byte
			for segment := int64(0); segment < fixtureSegmentsPerShrd; segment++ {
				leaves := make([][32]byte, fixtureLeavesPerSeg)
				for leaf := range leaves {
					leaves[leaf] = fixtureDigest(fmt.Sprintf("%s/%d/%d", regionID, shard, segment), int64(leaf))
				}
				raw, nodes := buildTree(leaves)
				key := SegmentKey{RegionID: regionID, ShardID: shard, SegmentID: segment}
				fixture.nodes[segmentTree(key)] = nodes
				fixture.metadata.Segments[key] = SegmentMetadata{LeafCount: fixtureLeavesPerSeg, ShardLeafIndex: segment, Sealed: true}
				segmentRoots = append(segmentRoots, hmf.CommitSegmentRoot(regionID, shard, segment, fixtureLeavesPerSeg, raw))
			}
			raw, nodes := buildTree(segmentRoots)
			shardKey := ShardKey{RegionID: regionID, ShardID: shard}
			fixture.nodes[shardTree(shardKey)] = nodes
			fixture.metadata.Shards[shardKey] = UpperTreeMetadata{LeafCount: fixtureSegmentsPerShrd, ParentLeafIndex: shard}
			shardRoots = append(shardRoots, hmf.CommitShardRoot(regionID, shard, fixtureSegmentsPerShrd, raw))
		}
		raw, nodes := buildTree(shardRoots)
		fixture.nodes[regionTree(regionID)] = nodes
		fixture.metadata.Regions[regionID] = UpperTreeMetadata{LeafCount: fixtureShardsPerRegion, ParentLeafIndex: int64(region)}
		regionRoots = append(regionRoots, hmf.CommitRegionRoot(regionID, fixtureShardsPerRegion, raw))
	}
	raw, nodes := buildTree(regionRoots)
	fixture.nodes[globalTree()] = nodes
	fixture.metadata.Global = UpperTreeMetadata{LeafCount: fixtureRegions}
	fixture.root = hmf.CommitGlobalRoot(fixtureRegions, raw)
	return fixture
}

// addressSets returns named, deterministic address sets: one leaf, a contiguous run, a run that
// crosses a segment, scattered leaves over every tree, an unsorted input with duplicates.
func addressSets() map[string][]PhysicalAddress {
	addr := func(region int, shard, segment, leaf int64) PhysicalAddress {
		return PhysicalAddress{RegionID: fmt.Sprintf("R%d", region), ShardID: shard, SegmentID: segment, LeafID: leaf}
	}
	sets := map[string][]PhysicalAddress{"single": {addr(0, 0, 0, 5)}}
	var run, crossing, scattered, messy []PhysicalAddress
	for leaf := int64(100); leaf < 612; leaf++ {
		run = append(run, addr(0, 0, 1, leaf))
	}
	for leaf := int64(700); leaf < 1000; leaf++ {
		crossing = append(crossing, addr(1, 1, 0, leaf))
	}
	for leaf := int64(0); leaf < 200; leaf++ {
		crossing = append(crossing, addr(1, 1, 1, leaf))
	}
	random := rand.New(rand.NewSource(42))
	for i := 0; i < 1500; i++ {
		scattered = append(scattered, addr(random.Intn(fixtureRegions), int64(random.Intn(fixtureShardsPerRegion)),
			int64(random.Intn(fixtureSegmentsPerShrd)), int64(random.Intn(fixtureLeavesPerSeg))))
	}
	messy = append(messy, scattered[:300]...)
	messy = append(messy, scattered[:100]...) // duplicates
	random.Shuffle(len(messy), func(i, j int) { messy[i], messy[j] = messy[j], messy[i] })
	sets["run"], sets["crossing"], sets["scattered"], sets["messy"] = run, crossing, scattered, messy
	return sets
}

// proofDigest hashes everything a proof contains, in order.
func proofDigest(result VerificationResult) [32]byte {
	hash := sha256.New()
	put := func(values ...int64) {
		for _, value := range values {
			var buf [8]byte
			binary.BigEndian.PutUint64(buf[:], uint64(value))
			hash.Write(buf[:])
		}
	}
	str := func(value string) { put(int64(len(value))); hash.Write([]byte(value)) }
	ref := func(tree TreeRef) { put(int64(tree.Layer), tree.ShardID, tree.SegmentID); str(tree.RegionID) }
	proof := result.Proof
	for _, address := range proof.Plan.Addresses {
		str(address.RegionID)
		put(address.ShardID, address.SegmentID, address.LeafID)
	}
	for _, tree := range proof.Plan.Trees {
		ref(tree.Tree)
		put(tree.LeafCount, int64(len(tree.Targets)), int64(len(tree.Required)))
		put(tree.Targets...)
		for _, position := range tree.Required {
			put(int64(position.Level), position.Index)
		}
		put(tree.RequiredOccurrences...)
	}
	for _, link := range proof.Plan.ParentLinks {
		ref(link.Child)
		ref(link.Parent)
		put(link.ParentLeafIndex)
	}
	for _, request := range proof.Plan.SegmentRequests {
		ref(request.Tree)
		put(int64(request.Level))
		put(request.NodeIndexes...)
	}
	for _, request := range proof.Plan.UpperRequests {
		ref(request.Tree)
		str(request.ScopeType)
		str(request.ScopeID)
		put(request.BucketID, int64(request.Level))
		put(request.NodeIndexes...)
	}
	for _, leaf := range proof.Leaves {
		str(leaf.Address.RegionID)
		put(leaf.Address.ShardID, leaf.Address.SegmentID, leaf.Address.LeafID)
		hash.Write(leaf.Hash[:])
	}
	for _, node := range proof.Nodes {
		ref(node.Ref.Tree)
		put(int64(node.Ref.Position.Level), node.Ref.Position.Index)
		hash.Write(node.Hash[:])
	}
	hash.Write(result.CalculatedGlobalRoot[:])
	var out [32]byte
	copy(out[:], hash.Sum(nil))
	return out
}

// goldenProofDigests are the digests of the unoptimized implementation, for a reader that returns
// nodes in canonical order and for one that returns them scrambled (the proof then keeps the
// reader's order for its authentication nodes, so the two differ).
var goldenProofDigests = map[string]string{
	"crossing":           "de7f65f8898b5814b3f52e592345c558bb320d0fb6b39b847bd07c004ba5e13c",
	"messy":              "deb6c48df3562833191d4f781fa67f9de05f0471a2bc2ae81110b3e655aadc21",
	"run":                "c8b5481b3f7fd32249ba40e041c75f0088da478d4913d3f7fb805bf4bb5c65a2",
	"scattered":          "fe02f0140cd60929f39adfcfef2041442f7524cbf91e151575d4808c17f4e62d",
	"single":             "d53c3cfc00d87478938efed587da49e376f297dcd5bdd637a5ccbccc623ca46e",
	"crossing/shuffled":  "d319b63d7d9763e24a6406814895a93cecb08c4bf542c46656f33d50487911f0",
	"messy/shuffled":     "e6093971a130f91df61279398f9bb0a2f8343eb0e2848236931743bb3fbf47ef",
	"run/shuffled":       "d489711741d53d601d7e1e3a582acef254fb48918a89b1a020f1512c7836f39f",
	"scattered/shuffled": "cd0daeb2c616f26adf1fd6a132d8e60cd2266ad54bb91be9d65c363cd14ceb80",
	"single/shuffled":    "efe5a52d58993e2980a98e98a79bce19b618652d23b54bb0de3f6322148b84f5",
}

func TestProofDigestsStayIdentical(t *testing.T) {
	fixture := newForestFixture()
	sets := addressSets()
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, shuffle := range []bool{false, true} {
		fixture.shuffle = shuffle
		service, err := NewService(fixture, fixture)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			result, err := service.BuildAndVerify(context.Background(), sets[name], fixture.root)
			if err != nil {
				t.Fatalf("%s (shuffle=%v): %v", name, shuffle, err)
			}
			got := fmt.Sprintf("%x", proofDigest(result))
			key := name
			if shuffle {
				key += "/shuffled"
			}
			want, known := goldenProofDigests[key]
			if !known {
				t.Fatalf("no golden digest for %q: %q", key, got)
			}
			if got != want {
				t.Errorf("%s (shuffle=%v): proof digest %s, want %s", name, shuffle, got, want)
			}
		}
	}
}

// TestTamperedProofsAreRejected: a wrong leaf hash, a wrong or missing authentication node and a
// wrong root all fail verification.
func TestTamperedProofsAreRejected(t *testing.T) {
	fixture := newForestFixture()
	service, err := NewService(fixture, fixture)
	if err != nil {
		t.Fatal(err)
	}
	addresses := addressSets()["scattered"]
	proof, err := service.BuildProof(context.Background(), addresses)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyHMFProofAgainstRoot(proof, addresses, fixture.root); err != nil {
		t.Fatalf("untampered proof rejected: %v", err)
	}
	clone := func() HMFProof {
		copyProof := proof
		copyProof.Leaves = append([]RequestedLeaf(nil), proof.Leaves...)
		copyProof.Nodes = append([]ProofNode(nil), proof.Nodes...)
		return copyProof
	}
	wrongLeaf := clone()
	wrongLeaf.Leaves[len(wrongLeaf.Leaves)/2].Hash[0] ^= 1
	wrongNode := clone()
	wrongNode.Nodes[len(wrongNode.Nodes)/3].Hash[5] ^= 1
	missingNode := clone()
	missingNode.Nodes = missingNode.Nodes[1:]
	extraNode := clone()
	extraNode.Nodes = append(extraNode.Nodes, extraNode.Nodes[0])
	for name, tampered := range map[string]HMFProof{"leaf": wrongLeaf, "node": wrongNode, "missing": missingNode, "extra": extraNode} {
		if _, err := VerifyHMFProofAgainstRoot(tampered, addresses, fixture.root); err == nil {
			t.Errorf("tampered %s accepted", name)
		}
	}
	other := fixture.root
	other[0] ^= 1
	if _, err := VerifyHMFProofAgainstRoot(proof, addresses, other); err == nil {
		t.Error("wrong trusted root accepted")
	}
}

func BenchmarkBuildAndVerifyScattered(b *testing.B) {
	fixture := newForestFixture()
	fixture.sorted = true
	service, err := NewService(fixture, fixture)
	if err != nil {
		b.Fatal(err)
	}
	addresses := addressSets()["scattered"]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := service.BuildAndVerify(context.Background(), addresses, fixture.root); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildAndVerifyRun(b *testing.B) {
	fixture := newForestFixture()
	fixture.sorted = true
	service, err := NewService(fixture, fixture)
	if err != nil {
		b.Fatal(err)
	}
	addresses := addressSets()["run"]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := service.BuildAndVerify(context.Background(), addresses, fixture.root); err != nil {
			b.Fatal(err)
		}
	}
}

// TestSortedSplitMatchesMapSplit: on nodes in canonical order, the merge-walk split returns exactly
// what the map-based split returns, leaves and authentication nodes alike.
func TestSortedSplitMatchesMapSplit(t *testing.T) {
	fixture := newForestFixture()
	fixture.sorted = true
	for name, addresses := range addressSets() {
		normalized, err := normalizeAddresses(addresses)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := NewPlanner().Plan(normalized, fixture.metadata)
		if err != nil {
			t.Fatal(err)
		}
		nodes, err := fixture.FetchProofNodes(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		wantLeaves, wantRest, err := splitTargetLeavesByMap(plan.Addresses, nodes)
		if err != nil {
			t.Fatal(err)
		}
		gotLeaves, gotRest, ok := splitSortedTargetLeaves(plan.Addresses, nodes)
		if !ok {
			t.Fatalf("%s: sorted split declined canonical input", name)
		}
		if !slices.Equal(gotLeaves, wantLeaves) || !slices.Equal(gotRest, wantRest) {
			t.Fatalf("%s: sorted split differs from the map split", name)
		}
		// A dropped leaf makes the walk decline, so the map split reports it.
		first := plan.Addresses[0]
		leafRef := NodeRef{Tree: segmentTree(SegmentKey{RegionID: first.RegionID, ShardID: first.ShardID, SegmentID: first.SegmentID}),
			Position: NodePosition{Level: 0, Index: first.LeafID}}
		without := slices.DeleteFunc(slices.Clone(nodes), func(node ProofNode) bool { return node.Ref == leafRef })
		if len(without) == len(nodes) {
			t.Fatalf("%s: leaf node %+v not found", name, leafRef)
		}
		if _, _, ok := splitSortedTargetLeaves(plan.Addresses, without); ok {
			t.Fatalf("%s: sorted split accepted a missing leaf", name)
		}
		if _, _, err := splitTargetLeaves(plan.Addresses, without); err == nil {
			t.Fatalf("%s: split accepted a missing leaf", name)
		}
	}
}
