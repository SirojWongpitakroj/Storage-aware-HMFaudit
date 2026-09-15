package tests

import (
	"crypto/sha256"
	"math/bits"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/domain"
	"github.com/SirojWongpitakroj/hmf-audit/internal/hmf"
)

func TestSegmentTreeAppendTracksLeafCount(t *testing.T) {
	tree := hmf.NewSegmentTree("R1", 2, 3, 4)

	if tree.TreeID.Type != hmf.TreeSegment || tree.TreeID.RegionID != "R1" || tree.TreeID.ShardID != 2 || tree.TreeID.SegmentID != 3 {
		t.Fatalf("unexpected segment tree identity: %+v", tree.TreeID)
	}

	if err := tree.Append(testHash("log-1")); err != nil {
		t.Fatalf("append first log: %v", err)
	}
	if err := tree.Append(testHash("log-2")); err != nil {
		t.Fatalf("append second log: %v", err)
	}
	if tree.LeafCount != 2 {
		t.Fatalf("leaf count = %d, want 2", tree.LeafCount)
	}

	tree.Sealed = true
	if err := tree.Append(testHash("after-seal")); err == nil {
		t.Fatal("append to a sealed segment succeeded")
	}
}

func TestShardTreeAppendUsesPromotion(t *testing.T) {
	tree := hmf.NewShardTree("R1", 2)
	hashes := []([32]byte){
		testHash("segment-a"),
		testHash("segment-b"),
		testHash("segment-c"),
		testHash("segment-d"),
		testHash("segment-e"),
	}

	for index, hash := range hashes {
		if err := tree.Append(hash); err != nil {
			t.Fatalf("append segment %d: %v", index, err)
		}

		wantRoot := merkleRoot(hashes[:index+1])
		if tree.Root != wantRoot {
			t.Fatalf("after %d leaves root = %x, want %x", index+1, tree.Root, wantRoot)
		}

		wantHeight := bits.Len(uint(index))
		if tree.Height != wantHeight {
			t.Fatalf("after %d leaves height = %d, want %d", index+1, tree.Height, wantHeight)
		}
	}
}

func TestRegionTreeBuild(t *testing.T) {
	hashes := []([32]byte){
		testHash("shard-0"),
		testHash("shard-1"),
		testHash("shard-2"),
		testHash("shard-3"),
		testHash("shard-4"),
	}
	tree := hmf.NewRegionTree("R1", len(hashes))

	updates, err := tree.Build(hashes)
	if err != nil {
		t.Fatalf("build region tree: %v", err)
	}

	assertBuiltTree(t, tree.MerkleTree, updates, hashes)
	if tree.TreeID.Type != hmf.TreeRegion || tree.TreeID.RegionID != "R1" {
		t.Fatalf("unexpected region tree identity: %+v", tree.TreeID)
	}
}

func TestGlobalTreeBuild(t *testing.T) {
	hashes := []([32]byte){
		testHash("region-0"),
		testHash("region-1"),
		testHash("region-2"),
	}
	tree := hmf.NewGlobalTree(len(hashes))

	updates, err := tree.Build(hashes)
	if err != nil {
		t.Fatalf("build global tree: %v", err)
	}

	assertBuiltTree(t, tree.MerkleTree, updates, hashes)
	if tree.TreeID.Type != hmf.TreeGlobal {
		t.Fatalf("tree type = %q, want %q", tree.TreeID.Type, hmf.TreeGlobal)
	}
}

func TestRegionAndGlobalBuildRejectWrongLeafCount(t *testing.T) {
	if _, err := hmf.NewRegionTree("R1", 2).Build([]([32]byte){testHash("only-one")}); err == nil {
		t.Fatal("region build accepted the wrong number of shard roots")
	}
	if _, err := hmf.NewGlobalTree(2).Build([]([32]byte){testHash("only-one")}); err == nil {
		t.Fatal("global build accepted the wrong number of region roots")
	}
}

func assertBuiltTree(t *testing.T, tree *hmf.MerkleTree, updates []hmf.MerkleNode, leaves [][32]byte) {
	t.Helper()

	wantRoot := merkleRoot(leaves)
	if tree.Root != wantRoot {
		t.Fatalf("root = %x, want %x", tree.Root, wantRoot)
	}

	wantHeight := bits.Len(uint(len(leaves) - 1))
	if tree.Height != wantHeight {
		t.Fatalf("height = %d, want %d", tree.Height, wantHeight)
	}

	if len(updates) != merkleNodeCount(len(leaves)) {
		t.Fatalf("update count = %d, want %d", len(updates), merkleNodeCount(len(leaves)))
	}
}

func merkleRoot(nodes [][32]byte) [32]byte {
	current := append([][32]byte(nil), nodes...)
	for len(current) > 1 {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for index := 0; index < len(current); index += 2 {
			if index+1 == len(current) {
				next = append(next, current[index])
				continue
			}
			next = append(next, domain.HashPair("NODE", &current[index], &current[index+1]))
		}
		current = next
	}
	return current[0]
}

func merkleNodeCount(leafCount int) int {
	count := 0
	for leafCount > 0 {
		count += leafCount
		leafCount = (leafCount + 1) / 2
		if leafCount == 1 {
			count++
			break
		}
	}
	return count
}

func testHash(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}
