package cassandra

import (
	"math/rand"
	"slices"
	"sort"
	"testing"

	"github.com/SirojWongpitakroj/hmf-audit/internal/hpp"
)

func proofNode(layer hpp.TreeLayer, region string, shard, segment int64, level int32, index int64, fill byte) hpp.ProofNode {
	return hpp.ProofNode{
		Ref: hpp.NodeRef{
			Tree:     hpp.TreeRef{Layer: layer, RegionID: region, ShardID: shard, SegmentID: segment},
			Position: hpp.NodePosition{Level: level, Index: index},
		},
		Hash: [32]byte{fill},
	}
}

// oldSortOrder is the comparator the reader sorted its nodes with before the sort was moved to
// slices.SortFunc; the canonical order must not have changed.
func oldSortOrder(result []hpp.ProofNode) {
	sort.Slice(result, func(left, right int) bool {
		leftRef, rightRef := result[left].Ref, result[right].Ref
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
}

func TestCanonicalNodeOrderIsUnchanged(t *testing.T) {
	random := rand.New(rand.NewSource(3))
	var nodes []hpp.ProofNode
	seen := map[hpp.NodeRef]bool{}
	for len(nodes) < 3000 {
		node := proofNode(hpp.TreeLayer(1+random.Intn(4)), []string{"R0", "R1", "R2"}[random.Intn(3)],
			int64(random.Intn(3)), int64(random.Intn(4)), int32(random.Intn(6)), int64(random.Intn(50)), 0)
		if !seen[node.Ref] {
			seen[node.Ref] = true
			nodes = append(nodes, node)
		}
	}
	want := slices.Clone(nodes)
	oldSortOrder(want)
	got := slices.Clone(nodes)
	slices.SortFunc(got, compareProofNodes)
	if !slices.Equal(got, want) {
		t.Fatal("slices.SortFunc(compareProofNodes) orders nodes differently from the old comparator")
	}
}

func TestDropIdenticalDuplicates(t *testing.T) {
	a := proofNode(hpp.LayerSegment, "R0", 0, 1, 0, 5, 1)
	b := proofNode(hpp.LayerSegment, "R0", 0, 1, 0, 6, 2)
	got, err := dropIdenticalDuplicates([]hpp.ProofNode{a, a, b, b, b})
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("got %v, %v; want the two distinct nodes", got, err)
	}
	conflict := a
	conflict.Hash = [32]byte{9}
	if _, err := dropIdenticalDuplicates([]hpp.ProofNode{a, conflict}); err == nil {
		t.Fatal("two hashes for one node were accepted")
	}
}

func TestCheckAllPresent(t *testing.T) {
	tree := hpp.TreeRef{Layer: hpp.LayerSegment, RegionID: "R0", ShardID: 0, SegmentID: 2}
	partition := nodePartition{tree: tree}
	partition.add(0, []int64{1, 4, 9})
	partition.add(2, []int64{0, 3})
	node := func(level int32, index int64) hpp.ProofNode {
		return hpp.ProofNode{Ref: hpp.NodeRef{Tree: tree, Position: hpp.NodePosition{Level: level, Index: index}}}
	}
	all := []hpp.ProofNode{node(0, 1), node(0, 4), node(0, 9), node(2, 0), node(2, 3)}
	if err := partition.checkAllPresent(all); err != nil {
		t.Fatalf("complete answer rejected: %v", err)
	}
	if err := partition.checkAllPresent([]hpp.ProofNode{all[4], all[2], all[0], all[3], all[1]}); err != nil {
		t.Fatalf("complete but unordered answer rejected: %v", err)
	}
	for drop := range all {
		missing := slices.Delete(slices.Clone(all), drop, drop+1)
		if err := partition.checkAllPresent(missing); err == nil {
			t.Fatalf("answer without %+v accepted", all[drop].Ref.Position)
		}
	}
	// A key listed twice (the no-dedup ablation) is satisfied by the one row Cassandra returns for it.
	repeated := nodePartition{tree: tree}
	repeated.add(0, []int64{4, 4, 4})
	if err := repeated.checkAllPresent([]hpp.ProofNode{node(0, 4)}); err != nil {
		t.Fatalf("repeated key rejected: %v", err)
	}
}
