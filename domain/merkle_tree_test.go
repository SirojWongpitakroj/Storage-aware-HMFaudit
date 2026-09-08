package domain

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func hashLeaf(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

// buildExpectedRoot mirrors the intended Merkle construction so the tests
// have an independent reference to check BuildSegmentTree against: pair up
// nodes level by level, promoting a lone left node unchanged.
func buildExpectedRoot(leaves [][32]byte) [32]byte {
	level := make([][32]byte, len(leaves))
	copy(level, leaves)

	for len(level) > 1 {
		var next [][32]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 >= len(level) {
				next = append(next, level[i])
				break
			}
			l, r := level[i], level[i+1]
			next = append(next, HashPair(&l, &r))
		}
		level = next
	}
	return level[0]
}

// insertAll inserts every leaf and returns the raw hashes for reference checks.
func insertAll(tree *SegmentTree, names ...string) [][32]byte {
	hashes := make([][32]byte, 0, len(names))
	for _, n := range names {
		h := hashLeaf(n)
		tree.InsertLog(h)
		hashes = append(hashes, h)
	}
	return hashes
}

// safeBuild runs BuildSegmentTree, turning a panic into a test failure
// instead of crashing the whole test binary.
func safeBuild(t *testing.T, tree *SegmentTree) [32]byte {
	t.Helper()
	var root [32]byte
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BuildSegmentTree panicked: %v", r)
		}
	}()
	root = tree.BuildSegmentTree()
	return root
}

func TestNewMerkleTreeDefaults(t *testing.T) {
	tree := NewMerkleTree(32768)

	if tree.MaxLeaves != 32768 {
		t.Errorf("expected MaxLeaves 32768, got %d", tree.MaxLeaves)
	}
	if len(tree.Nodes) != 1 {
		t.Fatalf("expected exactly the leaf level, got %d levels", len(tree.Nodes))
	}
	if len(tree.Nodes[0]) != 0 {
		t.Errorf("expected no leaves initially, got %d", len(tree.Nodes[0]))
	}
}

func TestInsertLogAppendsInOrder(t *testing.T) {
	tree := NewMerkleTree(32768)
	want := insertAll(tree, "leaf-1", "leaf-2", "leaf-3", "leaf-4")

	if len(tree.Nodes[0]) != len(want) {
		t.Fatalf("expected %d leaves, got %d", len(want), len(tree.Nodes[0]))
	}
	for i, h := range want {
		if !bytes.Equal(tree.Nodes[0][i].Hash[:], h[:]) {
			t.Errorf("leaf %d: got %x, want %x", i, tree.Nodes[0][i].Hash, h)
		}
	}
}

func TestInsertLogRespectsMaxLeaves(t *testing.T) {
	tree := NewMerkleTree(2)

	tree.InsertLog(hashLeaf("a"))
	tree.InsertLog(hashLeaf("b"))
	tree.InsertLog(hashLeaf("c")) // over capacity, should be dropped

	if len(tree.Nodes[0]) != 2 {
		t.Fatalf("expected leaves capped at 2, got %d", len(tree.Nodes[0]))
	}

	a, b := hashLeaf("a"), hashLeaf("b")
	if !bytes.Equal(tree.Nodes[0][0].Hash[:], a[:]) || !bytes.Equal(tree.Nodes[0][1].Hash[:], b[:]) {
		t.Errorf("unexpected leaf contents after hitting cap: %x, %x",
			tree.Nodes[0][0].Hash, tree.Nodes[0][1].Hash)
	}
}

func TestBuildSegmentTreeTwoLeaves(t *testing.T) {
	tree := NewMerkleTree(32768)
	leaves := insertAll(tree, "x", "y")

	root := safeBuild(t, tree)

	l1, l2 := leaves[0], leaves[1]
	want := HashPair(&l1, &l2)
	if !bytes.Equal(root[:], want[:]) {
		t.Errorf("root mismatch\n got %x\nwant %x", root, want)
	}
}

func TestBuildSegmentTreeFourLeaves(t *testing.T) {
	tree := NewMerkleTree(32768)
	leaves := insertAll(tree, "leaf-1", "leaf-2", "leaf-3", "leaf-4")

	root := safeBuild(t, tree)

	want := buildExpectedRoot(leaves)
	if !bytes.Equal(root[:], want[:]) {
		t.Errorf("root mismatch\n got %x\nwant %x", root, want)
	}
}

func TestBuildSegmentTreeOddLeaves(t *testing.T) {
	tree := NewMerkleTree(32768)
	leaves := insertAll(tree, "leaf-1", "leaf-2", "leaf-3", "leaf-4", "leaf-5")

	root := safeBuild(t, tree)

	want := buildExpectedRoot(leaves)
	if !bytes.Equal(root[:], want[:]) {
		t.Errorf("root mismatch\n got %x\nwant %x", root, want)
	}
}
