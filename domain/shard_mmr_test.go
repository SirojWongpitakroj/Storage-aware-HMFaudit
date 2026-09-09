package domain

import (
	"bytes"
	"math/bits"
	"testing"
)

// The user asked for a test file for shard_mmr.go. merkle_tree_test.go is
// already taken by the SegmentTree tests, so the ShardTree / MMR tests live
// here. hashLeaf is shared from merkle_tree_test.go (same package).

// ---------------------------------------------------------------------------
// Independent reference implementation
// ---------------------------------------------------------------------------

// mmrPeak mirrors the unexported peak{height,index} pair so the reference
// model can describe the expected peak set without touching internals.
type mmrPeak struct {
	height int
	index  int
}

// referenceMMR rebuilds, from scratch, what ShardTree.Nodes and the peak
// stack are expected to contain after appending leaves in order.
//
// It applies the same rule Append/merge use: whenever the two right-most
// peaks share a height, they are replaced one height up by
// HashPair(older, newer) with the older (left) peak as the first argument.
//
// The returned peaks slice is in stack order: index 0 is the bottom of the
// stack (the oldest / left-most / tallest peak), the last entry is the top.
func referenceMMR(leaves [][32]byte) (nodes [][][32]byte, peaks []mmrPeak) {
	nodes = [][][32]byte{{}}

	for _, leaf := range leaves {
		nodes[0] = append(nodes[0], leaf)
		cand := mmrPeak{height: 0, index: len(nodes[0]) - 1}

		for len(peaks) > 0 && peaks[len(peaks)-1].height == cand.height {
			older := peaks[len(peaks)-1]
			peaks = peaks[:len(peaks)-1]

			nh := cand.height + 1
			for len(nodes) <= nh {
				nodes = append(nodes, nil)
			}
			l := nodes[older.height][older.index]
			r := nodes[cand.height][cand.index]
			nodes[nh] = append(nodes[nh], HashPair(&l, &r))
			cand = mmrPeak{height: nh, index: len(nodes[nh]) - 1}
		}
		peaks = append(peaks, cand)
	}
	return nodes, peaks
}

// peakHashes returns the hash of every peak, left-most (tallest) first.
func peakHashes(leaves [][32]byte) [][32]byte {
	nodes, peaks := referenceMMR(leaves)
	out := make([][32]byte, len(peaks))
	for i, p := range peaks {
		out[i] = nodes[p.height][p.index]
	}
	return out
}

// referenceRoot bags the peaks the same way ShardTree.Root does: seed with
// the left-most (tallest) peak, then fold every remaining peak in on the
// left, moving rightwards:
//
//	h = p0
//	h = HashPair(p1, h)
//	h = HashPair(p2, h)
//	...
//
// so the right-most (most recent) peak ends up outermost. A single peak is
// returned unchanged; an empty tree is the zero hash.
func referenceRoot(leaves [][32]byte) [32]byte {
	peaks := peakHashes(leaves)
	if len(peaks) == 0 {
		return [32]byte{}
	}
	h := peaks[0]
	for i := 1; i < len(peaks); i++ {
		p := peaks[i]
		h = HashPair(&p, &h)
	}
	return h
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func names(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "leaf-" + string(rune('A'+i%26)) + string(rune('0'+i/26))
	}
	return out
}

// safeAppend appends one segment, turning a panic into a test failure with a
// clear message instead of crashing the whole binary.
func safeAppend(t *testing.T, tree *ShardTree, seg *SegmentNode) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ShardTree.Append panicked: %v", r)
		}
	}()
	tree.Append(seg)
}

// appendNamed appends one leaf per name and returns the raw leaf hashes.
func appendNamed(t *testing.T, tree *ShardTree, names ...string) [][32]byte {
	t.Helper()
	hashes := make([][32]byte, 0, len(names))
	for _, n := range names {
		h := hashLeaf(n)
		safeAppend(t, tree, &SegmentNode{Hash: h})
		hashes = append(hashes, h)
	}
	return hashes
}

// buildTree is a convenience that builds a fresh tree from n distinct leaves.
func buildTree(t *testing.T, n int) (*ShardTree, [][32]byte) {
	t.Helper()
	tree := NewShardMMR()
	leaves := appendNamed(t, tree, names(n)...)
	return tree, leaves
}

func safeRoot(t *testing.T, tree *ShardTree) [32]byte {
	t.Helper()
	var root [32]byte
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ShardTree.Root panicked: %v", r)
		}
	}()
	root = tree.Root()
	return root
}

// assertNodes checks tree.Nodes against the reference model in full: number
// of height levels, count per level, each hash and each Height field.
func assertNodes(t *testing.T, tree *ShardTree, leaves [][32]byte) {
	t.Helper()
	want, _ := referenceMMR(leaves)

	if len(tree.Nodes) != len(want) {
		t.Fatalf("Nodes: got %d height levels, want %d", len(tree.Nodes), len(want))
	}
	for h := range want {
		if len(tree.Nodes[h]) != len(want[h]) {
			t.Fatalf("Nodes height %d: got %d nodes, want %d",
				h, len(tree.Nodes[h]), len(want[h]))
		}
		for i := range want[h] {
			got := tree.Nodes[h][i]
			if !bytes.Equal(got.Hash[:], want[h][i][:]) {
				t.Errorf("Nodes[%d][%d].Hash: got %x, want %x", h, i, got.Hash, want[h][i])
			}
			if got.Height != h {
				t.Errorf("Nodes[%d][%d].Height: got %d, want %d", h, i, got.Height, h)
			}
		}
	}
}

// assertPeaks checks the peak stack against the reference model. Peaks.Values()
// is LIFO (top first), the reference is bottom first, so one side is reversed.
func assertPeaks(t *testing.T, tree *ShardTree, leaves [][32]byte) {
	t.Helper()
	_, want := referenceMMR(leaves)
	got := tree.Peaks.Values()

	if len(got) != len(want) {
		t.Fatalf("Peaks: got %d peaks, want %d", len(got), len(want))
	}
	for i := range want {
		w := want[len(want)-1-i] // reverse: compare top-first
		if got[i].height != w.height || got[i].index != w.index {
			t.Errorf("Peaks[%d from top]: got {h:%d i:%d}, want {h:%d i:%d}",
				i, got[i].height, got[i].index, w.height, w.index)
		}
	}
}

// ---------------------------------------------------------------------------
// peakStack
// ---------------------------------------------------------------------------

func TestPeakStackPushPopPeek(t *testing.T) {
	s := newPeakStack()

	if s.Size() != 0 {
		t.Fatalf("new stack size: got %d, want 0", s.Size())
	}
	if _, ok := s.Pop(); ok {
		t.Errorf("Pop on empty stack: ok = true, want false")
	}
	if _, ok := s.Peek(); ok {
		t.Errorf("Peek on empty stack: ok = true, want false")
	}

	s.Push(peak{height: 0, index: 0})
	s.Push(peak{height: 1, index: 3})

	if s.Size() != 2 {
		t.Fatalf("size after 2 pushes: got %d, want 2", s.Size())
	}

	if p, ok := s.Peek(); !ok || p != (peak{height: 1, index: 3}) {
		t.Errorf("Peek: got %+v ok=%v, want {1 3} true", p, ok)
	}
	if s.Size() != 2 {
		t.Errorf("Peek must not pop: size %d, want 2", s.Size())
	}

	if p, ok := s.Pop(); !ok || p != (peak{height: 1, index: 3}) {
		t.Errorf("Pop #1: got %+v ok=%v, want {1 3} true", p, ok)
	}
	if p, ok := s.Pop(); !ok || p != (peak{height: 0, index: 0}) {
		t.Errorf("Pop #2: got %+v ok=%v, want {0 0} true", p, ok)
	}
	if _, ok := s.Pop(); ok {
		t.Errorf("Pop past empty: ok = true, want false")
	}
}

func TestPeakStackValuesIsLIFO(t *testing.T) {
	s := newPeakStack()
	s.Push(peak{height: 0, index: 0})
	s.Push(peak{height: 1, index: 1})
	s.Push(peak{height: 2, index: 2})

	vals := s.Values()
	if len(vals) != 3 {
		t.Fatalf("Values length: got %d, want 3", len(vals))
	}
	// Root() relies on Values()[len-1] being the bottom (oldest) peak.
	if vals[0] != (peak{height: 2, index: 2}) {
		t.Errorf("Values()[0] (top): got %+v, want {2 2}", vals[0])
	}
	if vals[len(vals)-1] != (peak{height: 0, index: 0}) {
		t.Errorf("Values()[last] (bottom): got %+v, want {0 0}", vals[len(vals)-1])
	}
}

// ---------------------------------------------------------------------------
// NewShardMMR
// ---------------------------------------------------------------------------

func TestNewShardMMR(t *testing.T) {
	tree := NewShardMMR()

	if tree == nil {
		t.Fatal("NewShardMMR returned nil")
	}
	if len(tree.Nodes) != 1 {
		t.Errorf("fresh tree: got %d height levels, want 1", len(tree.Nodes))
	}
	if len(tree.Nodes[0]) != 0 {
		t.Errorf("fresh tree: got %d leaves, want 0", len(tree.Nodes[0]))
	}
	if tree.Peaks == nil {
		t.Fatal("fresh tree: Peaks is nil")
	}
	if tree.Peaks.Size() != 0 {
		t.Errorf("fresh tree: got %d peaks, want 0", tree.Peaks.Size())
	}
	if tree.NumLeaves != 0 {
		t.Errorf("fresh tree: NumLeaves = %d, want 0", tree.NumLeaves)
	}
}

// ---------------------------------------------------------------------------
// Append: node structure and peaks
// ---------------------------------------------------------------------------

func TestAppendSingleLeaf(t *testing.T) {
	tree := NewShardMMR()
	leaves := appendNamed(t, tree, "only")

	assertNodes(t, tree, leaves)
	assertPeaks(t, tree, leaves)

	if len(tree.Nodes[0]) != 1 {
		t.Fatalf("got %d leaves, want 1", len(tree.Nodes[0]))
	}
	if !bytes.Equal(tree.Nodes[0][0].Hash[:], leaves[0][:]) {
		t.Errorf("leaf hash: got %x, want %x", tree.Nodes[0][0].Hash, leaves[0])
	}
	if tree.Peaks.Size() != 1 {
		t.Fatalf("got %d peaks, want 1", tree.Peaks.Size())
	}
}

func TestAppendTwoLeavesMerges(t *testing.T) {
	tree := NewShardMMR()
	leaves := appendNamed(t, tree, "a", "b")

	assertNodes(t, tree, leaves)
	assertPeaks(t, tree, leaves)

	// Expect a single height-1 peak whose hash is HashPair(a, b).
	if len(tree.Nodes) < 2 || len(tree.Nodes[1]) != 1 {
		t.Fatalf("expected one height-1 internal node, Nodes = %v", shape(tree))
	}
	a, b := leaves[0], leaves[1]
	want := HashPair(&a, &b)
	if !bytes.Equal(tree.Nodes[1][0].Hash[:], want[:]) {
		t.Errorf("internal node hash: got %x, want %x", tree.Nodes[1][0].Hash, want)
	}
}

func TestAppendThreeLeaves(t *testing.T) {
	tree, leaves := buildTree(t, 3)

	assertNodes(t, tree, leaves)
	assertPeaks(t, tree, leaves)

	// Two peaks: height-1 node over leaves 0..1, and the lone leaf 2.
	if got := tree.Peaks.Size(); got != 2 {
		t.Fatalf("got %d peaks, want 2", got)
	}
}

func TestAppendFourLeavesPerfectTree(t *testing.T) {
	tree, leaves := buildTree(t, 4)

	assertNodes(t, tree, leaves)
	assertPeaks(t, tree, leaves)

	if got := tree.Peaks.Size(); got != 1 {
		t.Fatalf("got %d peaks, want 1 (perfect tree)", got)
	}
	if len(tree.Nodes) != 3 {
		t.Fatalf("got %d height levels, want 3", len(tree.Nodes))
	}
}

func TestAppendSevenLeaves(t *testing.T) {
	tree, leaves := buildTree(t, 7)

	assertNodes(t, tree, leaves)
	assertPeaks(t, tree, leaves)

	// 7 = 0b111 -> peaks at heights 2, 1, 0. Values() is top-first and the
	// top of the stack is the shortest / most recent peak.
	got := tree.Peaks.Values()
	wantHeights := []int{0, 1, 2}
	if len(got) != 3 {
		t.Fatalf("got %d peaks, want 3", len(got))
	}
	for i, h := range wantHeights {
		if got[i].height != h {
			t.Errorf("peak[%d from top] height: got %d, want %d", i, got[i].height, h)
		}
	}
}

func TestAppendEightLeavesPerfectTree(t *testing.T) {
	tree, leaves := buildTree(t, 8)

	assertNodes(t, tree, leaves)
	assertPeaks(t, tree, leaves)

	if got := tree.Peaks.Size(); got != 1 {
		t.Fatalf("got %d peaks, want 1 (perfect tree)", got)
	}
}

// TestAppendStructureTable exercises many sizes at once: peak count equals
// popcount(n), and the total node count equals 2n - popcount(n).
func TestAppendStructureTable(t *testing.T) {
	for n := 1; n <= 33; n++ {
		t.Run(padName(n), func(t *testing.T) {
			tree, leaves := buildTree(t, n)

			assertNodes(t, tree, leaves)
			assertPeaks(t, tree, leaves)

			wantPeaks := bits.OnesCount(uint(n))
			if got := tree.Peaks.Size(); got != wantPeaks {
				t.Errorf("n=%d: got %d peaks, want %d", n, got, wantPeaks)
			}

			total := 0
			for _, level := range tree.Nodes {
				total += len(level)
			}
			if want := 2*n - wantPeaks; total != want {
				t.Errorf("n=%d: got %d total nodes, want %d", n, total, want)
			}
		})
	}
}

// TestAppendLeafOrderPreserved makes sure Append never reorders leaves.
func TestAppendLeafOrderPreserved(t *testing.T) {
	tree, leaves := buildTree(t, 10)
	for i, want := range leaves {
		if !bytes.Equal(tree.Nodes[0][i].Hash[:], want[:]) {
			t.Errorf("leaf %d out of order: got %x, want %x", i, tree.Nodes[0][i].Hash, want)
		}
	}
}

// ---------------------------------------------------------------------------
// merge
// ---------------------------------------------------------------------------

// TestMergeGrowsMissingLevel targets the level-allocation guard in merge:
// when combining two height-0 peaks the height-1 level does not exist yet
// and merge must create it rather than index out of range.
func TestMergeGrowsMissingLevel(t *testing.T) {
	tree := NewShardMMR()
	a, b := hashLeaf("a"), hashLeaf("b")
	tree.Nodes[0] = append(tree.Nodes[0], MMRNode{Hash: a, Height: 0}, MMRNode{Hash: b, Height: 0})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("merge panicked instead of growing Nodes: %v", r)
		}
	}()

	node, newPeak, newHeight := tree.merge(peak{height: 0, index: 0}, peak{height: 0, index: 1})

	if newHeight != 1 {
		t.Errorf("newHeight: got %d, want 1", newHeight)
	}
	if newPeak.height != 1 || newPeak.index != 0 {
		t.Errorf("newPeak: got %+v, want {height:1 index:0}", newPeak)
	}
	if node.Height != 1 {
		t.Errorf("node.Height: got %d, want 1", node.Height)
	}
	want := HashPair(&a, &b)
	if !bytes.Equal(node.Hash[:], want[:]) {
		t.Errorf("node.Hash: got %x, want %x", node.Hash, want)
	}
	if len(tree.Nodes) < 2 {
		t.Errorf("merge did not grow Nodes: len = %d, want >= 2", len(tree.Nodes))
	}
}

// TestMergeHashOrder confirms merge hashes (left=first, right=second), not the
// other way round.
func TestMergeHashOrder(t *testing.T) {
	tree := NewShardMMR()
	tree.Nodes = append(tree.Nodes, nil) // pre-create height 1 to isolate hashing
	a, b := hashLeaf("left"), hashLeaf("right")
	tree.Nodes[0] = append(tree.Nodes[0], MMRNode{Hash: a}, MMRNode{Hash: b})

	node, _, _ := tree.merge(peak{height: 0, index: 0}, peak{height: 0, index: 1})

	forward := HashPair(&a, &b)
	backward := HashPair(&b, &a)
	if bytes.Equal(node.Hash[:], backward[:]) && !bytes.Equal(node.Hash[:], forward[:]) {
		t.Errorf("merge hashed (second, first); want (first, second)")
	}
	if !bytes.Equal(node.Hash[:], forward[:]) {
		t.Errorf("merge hash: got %x, want %x", node.Hash, forward)
	}
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

func TestRootSingleLeaf(t *testing.T) {
	tree, leaves := buildTree(t, 1)
	root := safeRoot(t, tree)
	if !bytes.Equal(root[:], leaves[0][:]) {
		t.Errorf("root: got %x, want %x", root, leaves[0])
	}
}

// TestRootPerfectTrees: when n is a power of two there is exactly one peak,
// so the root is unambiguous and is just that peak's hash.
func TestRootPerfectTrees(t *testing.T) {
	for _, n := range []int{1, 2, 4, 8, 16, 32} {
		t.Run(padName(n), func(t *testing.T) {
			tree, leaves := buildTree(t, n)
			root := safeRoot(t, tree)

			peaks := peakHashes(leaves)
			if len(peaks) != 1 {
				t.Fatalf("n=%d produced %d peaks, expected 1", n, len(peaks))
			}
			if !bytes.Equal(root[:], peaks[0][:]) {
				t.Errorf("n=%d root: got %x, want %x", n, root, peaks[0])
			}
		})
	}
}

// TestRootMultiPeakBagging: for non-power-of-two sizes the peaks are bagged
// together. The root must equal an honest fold of the *real* peak hashes in
// the order Root walks them - this fails if Root indexes the wrong peak
// column (e.g. reusing the first peak's index for every level).
func TestRootMultiPeakBagging(t *testing.T) {
	for _, n := range []int{3, 5, 6, 7, 11, 13, 19} {
		t.Run(padName(n), func(t *testing.T) {
			tree, leaves := buildTree(t, n)
			root := safeRoot(t, tree)

			if len(peakHashes(leaves)) < 2 {
				t.Fatalf("n=%d unexpectedly has a single peak", n)
			}
			want := referenceRoot(leaves)
			if !bytes.Equal(root[:], want[:]) {
				t.Errorf("n=%d root: got %x, want %x", n, root, want)
			}
		})
	}
}

// TestRootDependsOnEveryLeaf flips one leaf at a time; a correct root commits
// to all of them. This catches a Root that indexes the wrong peak/column.
func TestRootDependsOnEveryLeaf(t *testing.T) {
	const n = 5
	base, _ := buildTree(t, n)
	baseRoot := safeRoot(t, base)

	for i := range n {
		nm := names(n)
		nm[i] = "MUTATED"
		tree := NewShardMMR()
		appendNamed(t, tree, nm...)
		got := safeRoot(t, tree)

		if bytes.Equal(got[:], baseRoot[:]) {
			t.Errorf("changing leaf %d did not change the root %x", i, baseRoot)
		}
	}
}

func TestRootDependsOnLeafOrder(t *testing.T) {
	t1 := NewShardMMR()
	appendNamed(t, t1, "a", "b", "c")
	r1 := safeRoot(t, t1)

	t2 := NewShardMMR()
	appendNamed(t, t2, "c", "b", "a")
	r2 := safeRoot(t, t2)

	if bytes.Equal(r1[:], r2[:]) {
		t.Errorf("different leaf order produced the same root %x", r1)
	}
}

func TestRootIsDeterministic(t *testing.T) {
	for _, n := range []int{1, 2, 3, 7, 12} {
		a, _ := buildTree(t, n)
		b, _ := buildTree(t, n)
		ra, rb := safeRoot(t, a), safeRoot(t, b)
		if !bytes.Equal(ra[:], rb[:]) {
			t.Errorf("n=%d: non-deterministic root: %x vs %x", n, ra, rb)
		}
	}
}

// TestRootGrowsMonotonically is a light sanity check that each Append changes
// the root (new data => new commitment).
func TestRootChangesOnAppend(t *testing.T) {
	tree := NewShardMMR()
	nm := names(9)
	var prev [32]byte
	for i, n := range nm {
		safeAppend(t, tree, &SegmentNode{Hash: hashLeaf(n)})
		cur := safeRoot(t, tree)
		if i > 0 && bytes.Equal(cur[:], prev[:]) {
			t.Errorf("root unchanged after appending leaf %d", i)
		}
		prev = cur
	}
}

// TestRootEmptyTree documents the expected behaviour on an empty tree: it
// should not panic. Zero hash is the natural "nothing committed" value.
func TestRootEmptyTree(t *testing.T) {
	tree := NewShardMMR()
	root := safeRoot(t, tree)
	if root != ([32]byte{}) {
		t.Errorf("empty-tree root: got %x, want all zero", root)
	}
}

// ---------------------------------------------------------------------------
// NumLeaves bookkeeping
// ---------------------------------------------------------------------------

// TestNumLeavesTracksAppends expects the NumLeaves counter to follow the
// number of appended segments.
func TestNumLeavesTracksAppends(t *testing.T) {
	tree := NewShardMMR()
	for i := 1; i <= 6; i++ {
		safeAppend(t, tree, &SegmentNode{Hash: hashLeaf(names(1)[0] + padName(i))})
		if tree.NumLeaves != i {
			t.Errorf("after %d appends: NumLeaves = %d, want %d", i, tree.NumLeaves, i)
		}
	}
}

// ---------------------------------------------------------------------------
// misc helpers
// ---------------------------------------------------------------------------

func padName(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

func shape(tree *ShardTree) []int {
	out := make([]int, len(tree.Nodes))
	for i, l := range tree.Nodes {
		out[i] = len(l)
	}
	return out
}
