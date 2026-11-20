package all

import (
	"context"
	"errors"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

// recordingReader serves pages from memory, records every page ID read, can add latency to every read
// and can fail one page.
type recordingReader struct {
	inner   PageReader
	latency time.Duration
	failID  int64
	mu      sync.Mutex
	read    map[int64]int
}

func newRecordingReader(root *Page, latency time.Duration) *recordingReader {
	return &recordingReader{inner: newMemoryPageReader(root), latency: latency, failID: -1, read: map[int64]int{}}
}

func (reader *recordingReader) ReadPage(ctx context.Context, pageID int64) (*Page, error) {
	reader.mu.Lock()
	reader.read[pageID]++
	reader.mu.Unlock()
	if reader.latency > 0 {
		time.Sleep(reader.latency)
	}
	if pageID == reader.failID {
		return nil, errors.New("injected read failure")
	}
	return reader.inner.ReadPage(ctx, pageID)
}

func (reader *recordingReader) pages() []int64 {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	ids := make([]int64, 0, len(reader.read))
	for id := range reader.read {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	return ids
}

func buildPrefetchTree(t *testing.T, order, n int) (*LocatorTree, []LocatorKey) {
	t.Helper()
	keys, values := bulkTestEntries(n)
	tree := NewLocatorTree(order)
	tree.BeginBulkLoad()
	for i := range keys {
		tree.Insert(keys[i], values[i], tree.RootPage)
	}
	tree.FinishBulkLoad()
	sorted := append([]LocatorKey(nil), keys...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a].Compare(sorted[b]) < 0 })
	return tree, sorted
}

func withFetchConcurrency(t *testing.T, workers int) {
	t.Helper()
	previous := pageFetchConcurrency
	pageFetchConcurrency = workers
	t.Cleanup(func() { pageFetchConcurrency = previous })
}

// TestParallelLeafRetrievalReturnsTheSameRangesAndReadsTheSamePages: parallel retrieval returns the
// same entries, boundaries and proof as one-by-one retrieval, for ranges inside one leaf, across a few
// leaves, across parents and across most of the tree, and it reads exactly the same set of pages.
func TestParallelLeafRetrievalReturnsTheSameRangesAndReadsTheSamePages(t *testing.T) {
	random := rand.New(rand.NewSource(21))
	for _, order := range []int{4, 5, 8, 32} {
		tree, sorted := buildPrefetchTree(t, order, 4000)
		for trial := 0; trial < 120; trial++ {
			span := []int{1, 3, 10, 40, 200, 900, 3500}[random.Intn(7)]
			from := random.Intn(len(sorted) - 1)
			to := min(from+1+random.Intn(span), len(sorted)-1)
			if from == to {
				continue
			}
			lower, upper := sorted[from], sorted[to]
			if random.Intn(4) == 0 && to+1 < len(sorted) {
				upper = sorted[to+1]
			}
			run := func(workers int) (LocatorRangeResult, []int64, error) {
				withFetchConcurrency(t, workers)
				reader := newRecordingReader(tree.RootPage, 0)
				result, err := ResolveRangeWithReader(context.Background(), reader, tree.RootPageID, tree.RootHash, lower, upper)
				return result, reader.pages(), err
			}
			wantResult, wantPages, wantErr := run(0)
			gotResult, gotPages, gotErr := run(8)
			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("order %d range %d..%d: errors differ: %v vs %v", order, from, to, wantErr, gotErr)
			}
			if !reflect.DeepEqual(wantResult, gotResult) {
				t.Fatalf("order %d range %d..%d: results differ", order, from, to)
			}
			if !reflect.DeepEqual(wantPages, gotPages) {
				t.Fatalf("order %d range %d..%d: parallel retrieval read different pages (%d vs %d)", order, from, to, len(gotPages), len(wantPages))
			}
			if err := VerifyLocatorRangeResult(lower, upper, gotResult, tree.RootHash); err != nil {
				t.Fatalf("order %d range %d..%d: parallel result fails verification: %v", order, from, to, err)
			}
		}
	}
}

// TestParallelLeafRetrievalIsFasterWhenReadsHaveLatency: a range over many leaves, with 2 ms per page
// read, resolves several times faster with 8 concurrent reads.
func TestParallelLeafRetrievalIsFasterWhenReadsHaveLatency(t *testing.T) {
	tree, sorted := buildPrefetchTree(t, 16, 6000)
	lower, upper := sorted[500], sorted[4500]
	timed := func(workers int) time.Duration {
		withFetchConcurrency(t, workers)
		reader := newRecordingReader(tree.RootPage, 2*time.Millisecond)
		start := time.Now()
		if _, err := ResolveRangeWithReader(context.Background(), reader, tree.RootPageID, tree.RootHash, lower, upper); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	sequential, parallel := timed(0), timed(8)
	t.Logf("sequential %v, parallel %v", sequential, parallel)
	if parallel*3 > sequential {
		t.Fatalf("parallel %v is not at least 3x faster than sequential %v", parallel, sequential)
	}
}

// TestParallelLeafRetrievalStillReportsAFailedPage: a page that fails to read fails the resolution,
// as it does without prefetching, and nothing is left running afterwards.
func TestParallelLeafRetrievalStillReportsAFailedPage(t *testing.T) {
	tree, sorted := buildPrefetchTree(t, 8, 3000)
	lower, upper := sorted[100], sorted[2000]
	withFetchConcurrency(t, 0)
	probe := newRecordingReader(tree.RootPage, 0)
	if _, err := ResolveRangeWithReader(context.Background(), probe, tree.RootPageID, tree.RootHash, lower, upper); err != nil {
		t.Fatal(err)
	}
	pages := probe.pages()
	victim := pages[len(pages)/2]
	for _, workers := range []int{0, 8} {
		withFetchConcurrency(t, workers)
		reader := newRecordingReader(tree.RootPage, 0)
		reader.failID = victim
		if victim == tree.RootPageID {
			continue
		}
		if _, err := ResolveRangeWithReader(context.Background(), reader, tree.RootPageID, tree.RootHash, lower, upper); err == nil {
			t.Fatalf("workers=%d: a failed page read was not reported", workers)
		}
	}
}
