package all

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
	"uuid"
)

func bulkTestEntries(n int) ([]LocatorKey, []*LocatorValue) {
	keys := make([]LocatorKey, n)
	values := make([]*LocatorValue, n)
	base := time.Unix(1_500_000_000, 0).UTC()
	for i := range n {
		var id uuid.UUID
		id[0], id[1], id[2], id[3] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		keys[i] = LocatorKey{
			LogID:     id,
			EventTime: base.Add(time.Duration(i%97) * time.Second), // many shared times
			RegionID:  fmt.Sprintf("R%d", i%4),
			TenantID:  fmt.Sprintf("T%d", i%13),
			ServiceID: []string{"svc-a", "svc-b", "svc-c"}[i%3],
			LogType:   []string{"INFO", "WARN"}[i%2],
		}
		values[i] = &LocatorValue{RegionID: keys[i].RegionID, ShardID: "0",
			SegmentID: fmt.Sprint(i / 64), LeafID: fmt.Sprint(i % 64)}
	}
	// Insert in a shuffled order so splits happen everywhere in the tree.
	order := rand.New(rand.NewSource(7)).Perm(n)
	shuffledKeys := make([]LocatorKey, n)
	shuffledValues := make([]*LocatorValue, n)
	for to, from := range order {
		shuffledKeys[to], shuffledValues[to] = keys[from], values[from]
	}
	return shuffledKeys, shuffledValues
}

func TestBulkLoadBuildsTheSameTreeAsIncrementalInserts(t *testing.T) {
	for _, order := range []int{4, 8, 128} {
		keys, values := bulkTestEntries(20_000)
		incremental := NewLocatorTree(order)
		for i := range keys {
			incremental.Insert(keys[i], values[i], incremental.RootPage)
		}
		bulk := NewLocatorTree(order)
		bulk.BeginBulkLoad()
		for i := range keys {
			bulk.Insert(keys[i], values[i], bulk.RootPage)
		}
		bulk.FinishBulkLoad()

		if bulk.RootHash != incremental.RootHash || bulk.RootPageID != incremental.RootPageID ||
			bulk.NextPageID != incremental.NextPageID || bulk.Height != incremental.Height ||
			bulk.LeafCount != incremental.LeafCount {
			t.Fatalf("order %d: tree state differs", order)
		}
		pages := 0
		var compare func(a, b *Page)
		compare = func(a, b *Page) {
			pages++
			if a.PageID != b.PageID || a.Hash != b.Hash || a.IsLeaf != b.IsLeaf ||
				len(a.Keys) != len(b.Keys) || len(a.Children) != len(b.Children) {
				t.Fatalf("order %d: page %d differs", order, a.PageID)
			}
			for i := range a.Children {
				compare(a.Children[i], b.Children[i])
			}
		}
		compare(incremental.RootPage, bulk.RootPage)

		// A bulk-loaded tree answers and proves queries like any other.
		query := LocatorQuery{TenantID: "T0", ServiceID: "svc-a", LogType: "INFO", RegionID: "R0",
			StartTime: time.Unix(1_500_000_010, 0).UTC(), EndTime: time.Unix(1_500_000_030, 0).UTC()}
		result, err := bulk.Resolve(query)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyLocatorQueryResult(query, result, bulk.RootHash); err != nil {
			t.Fatalf("order %d: proof from bulk-loaded tree: %v", order, err)
		}
		if len(result.Entries) == 0 {
			t.Fatalf("order %d: empty result", order)
		}
		t.Logf("order %d: %d pages identical, query returned %d entries", order, pages, len(result.Entries))
	}
}
