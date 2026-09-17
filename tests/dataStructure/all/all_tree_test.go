package tests

import (
	"fmt"
	"testing"
	"time"
	"uuid"

	locator "github.com/SirojWongpitakroj/hmf-audit/internal/all"
)

func TestNewLocatorTree(t *testing.T) {
	tree := locator.NewLocatorTree(4)

	if tree.RootPage == nil {
		t.Fatal("root page is nil")
	}
	if !tree.RootPage.IsLeaf {
		t.Fatal("new tree root is not a leaf")
	}
	if tree.RootPageID != 0 || tree.RootPage.PageID != 0 {
		t.Fatalf("root page ID = %d, want 0", tree.RootPageID)
	}
	if tree.NextPageID != 1 {
		t.Fatalf("next page ID = %d, want 1", tree.NextPageID)
	}
	if tree.Height != 0 || tree.LeafCount != 0 {
		t.Fatalf("new tree height/count = %d/%d, want 0/0", tree.Height, tree.LeafCount)
	}
	if tree.Order != 4 {
		t.Fatalf("tree order = %d, want 4", tree.Order)
	}
}

func TestLocatorKeyLess(t *testing.T) {
	baseTime := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	base := locator.LocatorKey{
		TenantID:  "tenant-b",
		ServiceID: "service-b",
		LogType:   "type-b",
		RegionID:  "region-b",
		EventTime: baseTime,
		LogID:     uuid.UUID{2},
	}

	tests := []struct {
		name string
		key  locator.LocatorKey
	}{
		{name: "tenant", key: locator.LocatorKey{TenantID: "tenant-a"}},
		{name: "service", key: locator.LocatorKey{TenantID: base.TenantID, ServiceID: "service-a"}},
		{name: "log type", key: locator.LocatorKey{TenantID: base.TenantID, ServiceID: base.ServiceID, LogType: "type-a"}},
		{name: "region", key: locator.LocatorKey{TenantID: base.TenantID, ServiceID: base.ServiceID, LogType: base.LogType, RegionID: "region-a"}},
		{name: "event time", key: locator.LocatorKey{TenantID: base.TenantID, ServiceID: base.ServiceID, LogType: base.LogType, RegionID: base.RegionID, EventTime: baseTime.Add(-time.Second)}},
		{name: "log ID", key: locator.LocatorKey{TenantID: base.TenantID, ServiceID: base.ServiceID, LogType: base.LogType, RegionID: base.RegionID, EventTime: baseTime, LogID: uuid.UUID{1}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.key.Less(base) {
				t.Fatalf("%s key should sort before the base key", test.name)
			}
			if base.Less(test.key) {
				t.Fatalf("base key should not sort before the %s key", test.name)
			}
		})
	}
}

func TestLocatorTreeInsertMaintainsSortedKeyValuePairs(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	indexes := []int{2, 0, 1}

	var previousHash [32]byte
	for _, index := range indexes {
		key := testLocatorKey(index)
		value := testLocatorValue(index)
		tree.Insert(key, value, tree.RootPage)

		if tree.RootHash == previousHash {
			t.Fatalf("root hash did not change after inserting key %d", index)
		}
		previousHash = tree.RootHash
	}

	if tree.LeafCount != int64(len(indexes)) {
		t.Fatalf("leaf count = %d, want %d", tree.LeafCount, len(indexes))
	}
	if len(tree.RootPage.Keys) != len(indexes) {
		t.Fatalf("root key count = %d, want %d", len(tree.RootPage.Keys), len(indexes))
	}

	for index := range indexes {
		wantKey := testLocatorKey(index)
		if tree.RootPage.Keys[index] != wantKey {
			t.Fatalf("key at index %d = %+v, want %+v", index, tree.RootPage.Keys[index], wantKey)
		}
		if tree.RootPage.Values[index].LeafID != fmt.Sprint(index) {
			t.Fatalf("value at index %d has leaf ID %q, want %d", index, tree.RootPage.Values[index].LeafID, index)
		}
	}

	if tree.RootHash != tree.RootPage.Hash {
		t.Fatal("tree root hash does not match the root page hash")
	}
}

func TestLocatorTreeLeafSplitCreatesInternalRoot(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	for index := 4; index >= 0; index-- {
		tree.Insert(testLocatorKey(index), testLocatorValue(index), tree.RootPage)
	}

	if tree.RootPage.IsLeaf {
		t.Fatal("root is still a leaf after leaf-page overflow")
	}
	if tree.Height != 1 {
		t.Fatalf("tree height = %d, want 1", tree.Height)
	}
	if len(tree.RootPage.Children) != 2 {
		t.Fatalf("root child count = %d, want 2", len(tree.RootPage.Children))
	}

	left := tree.RootPage.Children[0]
	right := tree.RootPage.Children[1]
	if left.Parent != tree.RootPage || right.Parent != tree.RootPage {
		t.Fatal("leaf parent does not point to the new root")
	}
	if left.Next != right {
		t.Fatal("left leaf does not point to the right leaf")
	}
	if len(tree.RootPage.Keys) != 1 || tree.RootPage.Keys[0] != right.Keys[0] {
		t.Fatal("root separator is not the first key of the right leaf")
	}

	assertLocatorTree(t, tree, 5)
}

func TestLocatorTreeMultipleSplitsMaintainStructure(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	const recordCount = 40

	for index := recordCount - 1; index >= 0; index-- {
		tree.Insert(testLocatorKey(index), testLocatorValue(index), tree.RootPage)
	}

	if tree.Height < 2 {
		t.Fatalf("tree height = %d, want at least 2", tree.Height)
	}
	assertLocatorTree(t, tree, recordCount)
}

func TestLocatorTreeHashAuthenticatesLocatorValue(t *testing.T) {
	key := testLocatorKey(1)
	firstTree := locator.NewLocatorTree(4)
	secondTree := locator.NewLocatorTree(4)

	firstTree.Insert(key, &locator.LocatorValue{
		RegionID:  "region-a",
		ShardID:   "1",
		SegmentID: "2",
		LeafID:    "3",
	}, firstTree.RootPage)
	secondTree.Insert(key, &locator.LocatorValue{
		RegionID:  "region-b",
		ShardID:   "4",
		SegmentID: "5",
		LeafID:    "6",
	}, secondTree.RootPage)

	if firstTree.RootHash == secondTree.RootHash {
		t.Fatal("different locator values produced the same root hash")
	}
}

func assertLocatorTree(t *testing.T, tree *locator.LocatorTree, recordCount int) {
	t.Helper()

	if tree.RootPage == nil {
		t.Fatal("root page is nil")
	}
	if tree.RootPage.Parent != nil {
		t.Fatal("root page has a parent")
	}
	if tree.RootPageID != tree.RootPage.PageID {
		t.Fatalf("root page ID = %d, root page has ID %d", tree.RootPageID, tree.RootPage.PageID)
	}
	if tree.RootHash != tree.RootPage.Hash {
		t.Fatal("tree root hash does not match the root page hash")
	}
	if tree.LeafCount != int64(recordCount) {
		t.Fatalf("leaf count = %d, want %d", tree.LeafCount, recordCount)
	}

	leafDepth := -1
	pageIDs := make(map[int64]bool)
	validatePage(t, tree, tree.RootPage, 0, &leafDepth, pageIDs)
	if leafDepth != tree.Height {
		t.Fatalf("leaf depth = %d, tree height = %d", leafDepth, tree.Height)
	}

	leaf := tree.RootPage
	for !leaf.IsLeaf {
		leaf = leaf.Children[0]
	}

	keys := make([]locator.LocatorKey, 0, recordCount)
	values := make([]*locator.LocatorValue, 0, recordCount)
	for leaf != nil {
		keys = append(keys, leaf.Keys...)
		values = append(values, leaf.Values...)
		leaf = leaf.Next
	}

	if len(keys) != recordCount || len(values) != recordCount {
		t.Fatalf("leaf chain contains %d keys and %d values, want %d", len(keys), len(values), recordCount)
	}
	for index := 0; index < recordCount; index++ {
		if keys[index] != testLocatorKey(index) {
			t.Fatalf("leaf-chain key at index %d is out of order", index)
		}
		if values[index].LeafID != fmt.Sprint(index) {
			t.Fatalf("leaf-chain value at index %d has leaf ID %q", index, values[index].LeafID)
		}
	}
}

func validatePage(t *testing.T, tree *locator.LocatorTree, page *locator.Page,
	depth int, leafDepth *int, pageIDs map[int64]bool) {

	t.Helper()

	if pageIDs[page.PageID] {
		t.Fatalf("duplicate page ID %d", page.PageID)
	}
	pageIDs[page.PageID] = true

	for index := 1; index < len(page.Keys); index++ {
		if !page.Keys[index-1].Less(page.Keys[index]) {
			t.Fatalf("page %d keys are not strictly sorted", page.PageID)
		}
	}

	if page.IsLeaf {
		if len(page.Keys) != len(page.Values) {
			t.Fatalf("leaf page %d has %d keys and %d values", page.PageID, len(page.Keys), len(page.Values))
		}
		if len(page.Keys) > tree.Order-1 {
			t.Fatalf("leaf page %d has %d keys, maximum is %d", page.PageID, len(page.Keys), tree.Order-1)
		}
		if *leafDepth == -1 {
			*leafDepth = depth
		} else if *leafDepth != depth {
			t.Fatalf("leaf page %d is at depth %d, want %d", page.PageID, depth, *leafDepth)
		}
		return
	}

	if len(page.Children) != len(page.Keys)+1 {
		t.Fatalf("internal page %d has %d keys and %d children", page.PageID, len(page.Keys), len(page.Children))
	}
	if len(page.Children) > tree.Order {
		t.Fatalf("internal page %d has %d children, maximum is %d", page.PageID, len(page.Children), tree.Order)
	}

	for index, child := range page.Children {
		if child.Parent != page {
			t.Fatalf("child page %d does not point to parent page %d", child.PageID, page.PageID)
		}
		if index > 0 && page.Keys[index-1] != firstLocatorKey(child) {
			t.Fatalf("separator %d in page %d does not match its right child", index-1, page.PageID)
		}
		validatePage(t, tree, child, depth+1, leafDepth, pageIDs)
	}
}

func firstLocatorKey(page *locator.Page) locator.LocatorKey {
	for !page.IsLeaf {
		page = page.Children[0]
	}
	return page.Keys[0]
}

func testLocatorKey(index int) locator.LocatorKey {
	return locator.LocatorKey{
		TenantID:  "tenant",
		ServiceID: "service",
		LogType:   "audit",
		RegionID:  "region",
		EventTime: time.Date(2026, time.January, 1, 0, 0, index, 0, time.UTC),
		LogID:     uuid.UUID{byte(index)},
	}
}

func testLocatorValue(index int) *locator.LocatorValue {
	return &locator.LocatorValue{
		RegionID:  "region",
		ShardID:   "1",
		SegmentID: "2",
		LeafID:    fmt.Sprint(index),
	}
}
