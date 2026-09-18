package tests

import (
	"context"
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
	var updates []locator.Page
	for index := 4; index >= 0; index-- {
		insertUpdates := tree.Insert(testLocatorKey(index), testLocatorValue(index), tree.RootPage)
		if index == 1 {
			updates = insertUpdates
		}
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

	updateIDs := make(map[int64]bool, len(updates))
	for _, page := range updates {
		updateIDs[page.PageID] = true
	}
	for _, page := range []*locator.Page{tree.RootPage, left, right} {
		if !updateIDs[page.PageID] {
			t.Fatalf("split update does not include page %d", page.PageID)
		}
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

func TestLocatorTreeResolveRangeAcrossLeafPages(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	for index := 0; index < 10; index++ {
		tree.Insert(testLocatorKey(index), testLocatorValue(index), tree.RootPage)
	}

	result, err := tree.ResolveRange(testLocatorKey(4), testLocatorKey(6))
	if err != nil {
		t.Fatalf("resolve range: %v", err)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(result.Entries))
	}
	for index, wantLeafID := range []string{"4", "5"} {
		if result.Entries[index].Value == nil || result.Entries[index].Value.LeafID != wantLeafID {
			t.Fatalf("entry %d leaf ID = %+v, want %s", index, result.Entries[index].Value, wantLeafID)
		}
	}
	if result.Predecessor == nil || result.Predecessor.Value.LeafID != "3" {
		t.Fatalf("predecessor = %+v, want leaf ID 3", result.Predecessor)
	}
	if result.Successor == nil || result.Successor.Value.LeafID != "6" {
		t.Fatalf("successor = %+v, want leaf ID 6", result.Successor)
	}
}

func TestLocatorTreeResolveRangeAtTreeEdges(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	for index := 0; index < 5; index++ {
		tree.Insert(testLocatorKey(index), testLocatorValue(index), tree.RootPage)
	}

	lower := testLocatorKey(0)
	upper := testLocatorKey(5)
	result, err := tree.ResolveRange(lower, upper)
	if err != nil {
		t.Fatalf("resolve full range: %v", err)
	}
	if len(result.Entries) != 5 {
		t.Fatalf("entry count = %d, want 5", len(result.Entries))
	}
	if result.Predecessor != nil {
		t.Fatalf("predecessor = %+v, want nil at left tree edge", result.Predecessor)
	}
	if result.Successor != nil {
		t.Fatalf("successor = %+v, want nil at right tree edge", result.Successor)
	}
}

func TestLocatorQueryResolveUsesHalfOpenTimeRange(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	for index := 0; index < 4; index++ {
		tree.Insert(testLocatorKey(index), testLocatorValue(index), tree.RootPage)
	}

	start := testLocatorKey(1).EventTime
	end := testLocatorKey(3).EventTime
	result, err := tree.Resolve(locator.LocatorQuery{
		TenantID:  "tenant",
		ServiceID: "service",
		LogType:   "audit",
		RegionID:  "region",
		StartTime: start,
		EndTime:   end,
	})
	if err != nil {
		t.Fatalf("resolve query: %v", err)
	}
	if len(result.Entries) != 2 || result.Entries[0].Value.LeafID != "1" || result.Entries[1].Value.LeafID != "2" {
		t.Fatalf("unexpected half-open range entries: %+v", result.Entries)
	}
	if result.Predecessor == nil || result.Predecessor.Value.LeafID != "0" {
		t.Fatalf("predecessor = %+v, want leaf ID 0", result.Predecessor)
	}
	if result.Successor == nil || result.Successor.Value.LeafID != "3" {
		t.Fatalf("successor = %+v, want leaf ID 3", result.Successor)
	}
}

func TestResolveRangeWithReaderFetchesDetachedPages(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	for index := 0; index < 10; index++ {
		tree.Insert(testLocatorKey(index), testLocatorValue(index), tree.RootPage)
	}
	reader := newDetachedPageReader(t, tree.RootPage)

	result, err := locator.ResolveRangeWithReader(
		context.Background(),
		reader,
		tree.RootPageID,
		tree.RootHash,
		testLocatorKey(4),
		testLocatorKey(6),
	)
	if err != nil {
		t.Fatalf("resolve detached range: %v", err)
	}
	if len(result.Entries) != 2 || result.Entries[0].Value.LeafID != "4" || result.Entries[1].Value.LeafID != "5" {
		t.Fatalf("unexpected detached range entries: %+v", result.Entries)
	}
	if result.Predecessor == nil || result.Predecessor.Value.LeafID != "3" {
		t.Fatalf("predecessor = %+v, want leaf ID 3", result.Predecessor)
	}
	if result.Successor == nil || result.Successor.Value.LeafID != "6" {
		t.Fatalf("successor = %+v, want leaf ID 6", result.Successor)
	}
	if result.Proof.ReconstructedRoot != tree.RootHash {
		t.Fatalf("reconstructed root = %x, want %x", result.Proof.ReconstructedRoot, tree.RootHash)
	}
	if err := locator.VerifyLocatorPathProofs(result.Proof, tree.RootHash); err != nil {
		t.Fatalf("verify locator path proofs: %v", err)
	}
	if err := locator.VerifyLocatorRangeResult(
		testLocatorKey(4), testLocatorKey(6), result, tree.RootHash,
	); err != nil {
		t.Fatalf("verify locator range result: %v", err)
	}
	if len(result.Proof.Leaves) < 2 {
		t.Fatalf("proof leaf count = %d, want proofs for multiple range pages", len(result.Proof.Leaves))
	}
	if len(reader.reads) <= tree.Height {
		t.Fatalf("read %d unique pages, expected root paths and boundary pages", len(reader.reads))
	}
}

func TestVerifyLocatorRangeResultRejectsIncompleteResults(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	for index := 0; index < 12; index++ {
		tree.Insert(testLocatorKey(index), testLocatorValue(index), tree.RootPage)
	}
	lower := testLocatorKey(2)
	upper := testLocatorKey(10)
	result, err := tree.ResolveRange(lower, upper)
	if err != nil {
		t.Fatalf("resolve range: %v", err)
	}
	if err := locator.VerifyLocatorRangeResult(lower, upper, result, tree.RootHash); err != nil {
		t.Fatalf("verify valid range: %v", err)
	}

	t.Run("missing returned entry", func(t *testing.T) {
		changed := result
		changed.Entries = append([]locator.LocatorEntry(nil), result.Entries[1:]...)
		if err := locator.VerifyLocatorRangeResult(lower, upper, changed, tree.RootHash); err == nil {
			t.Fatal("verification accepted an omitted matching entry")
		}
	})

	t.Run("changed returned address", func(t *testing.T) {
		changed := result
		changed.Entries = append([]locator.LocatorEntry(nil), result.Entries...)
		value := *changed.Entries[0].Value
		value.LeafID = "forged"
		changed.Entries[0].Value = &value
		if err := locator.VerifyLocatorRangeResult(lower, upper, changed, tree.RootHash); err == nil {
			t.Fatal("verification accepted a changed physical address")
		}
	})

	t.Run("missing predecessor", func(t *testing.T) {
		changed := result
		changed.Predecessor = nil
		if err := locator.VerifyLocatorRangeResult(lower, upper, changed, tree.RootHash); err == nil {
			t.Fatal("verification accepted a missing predecessor")
		}
	})

	t.Run("missing successor", func(t *testing.T) {
		changed := result
		changed.Successor = nil
		if err := locator.VerifyLocatorRangeResult(lower, upper, changed, tree.RootHash); err == nil {
			t.Fatal("verification accepted a missing successor")
		}
	})

	t.Run("missing intermediate leaf", func(t *testing.T) {
		if len(result.Proof.Leaves) < 3 {
			t.Fatalf("proof has %d leaves, need at least 3", len(result.Proof.Leaves))
		}
		changed := result
		changed.Proof = result.Proof
		changed.Proof.Leaves = append([]locator.LocatorLeafProof(nil), result.Proof.Leaves...)
		changed.Proof.Leaves = append(changed.Proof.Leaves[:1], changed.Proof.Leaves[2:]...)
		if err := locator.VerifyLocatorRangeResult(lower, upper, changed, tree.RootHash); err == nil {
			t.Fatal("verification accepted a missing intermediate leaf")
		}
	})
}

func TestVerifyLocatorPathProofsRejectsChangedSiblingHash(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	for index := 0; index < 10; index++ {
		tree.Insert(testLocatorKey(index), testLocatorValue(index), tree.RootPage)
	}
	result, err := tree.ResolveRange(testLocatorKey(4), testLocatorKey(6))
	if err != nil {
		t.Fatalf("resolve range: %v", err)
	}

	proof := result.Proof
	proof.Leaves = append([]locator.LocatorLeafProof(nil), proof.Leaves...)
	proof.Leaves[0].Path = append([]locator.LocatorProofStep(nil), proof.Leaves[0].Path...)
	step := &proof.Leaves[0].Path[0]
	step.ChildHashes = append([][32]byte(nil), step.ChildHashes...)
	siblingIndex := 0
	if siblingIndex == step.ChildIndex {
		siblingIndex = 1
	}
	step.ChildHashes[siblingIndex][0] ^= 0xff

	if err := locator.VerifyLocatorPathProofs(proof, tree.RootHash); err == nil {
		t.Fatal("path verification accepted a changed sibling hash")
	}
}

func TestResolveRangeWithReaderRejectsUntrustedRoot(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	tree.Insert(testLocatorKey(0), testLocatorValue(0), tree.RootPage)
	reader := newDetachedPageReader(t, tree.RootPage)

	_, err := locator.ResolveRangeWithReader(
		context.Background(),
		reader,
		tree.RootPageID,
		[32]byte{1},
		testLocatorKey(0),
		testLocatorKey(1),
	)
	if err == nil {
		t.Fatal("resolve range accepted a root page that does not match the trusted root")
	}
}

func TestPageCodecRoundTrip(t *testing.T) {
	t.Run("leaf", func(t *testing.T) {
		page := locator.Page{
			PageID: 10,
			IsLeaf: true,
			Keys:   []locator.LocatorKey{testLocatorKey(1)},
			Values: []*locator.LocatorValue{testLocatorValue(1)},
		}

		data, err := locator.MarshalPage(page)
		if err != nil {
			t.Fatalf("marshal leaf page: %v", err)
		}
		restored, err := locator.UnmarshalPage(data)
		if err != nil {
			t.Fatalf("unmarshal leaf page: %v", err)
		}
		if !restored.IsLeaf || restored.Keys[0] != page.Keys[0] {
			t.Fatal("leaf key was not restored")
		}
		if restored.Values[0] == nil || *restored.Values[0] != *page.Values[0] {
			t.Fatal("leaf value was not restored")
		}
	})

	t.Run("internal", func(t *testing.T) {
		page := locator.Page{
			IsLeaf: false,
			Keys:   []locator.LocatorKey{testLocatorKey(1)},
			Children: []*locator.Page{
				{PageID: 2, Hash: [32]byte{2}},
				{PageID: 3, Hash: [32]byte{3}},
			},
		}

		data, err := locator.MarshalPage(page)
		if err != nil {
			t.Fatalf("marshal internal page: %v", err)
		}
		restored, err := locator.UnmarshalPage(data)
		if err != nil {
			t.Fatalf("unmarshal internal page: %v", err)
		}
		if restored.IsLeaf || restored.Keys[0] != page.Keys[0] {
			t.Fatal("internal key was not restored")
		}
		for index, child := range page.Children {
			if restored.Children[index].PageID != child.PageID || restored.Children[index].Hash != child.Hash {
				t.Fatalf("child %d was not restored", index)
			}
		}
	})
}

func TestStoredLeafHashAuthenticatesPageAndNextPageIDs(t *testing.T) {
	tree := locator.NewLocatorTree(4)
	tree.Insert(testLocatorKey(0), testLocatorValue(0), tree.RootPage)
	data, err := locator.MarshalPage(*tree.RootPage)
	if err != nil {
		t.Fatalf("marshal root leaf: %v", err)
	}

	wrongNextPageID := int64(99)
	if _, err := locator.UnmarshalStoredPage(
		data, tree.RootPageID, nil, &wrongNextPageID, tree.RootHash[:],
	); err == nil {
		t.Fatal("stored leaf accepted a changed next page ID")
	}
	if _, err := locator.UnmarshalStoredPage(
		data, tree.RootPageID+1, nil, nil, tree.RootHash[:],
	); err == nil {
		t.Fatal("stored leaf accepted a changed page ID")
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

type detachedPageReader struct {
	pages map[int64]*locator.Page
	reads map[int64]int
}

func newDetachedPageReader(t *testing.T, root *locator.Page) *detachedPageReader {
	t.Helper()
	reader := &detachedPageReader{
		pages: make(map[int64]*locator.Page),
		reads: make(map[int64]int),
	}
	var detach func(*locator.Page)
	detach = func(page *locator.Page) {
		if _, exists := reader.pages[page.PageID]; exists {
			return
		}
		data, err := locator.MarshalPage(*page)
		if err != nil {
			t.Fatalf("marshal detached page %d: %v", page.PageID, err)
		}
		var nextPageID *int64
		if page.Next != nil {
			next := page.Next.PageID
			nextPageID = &next
		}
		detached, err := locator.UnmarshalStoredPage(
			data,
			page.PageID,
			page.ParentPageID,
			nextPageID,
			page.Hash[:],
		)
		if err != nil {
			t.Fatalf("unmarshal detached page %d: %v", page.PageID, err)
		}
		reader.pages[page.PageID] = &detached
		for _, child := range page.Children {
			detach(child)
		}
	}
	detach(root)
	return reader
}

func (reader *detachedPageReader) ReadPage(_ context.Context, pageID int64) (*locator.Page, error) {
	page, exists := reader.pages[pageID]
	if !exists {
		return nil, fmt.Errorf("detached page %d not found", pageID)
	}
	reader.reads[pageID]++
	return page, nil
}
