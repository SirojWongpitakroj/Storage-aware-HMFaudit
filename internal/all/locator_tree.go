package all

import (
	"slices"
	"sort"
)

// Merkle B+ tree

type pageUpdates map[int64]*Page

func newPageUpdates() pageUpdates {
	return make(pageUpdates)
}

func (updates pageUpdates) add(page *Page) {
	updates[page.PageID] = page
}

func (updates pageUpdates) pages() []Page {
	pageIDs := make([]int64, 0, len(updates))
	for pageID := range updates {
		pageIDs = append(pageIDs, pageID)
	}
	sort.Slice(pageIDs, func(left, right int) bool {
		return pageIDs[left] < pageIDs[right]
	})

	pages := make([]Page, 0, len(pageIDs))
	for _, pageID := range pageIDs {
		pages = append(pages, *updates[pageID])
	}
	return pages
}

func pageIDPointer(page *Page) *int64 {
	if page == nil {
		return nil
	}
	pageID := page.PageID
	return &pageID
}

func NewLocatorTree(order int) *LocatorTree {
	tree := LocatorTree{
		RootPageID: 0,
		RootPage: &Page{
			PageID: 0,
			IsLeaf: true,
			Keys:   make([]LocatorKey, 0, order-1),
			Values: make([]*LocatorValue, 0, order),
		},
		NextPageID: 1,
		Order:      order,
		Height:     0,
		LeafCount:  0,
	}
	tree.RootPage.Hash = tree.RootPage.leafHash()
	tree.RootHash = tree.RootPage.Hash
	return &tree
}

func (tree *LocatorTree) setRoot(currPage *Page, updates pageUpdates) {
	currPage.Parent = nil
	currPage.ParentPageID = nil
	tree.RootPageID = currPage.PageID
	tree.RootHash = currPage.Hash
	tree.RootPage = currPage
	updates.add(currPage)
}

func (tree *LocatorTree) insertParent(currPage, rightPage *Page,
	currKey LocatorKey, updates pageUpdates) {

	parent := currPage.Parent

	//no parent
	if parent == nil {
		parent = &Page{
			PageID:   tree.NextPageID,
			IsLeaf:   false,
			Keys:     make([]LocatorKey, 0, tree.Order-1),
			Children: make([]*Page, 0, tree.Order),
		}
		tree.NextPageID++

		parent.Keys = append(parent.Keys, currKey)

		parent.Children = append(parent.Children, currPage)
		parent.Children = append(parent.Children, rightPage)
		currPage.Parent = parent
		currPage.ParentPageID = pageIDPointer(parent)
		rightPage.Parent = parent
		rightPage.ParentPageID = pageIDPointer(parent)

		parent.Hash = parent.internalHash()
		tree.Height++
		updates.add(currPage)
		updates.add(rightPage)
		tree.setRoot(parent, updates)
	} else { //there exist a parent
		currIdx := slices.Index(parent.Children, currPage)
		if currIdx == -1 {
			panic("insert parent: current page is not a child of its parent")
		}

		parent.Keys = slices.Insert(parent.Keys, currIdx, currKey)
		parent.Children = slices.Insert(parent.Children, currIdx+1, rightPage)
		rightPage.Parent = parent
		rightPage.ParentPageID = pageIDPointer(parent)
		updates.add(parent)
		updates.add(rightPage)
	}
	tree.internalSplit(parent, updates)
}

func (tree *LocatorTree) internalSplit(currPage *Page, updates pageUpdates) {
	if len(currPage.Children) <= tree.Order {
		return
	}

	mid := len(currPage.Keys) / 2
	currKey := currPage.Keys[mid]

	// right side
	rightKeys := append([]LocatorKey(nil), currPage.Keys[mid+1:]...)
	rightChildren := append([]*Page(nil), currPage.Children[mid+1:]...)

	rightPage := &Page{
		PageID:       tree.NextPageID,
		IsLeaf:       false,
		Parent:       currPage.Parent,
		ParentPageID: pageIDPointer(currPage.Parent),
		Keys:         rightKeys,
		Children:     rightChildren,
	}
	tree.NextPageID++
	for _, child := range rightPage.Children {
		child.Parent = rightPage
		child.ParentPageID = pageIDPointer(rightPage)
		updates.add(child)
	}
	rightPage.Hash = rightPage.internalHash()

	// left side
	currPage.Keys = currPage.Keys[:mid:mid]
	currPage.Children = currPage.Children[: mid+1 : mid+1]
	currPage.Hash = currPage.internalHash()
	updates.add(currPage)
	updates.add(rightPage)

	tree.insertParent(currPage, rightPage, currKey, updates)
}

func (tree *LocatorTree) leafSplit(currPage *Page, updates pageUpdates) {
	mid := len(currPage.Keys) / 2
	// right side
	rightKeys := append([]LocatorKey(nil), currPage.Keys[mid:]...)
	rightValues := append([]*LocatorValue(nil), currPage.Values[mid:]...)

	rightPage := &Page{
		PageID:       tree.NextPageID,
		IsLeaf:       true,
		Parent:       currPage.Parent,
		ParentPageID: pageIDPointer(currPage.Parent),
		Keys:         rightKeys,
		Values:       rightValues,
		Next:         currPage.Next,
	}
	tree.NextPageID++
	currPage.Hash = currPage.leafHash()
	rightPage.Hash = rightPage.leafHash()

	// left side
	currPage.Keys = currPage.Keys[:mid:mid]
	currPage.Values = currPage.Values[:mid:mid]
	currPage.Next = rightPage
	updates.add(currPage)
	updates.add(rightPage)

	tree.insertParent(currPage, rightPage, rightPage.Keys[0], updates)
}

func (tree *LocatorTree) updatePathHashes(currPage *Page, updates pageUpdates) {
	for currPage != nil {
		if currPage.IsLeaf {
			currPage.Hash = currPage.leafHash()
		} else {
			currPage.Hash = currPage.internalHash()
		}

		updates.add(currPage)

		if currPage.Parent == nil {
			break
		}
		currPage = currPage.Parent
	}
	tree.setRoot(currPage, updates)
}

func (tree *LocatorTree) Insert(key LocatorKey, value *LocatorValue, currPage *Page) []Page {
	return tree.InsertWithUpdate(key, value, currPage).Pages
}

// InsertWithUpdate adds a locator record and returns every changed page and
// the final authenticated tree state needed for persistence.
func (tree *LocatorTree) InsertWithUpdate(key LocatorKey, value *LocatorValue, currPage *Page) LocatorUpdate {
	updates := newPageUpdates()
	tree.insert(key, value, currPage, updates)

	return LocatorUpdate{
		Pages:       updates.pages(),
		RootPageID:  tree.RootPageID,
		RootHash:    tree.RootHash,
		NextPageID:  tree.NextPageID,
		Height:      tree.Height,
		RecordCount: tree.LeafCount,
	}
}

func (tree *LocatorTree) insert(key LocatorKey, value *LocatorValue, currPage *Page, updates pageUpdates) {
	//base case
	if currPage.IsLeaf {
		currIdx := currPage.findKeyIdx(key)
		currPage.Keys = slices.Insert(currPage.Keys, currIdx, key)
		currPage.Values = slices.Insert(currPage.Values, currIdx, value)
		if len(currPage.Keys) >= tree.Order {
			tree.leafSplit(currPage, updates)
		}
		tree.LeafCount++
		tree.updatePathHashes(currPage, updates)
		return
	}

	idx := currPage.findKeyIdx(key)
	tree.insert(key, value, currPage.Children[idx], updates)
}
