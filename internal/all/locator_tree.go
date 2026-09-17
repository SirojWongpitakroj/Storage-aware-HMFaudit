package all

import (
	"slices"
)

// Merkle B+ tree

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

func (tree *LocatorTree) setRoot(currPage *Page) {
	tree.RootPageID = currPage.PageID
	tree.RootHash = currPage.Hash
	tree.RootPage = currPage
}

func (tree *LocatorTree) insertParent(currPage, rightPage *Page,
	currKey LocatorKey) {

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
		rightPage.Parent = parent

		parent.Hash = parent.internalHash()
		tree.Height++
		tree.setRoot(parent)
	} else { //there exist a parent
		currIdx := slices.Index(parent.Children, currPage)
		if currIdx == -1 {
			panic("insert parent: current page is not a child of its parent")
		}

		parent.Keys = slices.Insert(parent.Keys, currIdx, currKey)
		parent.Children = slices.Insert(parent.Children, currIdx+1, rightPage)
		rightPage.Parent = parent
	}
	tree.internalSplit(parent)
}

func (tree *LocatorTree) internalSplit(currPage *Page) {
	if len(currPage.Children) <= tree.Order {
		return
	}

	mid := len(currPage.Keys) / 2
	currKey := currPage.Keys[mid]

	// right side
	rightKeys := append([]LocatorKey(nil), currPage.Keys[mid+1:]...)
	rightChildren := append([]*Page(nil), currPage.Children[mid+1:]...)

	rightPage := &Page{
		PageID:   tree.NextPageID,
		IsLeaf:   false,
		Parent:   currPage.Parent,
		Keys:     rightKeys,
		Children: rightChildren,
	}
	tree.NextPageID++
	for _, child := range rightPage.Children {
		child.Parent = rightPage
	}
	rightPage.Hash = rightPage.internalHash()

	// left side
	currPage.Keys = currPage.Keys[:mid:mid]
	currPage.Children = currPage.Children[: mid+1 : mid+1]
	currPage.Hash = currPage.internalHash()

	tree.insertParent(currPage, rightPage, currKey)
}

func (tree *LocatorTree) leafSplit(currPage *Page) {
	mid := len(currPage.Keys) / 2
	// right side
	rightKeys := append([]LocatorKey(nil), currPage.Keys[mid:]...)
	rightValues := append([]*LocatorValue(nil), currPage.Values[mid:]...)

	rightPage := &Page{
		PageID: tree.NextPageID,
		IsLeaf: true,
		Parent: currPage.Parent,
		Keys:   rightKeys,
		Values: rightValues,
		Next:   currPage.Next,
	}
	tree.NextPageID++
	currPage.Hash = currPage.leafHash()
	rightPage.Hash = rightPage.leafHash()

	// left side
	currPage.Keys = currPage.Keys[:mid:mid]
	currPage.Values = currPage.Values[:mid:mid]
	currPage.Next = rightPage

	tree.insertParent(currPage, rightPage, rightPage.Keys[0])
}

func (tree *LocatorTree) updatePathHashes(currPage *Page) {
	for currPage != nil {
		if currPage.IsLeaf {
			currPage.Hash = currPage.leafHash()
		} else {
			currPage.Hash = currPage.internalHash()
		}
		if currPage.Parent == nil {
			break
		}
		currPage = currPage.Parent
	}
	tree.setRoot(currPage)
}

//Main function

func (tree *LocatorTree) Insert(key LocatorKey, value *LocatorValue, currPage *Page) {
	//base case
	if currPage.IsLeaf {
		currIdx := currPage.findKeyIdx(key)
		currPage.Keys = slices.Insert(currPage.Keys, currIdx, key)
		currPage.Values = slices.Insert(currPage.Values, currIdx, value)
		if len(currPage.Keys) >= tree.Order {
			tree.leafSplit(currPage)
		}
		tree.LeafCount++
		tree.updatePathHashes(currPage)
		return
	}

	idx := currPage.findKeyIdx(key)
	tree.Insert(key, value, currPage.Children[idx])
}
