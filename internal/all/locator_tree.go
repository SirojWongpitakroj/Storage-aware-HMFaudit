package domain

import (
	"slices"
)

// Merkle B+ tree
func NewLocatorTree(order int) *LocatorTree {
	tree := LocatorTree{
		RootPageID: 0,
		RootPage: &Page{
			PageID: uint64(0),
			IsLeaf: true,
			Keys:   make([]LocatorKey, 0, order-1),
			Values: make([]*LocatorValue, 0, order),
		},
		NextPageID: 1,
		Order:      order,
		Height:     0,
		LeafCount:  0,
	}
	return &tree
}

func (tree *LocatorTree) setRoot(currPage *Page) {
	tree.RootPageID = currPage.PageID
	tree.RootHash = currPage.Hash
	tree.RootPage = currPage
}

func (tree *LocatorTree) insertParent(currPage, rightPage *Page) {
	parent := currPage.Parent
	currKey := rightPage.Keys[0]

	//no parent
	if parent == nil {
		parent = &Page{
			PageID:   uint64(tree.NextPageID),
			IsLeaf:   false,
			Keys:     make([]LocatorKey, 0, tree.Order-1),
			Children: make([]*Page, 0, tree.Order),
		}
		tree.NextPageID++

		parent.Keys = append(parent.Keys, currKey)

		parent.Children = append(parent.Children, currPage)
		parent.Children = append(parent.Children, rightPage)
	} else { //there exist a parent
		//find currKey
		currIdx := parent.findKeyIdx(currKey)

		//insert newKey
		if currIdx == len(parent.Keys) { //last element (edge case)
			parent.Keys = append(parent.Keys, currKey)
		} else { //in the middle insertion
			parent.Keys = slices.Insert(parent.Keys, currIdx, currKey)
		}

		//assign new children to rightPage
		parent.Children = slices.Insert(parent.Children, currIdx+1, rightPage)
	}
	tree.internalSplit(parent)
}

func (tree *LocatorTree) internalSplit(currPage *Page) {
	if len(currPage.Children) <= tree.Order {
		return
	}
	//full
	mid := len(currPage.Keys) / 2
	// right side
	rightKeys := append([]LocatorKey(nil), currPage.Keys[mid:]...)
	rightChildren := append([]*Page{}, currPage.Children[mid:]...)

	rightPage := &Page{
		PageID:   uint64(tree.NextPageID),
		IsLeaf:   false,
		Parent:   currPage.Parent,
		Keys:     rightKeys,
		Children: rightChildren,
	}
	tree.NextPageID++
	//set rightPage PageHash
	rightPage.Hash = rightPage.internalHash()

	// left side
	currPage.Keys = currPage.Keys[:mid:mid]
	currPage.Children = currPage.Children[: mid+1 : mid+1]

	//set parent
	tree.insertParent(currPage, rightPage)
}

func (tree *LocatorTree) leafSplit(currPage *Page) {
	mid := len(currPage.Keys) / 2
	// right side
	rightKeys := append([]LocatorKey(nil), currPage.Keys[mid:]...)
	rightValues := append([]*LocatorValue(nil), currPage.Values[mid:]...)

	rightPage := &Page{
		PageID: uint64(tree.NextPageID),
		IsLeaf: true,
		Parent: currPage.Parent,
		Keys:   rightKeys,
		Values: rightValues,
		Next:   currPage.Next,
	}
	tree.NextPageID++
	//set rightPage PageHash
	rightPage.Hash = rightPage.leafHash()

	// left side
	currPage.Keys = currPage.Keys[:mid:mid]
	currPage.Values = currPage.Values[:mid:mid]
	currPage.Next = rightPage

	//set parent
	tree.insertParent(currPage, rightPage)
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

func (tree *LocatorTree) Insert(key LocatorKey, value *LocatorValue, currPage *Page) {
	//base case
	if currPage.IsLeaf {
		currIdx := currPage.findKeyIdx(key)
		currPage.Keys = slices.Insert(currPage.Keys, currIdx, key)
		currPage.Values = slices.Insert(currPage.Values, currIdx, value)
		if len(currPage.Keys) > tree.Order {
			tree.leafSplit(currPage)
		}
		tree.updatePathHashes(currPage)
		return
	}

	idx := currPage.findKeyIdx(key)
	tree.Insert(key, value, currPage.Children[idx])
}
