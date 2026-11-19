package all

// Bulk loading computes the same tree as one Insert per record -- the same
// pages, page IDs, keys, values and hashes, and therefore the same root --
// but hashes every page once at the end instead of re-hashing the path from
// the changed leaf to the root after every insert. Building a large tree
// (for example a 10M-record benchmark fixture) then costs one hash per page
// instead of one per page on every insertion path.
//
// Between BeginBulkLoad and FinishBulkLoad page hashes and RootHash are not
// valid: do not resolve, prove or persist the tree until FinishBulkLoad.

// BeginBulkLoad defers all page hashing until FinishBulkLoad.
func (tree *LocatorTree) BeginBulkLoad() { tree.deferHashes = true }

// FinishBulkLoad computes every page hash bottom-up and sets RootHash.
func (tree *LocatorTree) FinishBulkLoad() {
	tree.deferHashes = false
	hashSubtree(tree.RootPage)
	tree.RootHash = tree.RootPage.Hash
}

// rehashPage sets a page's hash from its current contents (an internal
// page's hash covers its children's hashes), unless hashing is deferred.
func (tree *LocatorTree) rehashPage(page *Page) {
	if tree.deferHashes {
		return
	}
	if page.IsLeaf {
		page.Hash = page.leafHash()
	} else {
		page.Hash = page.internalHash()
	}
}

func hashSubtree(page *Page) {
	if page.IsLeaf {
		page.Hash = page.leafHash()
		return
	}
	for _, child := range page.Children {
		hashSubtree(child)
	}
	page.Hash = page.internalHash()
}
