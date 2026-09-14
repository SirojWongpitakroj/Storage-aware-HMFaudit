package domain

import "crypto/sha256"

func (page *Page) concatEncKeys(prefix []byte) []byte {
	for _, key := range page.Keys {
		prefix = append(prefix, encodeKey(key)...)
	}
	return prefix
}

func (page *Page) concatEncChild(prefix []byte) []byte {
	for _, child := range page.Children {
		prefix = append(prefix, child.Hash[:]...)
	}
	return prefix
}

func (page *Page) findKeyIdx(currKey LocatorKey) int {
	//-1 for last element
	currKeyIdx := len(page.Keys) //last elem
	for i, key := range page.Keys {
		if currKey.Less(key) {
			currKeyIdx = i
			break
		}
	}
	return currKeyIdx
}

func (page *Page) leafHash() [32]byte {
	concatLeaf := []byte("LEAF")
	concatLeaf = page.concatEncKeys(concatLeaf)
	return sha256.Sum256(concatLeaf)
}

func (page *Page) internalHash() [32]byte {
	concatInternal := []byte("INTERNAL")
	concatInternal = page.concatEncKeys(concatInternal)
	concatInternal = page.concatEncChild(concatInternal)
	return sha256.Sum256(concatInternal)
}
