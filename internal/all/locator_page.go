package all

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

// Page struct
type Page struct {
	PageID int64
	Hash   [32]byte

	IsLeaf bool
	Keys   []LocatorKey

	Parent       *Page
	ParentPageID *int64

	//used by leaf pages
	Values []*LocatorValue
	Next   *Page

	//used by internal pages
	Children []*Page
}

func (page *Page) concatEncKeys(prefix []byte) []byte {
	for _, key := range page.Keys {
		prefix = appendKey(prefix, key)
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

// hashBuffers holds the scratch buffers page hashing assembles its message in, so that hashing a
// page allocates nothing once the buffers have grown to the size of the pages in use.
var hashBuffers = sync.Pool{New: func() any { buffer := make([]byte, 0, 4096); return &buffer }}

// sumMessage hashes the message build appends to a pooled buffer.
func sumMessage(build func(dst []byte) []byte) [32]byte {
	buffer := hashBuffers.Get().(*[]byte)
	message := build((*buffer)[:0])
	sum := sha256.Sum256(message)
	*buffer = message[:0]
	hashBuffers.Put(buffer)
	return sum
}

func (page *Page) leafHash() [32]byte {
	return sumMessage(func(dst []byte) []byte {
		dst = append(dst, "LEAF"...)
		dst = binary.BigEndian.AppendUint64(dst, uint64(page.PageID))
		if page.Next == nil {
			dst = append(dst, 0)
		} else {
			dst = append(dst, 1)
			dst = binary.BigEndian.AppendUint64(dst, uint64(page.Next.PageID))
		}
		for index, key := range page.Keys {
			dst = appendKey(dst, key)
			dst = appendValue(dst, page.Values[index])
		}
		return dst
	})
}

func (page *Page) internalHash() [32]byte {
	return sumMessage(func(dst []byte) []byte {
		dst = append(dst, "INTERNAL"...)
		dst = page.concatEncKeys(dst)
		return page.concatEncChild(dst)
	})
}

// internalHashOf is internalHash of an internal page with the given keys and child hashes, where
// child number replaced has hash replacement instead of its listed one (replaced < 0: none replaced).
// It builds no Page, which is what a proof verifier needs for every step of a path.
func internalHashOf(keys []LocatorKey, childHashes [][32]byte, replaced int, replacement [32]byte) [32]byte {
	return sumMessage(func(dst []byte) []byte {
		dst = append(dst, "INTERNAL"...)
		for _, key := range keys {
			dst = appendKey(dst, key)
		}
		for index := range childHashes {
			if index == replaced {
				dst = append(dst, replacement[:]...)
			} else {
				dst = append(dst, childHashes[index][:]...)
			}
		}
		return dst
	})
}
