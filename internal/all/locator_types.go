package domain

import (
	"time"
	"uuid"
)

// tree struct
type LocatorKey struct {
	LogID uuid.UUID

	EventTime time.Time
	RegionID  string
	TenantID  string
	ServiceID string
	LogType   string
}

type LocatorValue struct {
	RegionID  string
	ShardID   string
	SegmentID string
	LeafID    string
}

type LocatorTree struct {
	RootPageID uint64
	NextPageID uint64
	RootHash   [32]byte
	RootPage   *Page

	Height    int
	LeafCount int

	Order int //m: max children per internal page
}

// page struct
type Page struct {
	PageID uint64
	Hash   [32]byte

	IsLeaf bool
	Keys   []LocatorKey

	Parent *Page

	//used by leaf pages
	Values []*LocatorValue
	Next   *Page

	//used by internal pages
	Children []*Page
}
