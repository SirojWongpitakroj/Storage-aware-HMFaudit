package all

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
	RootPageID int64
	NextPageID int64
	RootHash   [32]byte
	RootPage   *Page

	Height    int
	LeafCount int64

	Order int //m: max children per internal page
}

// LocatorUpdate contains the final ALL state changed by one insertion.
type LocatorUpdate struct {
	Pages []Page

	RootPageID  int64
	RootHash    [32]byte
	NextPageID  int64
	Height      int
	RecordCount int64
}
