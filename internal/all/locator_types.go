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

// LocatorQuery describes one continuous range in the ALL key order (service,
// log type, region, event time, tenant, log ID). ServiceID, LogType and
// RegionID are exact matches and the time interval is half-open. The range
// covers every tenant, so one query and one range proof resolve all tenants.
//
// TenantID is optional. Empty means all tenants. When set, it selects one
// tenant's entries out of the verified range (FilterTenant); it does not change
// the range or the proof.
type LocatorQuery struct {
	TenantID  string
	ServiceID string
	LogType   string
	RegionID  string
	StartTime time.Time
	EndTime   time.Time
}

// LocatorEntry an object sent by the auditor
type LocatorEntry struct {
	PageID int64
	Key    LocatorKey
	Value  *LocatorValue
}

// LocatorProofStep contains one internal page on a leaf-to-root path.
// ChildHashes contains every child hash; the verifier replaces ChildIndex
// with the hash reconstructed at the preceding level.
type LocatorProofStep struct {
	PageID      int64
	Keys        []LocatorKey
	ChildIndex  int
	ChildHashes [][32]byte
}

// LocatorLeafProof contains a complete leaf and its path from parent to root.
type LocatorLeafProof struct {
	PageID     int64
	NextPageID *int64
	Keys       []LocatorKey
	Values     []*LocatorValue
	Path       []LocatorProofStep
}

type LocatorRangeProof struct {
	Leaves            []LocatorLeafProof
	ReconstructedRoot [32]byte
}

// LocatorRangeResult includes entries in [lower, upper), their adjacent
// boundaries, and the paths required to reconstruct the locator root.
type LocatorRangeResult struct {
	Entries     []LocatorEntry
	Predecessor *LocatorEntry
	Successor   *LocatorEntry
	Proof       LocatorRangeProof
}

type LocatorTree struct {
	RootPageID int64
	NextPageID int64
	RootHash   [32]byte
	RootPage   *Page

	Height    int
	LeafCount int64

	Order int //m: max children per internal page

	// deferHashes is set between BeginBulkLoad and FinishBulkLoad: inserts
	// and splits leave page hashes unset and FinishBulkLoad computes every
	// page hash once, bottom-up.
	deferHashes bool
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
