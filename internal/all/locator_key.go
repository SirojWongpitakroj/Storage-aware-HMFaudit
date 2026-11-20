// Package all implements Authenticated Log Locator
package all

import "encoding/binary"

// Compare compares locator keys lexicographically by TenantID, ServiceID,
// LogType, RegionID, EventTime, and LogID.
//
// TenantID leads, so a query that names a tenant, service, log type and region
// and gives a time range is ONE continuous key range that holds exactly that
// tenant's logs for the interval. The range proof therefore covers only the
// queried tenant; no other tenant's entries are read, proven or filtered.
func (key LocatorKey) Compare(other LocatorKey) int {
	if key.TenantID != other.TenantID {
		if key.TenantID < other.TenantID {
			return -1
		}
		return 1
	}
	if key.ServiceID != other.ServiceID {
		if key.ServiceID < other.ServiceID {
			return -1
		}
		return 1
	}
	if key.LogType != other.LogType {
		if key.LogType < other.LogType {
			return -1
		}
		return 1
	}
	if key.RegionID != other.RegionID {
		if key.RegionID < other.RegionID {
			return -1
		}
		return 1
	}
	if !key.EventTime.Equal(other.EventTime) {
		if key.EventTime.Before(other.EventTime) {
			return -1
		}
		return 1
	}
	return key.LogID.Compare(other.LogID)
}

// Less reports whether key sorts before other.
func (key *LocatorKey) Less(other LocatorKey) bool {
	return key.Compare(other) < 0
}

// appendString appends a uint32 big-endian length and the string bytes.
func appendString(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
	return append(dst, s...)
}

// appendKey appends the canonical key encoding: the tenant, service, log type and region as
// length-prefixed strings, the event time in Unix nanoseconds (big-endian int64) and the 16 log-ID bytes.
func appendKey(dst []byte, key LocatorKey) []byte {
	dst = appendString(dst, key.TenantID)
	dst = appendString(dst, key.ServiceID)
	dst = appendString(dst, key.LogType)
	dst = appendString(dst, key.RegionID)
	dst = binary.BigEndian.AppendUint64(dst, uint64(key.EventTime.UnixNano()))
	return append(dst, key.LogID[:]...)
}

// appendValue appends the canonical value encoding: 0 for no value, else 1 and four length-prefixed strings.
func appendValue(dst []byte, value *LocatorValue) []byte {
	if value == nil {
		return append(dst, 0)
	}
	dst = append(dst, 1)
	dst = appendString(dst, value.RegionID)
	dst = appendString(dst, value.ShardID)
	dst = appendString(dst, value.SegmentID)
	return appendString(dst, value.LeafID)
}

func encodeKey(key LocatorKey) []byte { return appendKey(nil, key) }

func encodeValue(value *LocatorValue) []byte { return appendValue(nil, value) }
