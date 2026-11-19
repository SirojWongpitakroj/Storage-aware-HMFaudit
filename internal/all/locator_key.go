// Package all implements Authenticated Log Locator
package all

import (
	"bytes"
	"encoding/binary"
)

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

func writeString(buf *bytes.Buffer, s string) {
	binary.Write(buf, binary.BigEndian, uint32(len(s)))
	buf.WriteString(s)
}

func encodeKey(key LocatorKey) []byte {
	var buf bytes.Buffer

	writeString(&buf, key.TenantID)
	writeString(&buf, key.ServiceID)
	writeString(&buf, key.LogType)
	writeString(&buf, key.RegionID)

	//timestamp
	binary.Write(
		&buf, binary.BigEndian, key.EventTime.UnixNano(),
	)

	buf.Write(key.LogID[:])

	return buf.Bytes()
}

func encodeValue(value *LocatorValue) []byte {
	var buf bytes.Buffer

	if value == nil {
		buf.WriteByte(0)
		return buf.Bytes()
	}

	buf.WriteByte(1)
	writeString(&buf, value.RegionID)
	writeString(&buf, value.ShardID)
	writeString(&buf, value.SegmentID)
	writeString(&buf, value.LeafID)

	return buf.Bytes()
}
