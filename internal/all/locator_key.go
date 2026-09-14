package domain

import (
	"bytes"
	"encoding/binary"
)

// compare lexicographically (Tenant, Service, LogType, Region, Timestamp)
func (key *LocatorKey) Less(other LocatorKey) bool {
	if key.TenantID != other.TenantID {
		return key.TenantID < other.TenantID
	}
	if key.ServiceID != other.ServiceID {
		return key.ServiceID < other.ServiceID
	}
	if key.LogType != other.LogType {
		return key.LogType < other.LogType
	}
	if key.RegionID != other.RegionID {
		return key.RegionID < other.RegionID
	}
	if !key.EventTime.Equal(other.EventTime) {
		return key.EventTime.Before(other.EventTime)
	}
	return key.LogID.Compare(other.LogID) < 0
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
