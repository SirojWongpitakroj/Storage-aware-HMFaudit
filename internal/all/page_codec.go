package all

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"time"
	"uuid"
)

// Version 2 binds PageID and NextPageID into leaf hashes. Existing version 1
// ALL pages must be rebuilt before they can be queried with this code.
const PageFormatVersion int32 = 2

// MarshalPage returns the deterministic on-disk representation of one page.
func MarshalPage(page Page) ([]byte, error) {
	if page.IsLeaf && len(page.Keys) != len(page.Values) {
		return nil, fmt.Errorf("marshal page %d: leaf keys and values do not match", page.PageID)
	}
	if !page.IsLeaf && len(page.Children) != len(page.Keys)+1 {
		return nil, fmt.Errorf("marshal page %d: internal keys and children do not match", page.PageID)
	}

	var data bytes.Buffer
	data.WriteByte(byte(PageFormatVersion))
	if page.IsLeaf {
		data.WriteByte(1)
	} else {
		data.WriteByte(0)
	}
	writeUint32(&data, uint32(len(page.Keys)))
	for _, key := range page.Keys {
		writeBytes(&data, encodeKey(key))
	}

	if page.IsLeaf {
		for _, value := range page.Values {
			writeBytes(&data, encodeValue(value)) //serailize page.Values
		}
		return data.Bytes(), nil
	}

	for _, child := range page.Children {
		writeInt64(&data, child.PageID) //serialize page.Children pageID and hash
		data.Write(child.Hash[:])
	}
	return data.Bytes(), nil
}

// UnmarshalPage restores the page contents stored in page_data. The caller
// restores PageID, Hash, ParentPageID, and Next from their Cassandra columns.
func UnmarshalPage(data []byte) (Page, error) {
	reader := bytes.NewReader(data)

	version, err := reader.ReadByte()
	if err != nil {
		return Page{}, fmt.Errorf("unmarshal page: read format version: %w", err)
	}
	if int32(version) != PageFormatVersion {
		return Page{}, fmt.Errorf("unmarshal page: unsupported format version %d", version)
	}

	isLeaf, err := reader.ReadByte()
	if err != nil {
		return Page{}, fmt.Errorf("unmarshal page: read page type: %w", err)
	}
	if isLeaf != 0 && isLeaf != 1 {
		return Page{}, fmt.Errorf("unmarshal page: invalid page type %d", isLeaf)
	}

	keyCount, err := readUint32(reader)
	if err != nil {
		return Page{}, fmt.Errorf("unmarshal page: read key count: %w", err)
	}
	if uint64(keyCount) > uint64(reader.Len()/4) {
		return Page{}, fmt.Errorf("unmarshal page: invalid key count %d", keyCount)
	}
	keys := make([]LocatorKey, 0, keyCount)
	for range keyCount {
		keyData, err := readBytes(reader)
		if err != nil {
			return Page{}, fmt.Errorf("unmarshal page: read key: %w", err)
		}
		key, err := unmarshalKey(keyData)
		if err != nil {
			return Page{}, err
		}
		keys = append(keys, key)
	}

	page := Page{
		IsLeaf: isLeaf == 1,
		Keys:   keys,
	}
	if page.IsLeaf {
		if uint64(keyCount) > uint64(reader.Len()/4) {
			return Page{}, fmt.Errorf("unmarshal page: invalid value count %d", keyCount)
		}
		page.Values = make([]*LocatorValue, 0, keyCount)
		for range keyCount {
			valueData, err := readBytes(reader)
			if err != nil {
				return Page{}, fmt.Errorf("unmarshal page: read value: %w", err)
			}
			value, err := unmarshalValue(valueData)
			if err != nil {
				return Page{}, err
			}
			page.Values = append(page.Values, value)
		}
	} else {
		childCount := uint64(keyCount) + 1
		if childCount > uint64(reader.Len()/40) {
			return Page{}, fmt.Errorf("unmarshal page: invalid child count %d", childCount)
		}
		page.Children = make([]*Page, 0, keyCount+1)
		for range keyCount + 1 {
			pageID, err := readInt64(reader)
			if err != nil {
				return Page{}, fmt.Errorf("unmarshal page: read child page ID: %w", err)
			}
			child := &Page{PageID: pageID}
			if _, err := io.ReadFull(reader, child.Hash[:]); err != nil {
				return Page{}, fmt.Errorf("unmarshal page: read child hash: %w", err)
			}
			page.Children = append(page.Children, child)
		}
	}

	if reader.Len() != 0 {
		return Page{}, fmt.Errorf("unmarshal page: unexpected trailing data")
	}
	return page, nil
}

// UnmarshalStoredPage restores the page fields stored outside page_data and
// verifies that the decoded contents produce the persisted page hash.
func UnmarshalStoredPage(data []byte, pageID int64, parentPageID, nextPageID *int64,
	pageHash []byte) (Page, error) {

	if len(pageHash) != 32 {
		return Page{}, fmt.Errorf("unmarshal stored page %d: page hash has %d bytes, want 32", pageID, len(pageHash))
	}

	page, err := UnmarshalPage(data)
	if err != nil {
		return Page{}, fmt.Errorf("unmarshal stored page %d: %w", pageID, err)
	}
	page.PageID = pageID
	page.ParentPageID = copyInt64Pointer(parentPageID)
	if nextPageID != nil {
		page.Next = &Page{PageID: *nextPageID}
	}
	copy(page.Hash[:], pageHash)

	computed := page.internalHash()
	if page.IsLeaf {
		computed = page.leafHash()
	}
	if subtle.ConstantTimeCompare(computed[:], page.Hash[:]) != 1 {
		return Page{}, fmt.Errorf("unmarshal stored page %d: page hash does not match page data", pageID)
	}
	return page, nil
}

func copyInt64Pointer(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func unmarshalKey(data []byte) (LocatorKey, error) {
	reader := bytes.NewReader(data)
	tenantID, err := readString(reader)
	if err != nil {
		return LocatorKey{}, fmt.Errorf("unmarshal key: tenant ID: %w", err)
	}
	serviceID, err := readString(reader)
	if err != nil {
		return LocatorKey{}, fmt.Errorf("unmarshal key: service ID: %w", err)
	}
	logType, err := readString(reader)
	if err != nil {
		return LocatorKey{}, fmt.Errorf("unmarshal key: log type: %w", err)
	}
	regionID, err := readString(reader)
	if err != nil {
		return LocatorKey{}, fmt.Errorf("unmarshal key: region ID: %w", err)
	}
	eventTime, err := readInt64(reader)
	if err != nil {
		return LocatorKey{}, fmt.Errorf("unmarshal key: event time: %w", err)
	}
	var logID uuid.UUID
	if _, err := io.ReadFull(reader, logID[:]); err != nil {
		return LocatorKey{}, fmt.Errorf("unmarshal key: log ID: %w", err)
	}
	if reader.Len() != 0 {
		return LocatorKey{}, fmt.Errorf("unmarshal key: unexpected trailing data")
	}

	return LocatorKey{
		LogID:     logID,
		EventTime: time.Unix(0, eventTime).UTC(),
		RegionID:  regionID,
		TenantID:  tenantID,
		ServiceID: serviceID,
		LogType:   logType,
	}, nil
}

func unmarshalValue(data []byte) (*LocatorValue, error) {
	reader := bytes.NewReader(data)
	present, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("unmarshal value: read presence: %w", err)
	}
	if present == 0 {
		if reader.Len() != 0 {
			return nil, fmt.Errorf("unmarshal value: unexpected trailing data")
		}
		return nil, nil
	}
	if present != 1 {
		return nil, fmt.Errorf("unmarshal value: invalid presence %d", present)
	}

	regionID, err := readString(reader)
	if err != nil {
		return nil, fmt.Errorf("unmarshal value: region ID: %w", err)
	}
	shardID, err := readString(reader)
	if err != nil {
		return nil, fmt.Errorf("unmarshal value: shard ID: %w", err)
	}
	segmentID, err := readString(reader)
	if err != nil {
		return nil, fmt.Errorf("unmarshal value: segment ID: %w", err)
	}
	leafID, err := readString(reader)
	if err != nil {
		return nil, fmt.Errorf("unmarshal value: leaf ID: %w", err)
	}
	if reader.Len() != 0 {
		return nil, fmt.Errorf("unmarshal value: unexpected trailing data")
	}

	return &LocatorValue{
		RegionID:  regionID,
		ShardID:   shardID,
		SegmentID: segmentID,
		LeafID:    leafID,
	}, nil
}

func writeUint32(data *bytes.Buffer, value uint32) {
	binary.Write(data, binary.BigEndian, value)
}

func writeInt64(data *bytes.Buffer, value int64) {
	binary.Write(data, binary.BigEndian, value)
}

func writeBytes(data *bytes.Buffer, value []byte) {
	writeUint32(data, uint32(len(value))) //write length of the key or values first
	data.Write(value)
}

func readUint32(reader *bytes.Reader) (uint32, error) {
	var value uint32
	if err := binary.Read(reader, binary.BigEndian, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func readInt64(reader *bytes.Reader) (int64, error) {
	var value int64
	if err := binary.Read(reader, binary.BigEndian, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func readBytes(reader *bytes.Reader) ([]byte, error) {
	length, err := readUint32(reader)
	if err != nil {
		return nil, err
	}
	if uint64(length) > uint64(reader.Len()) {
		return nil, io.ErrUnexpectedEOF
	}

	value := make([]byte, length)
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, err
	}
	return value, nil
}

func readString(reader *bytes.Reader) (string, error) {
	value, err := readBytes(reader)
	if err != nil {
		return "", err
	}
	return string(value), nil
}
