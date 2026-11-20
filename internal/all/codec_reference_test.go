package all

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"reflect"
	"testing"
	"time"
	"uuid"
)

// The decoder below is the page decoder as it was before it read from a byte cursor instead of a
// bytes.Reader. The current decoder must accept and reject exactly the same inputs and return the
// same pages.

// refUnmarshalPage restores the page contents stored in page_data. The caller
// restores PageID, Hash, ParentPageID, and Next from their Cassandra columns.
func refUnmarshalPage(data []byte) (Page, error) {
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

	keyCount, err := refReadUint32(reader)
	if err != nil {
		return Page{}, fmt.Errorf("unmarshal page: read key count: %w", err)
	}
	if uint64(keyCount) > uint64(reader.Len()/4) {
		return Page{}, fmt.Errorf("unmarshal page: invalid key count %d", keyCount)
	}
	keys := make([]LocatorKey, 0, keyCount)
	for range keyCount {
		keyData, err := refReadBytes(reader)
		if err != nil {
			return Page{}, fmt.Errorf("unmarshal page: read key: %w", err)
		}
		key, err := refUnmarshalKey(keyData)
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
			valueData, err := refReadBytes(reader)
			if err != nil {
				return Page{}, fmt.Errorf("unmarshal page: read value: %w", err)
			}
			value, err := refUnmarshalValue(valueData)
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
			pageID, err := refReadInt64(reader)
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

func refUnmarshalKey(data []byte) (LocatorKey, error) {
	reader := bytes.NewReader(data)
	tenantID, err := refReadString(reader)
	if err != nil {
		return LocatorKey{}, fmt.Errorf("unmarshal key: tenant ID: %w", err)
	}
	serviceID, err := refReadString(reader)
	if err != nil {
		return LocatorKey{}, fmt.Errorf("unmarshal key: service ID: %w", err)
	}
	logType, err := refReadString(reader)
	if err != nil {
		return LocatorKey{}, fmt.Errorf("unmarshal key: log type: %w", err)
	}
	regionID, err := refReadString(reader)
	if err != nil {
		return LocatorKey{}, fmt.Errorf("unmarshal key: region ID: %w", err)
	}
	eventTime, err := refReadInt64(reader)
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

func refUnmarshalValue(data []byte) (*LocatorValue, error) {
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

	regionID, err := refReadString(reader)
	if err != nil {
		return nil, fmt.Errorf("unmarshal value: region ID: %w", err)
	}
	shardID, err := refReadString(reader)
	if err != nil {
		return nil, fmt.Errorf("unmarshal value: shard ID: %w", err)
	}
	segmentID, err := refReadString(reader)
	if err != nil {
		return nil, fmt.Errorf("unmarshal value: segment ID: %w", err)
	}
	leafID, err := refReadString(reader)
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

func refReadUint32(reader *bytes.Reader) (uint32, error) {
	var value uint32
	if err := binary.Read(reader, binary.BigEndian, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func refReadInt64(reader *bytes.Reader) (int64, error) {
	var value int64
	if err := binary.Read(reader, binary.BigEndian, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func refReadBytes(reader *bytes.Reader) ([]byte, error) {
	length, err := refReadUint32(reader)
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

func refReadString(reader *bytes.Reader) (string, error) {
	value, err := refReadBytes(reader)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func marshalRandomPage(t *testing.T, random *rand.Rand, leaf bool, keys int) []byte {
	t.Helper()
	var page *Page
	if leaf {
		page = randomLeafPage(random, keys)
	} else {
		page = randomInternalPage(random, keys)
	}
	data, err := MarshalPage(*page)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sameDecoding(t *testing.T, label string, data []byte) {
	t.Helper()
	got, gotErr := UnmarshalPage(data)
	want, wantErr := refUnmarshalPage(data)
	if (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("%s: new error %v, old error %v", label, gotErr, wantErr)
	}
	if gotErr == nil && !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: decoded pages differ", label)
	}
}

func TestPageDecoderMatchesPreviousDecoder(t *testing.T) {
	random := rand.New(rand.NewSource(11))
	for _, leaf := range []bool{true, false} {
		for _, keys := range []int{0, 1, 3, 12} {
			data := marshalRandomPage(t, random, leaf, keys)
			sameDecoding(t, "intact", data)
			for cut := 0; cut < len(data); cut++ {
				sameDecoding(t, "truncated", data[:cut])
			}
			sameDecoding(t, "trailing byte", append(append([]byte(nil), data...), 0))
			for trial := 0; trial < 300; trial++ {
				mutated := append([]byte(nil), data...)
				for flips := 1 + random.Intn(3); flips > 0; flips-- {
					mutated[random.Intn(len(mutated))] ^= byte(1 + random.Intn(255))
				}
				sameDecoding(t, "mutated", mutated)
			}
		}
	}
}

func TestPageDecoderRoundTrip(t *testing.T) {
	random := rand.New(rand.NewSource(12))
	for trial := 0; trial < 40; trial++ {
		leaf := random.Intn(2) == 0
		var page *Page
		if leaf {
			page = randomLeafPage(random, random.Intn(60))
		} else {
			page = randomInternalPage(random, random.Intn(60))
		}
		data, err := MarshalPage(*page)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := UnmarshalPage(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded.Keys) != len(page.Keys) || decoded.IsLeaf != leaf {
			t.Fatal("round trip changed the page shape")
		}
		for index := range page.Keys {
			if decoded.Keys[index].Compare(page.Keys[index]) != 0 {
				t.Fatalf("key %d changed in the round trip", index)
			}
		}
	}
}

func BenchmarkUnmarshalLeafPage(b *testing.B) {
	data, err := MarshalPage(*randomLeafPage(rand.New(rand.NewSource(13)), 128))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := UnmarshalPage(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnmarshalLeafPagePrevious(b *testing.B) {
	data, err := MarshalPage(*randomLeafPage(rand.New(rand.NewSource(13)), 128))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := refUnmarshalPage(data); err != nil {
			b.Fatal(err)
		}
	}
}

var (
	_ = binary.BigEndian
	_ = bytes.NewReader
	_ = fmt.Sprint
	_ = io.EOF
	_ = time.Now
	_ uuid.UUID
)
