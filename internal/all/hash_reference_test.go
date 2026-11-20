package all

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"
	"uuid"
)

// The functions below are the page and key encodings exactly as they were before the hashing was
// rewritten to append into a reused buffer. The current code must produce the same bytes and hashes.

func refWriteString(buf *bytes.Buffer, s string) {
	binary.Write(buf, binary.BigEndian, uint32(len(s)))
	buf.WriteString(s)
}

func refEncodeKey(key LocatorKey) []byte {
	var buf bytes.Buffer
	refWriteString(&buf, key.TenantID)
	refWriteString(&buf, key.ServiceID)
	refWriteString(&buf, key.LogType)
	refWriteString(&buf, key.RegionID)
	binary.Write(&buf, binary.BigEndian, key.EventTime.UnixNano())
	buf.Write(key.LogID[:])
	return buf.Bytes()
}

func refEncodeValue(value *LocatorValue) []byte {
	var buf bytes.Buffer
	if value == nil {
		buf.WriteByte(0)
		return buf.Bytes()
	}
	buf.WriteByte(1)
	refWriteString(&buf, value.RegionID)
	refWriteString(&buf, value.ShardID)
	refWriteString(&buf, value.SegmentID)
	refWriteString(&buf, value.LeafID)
	return buf.Bytes()
}

func refLeafHash(page *Page) [32]byte {
	var encoded bytes.Buffer
	encoded.WriteString("LEAF")
	binary.Write(&encoded, binary.BigEndian, page.PageID)
	if page.Next == nil {
		encoded.WriteByte(0)
	} else {
		encoded.WriteByte(1)
		binary.Write(&encoded, binary.BigEndian, page.Next.PageID)
	}
	for index, key := range page.Keys {
		encoded.Write(refEncodeKey(key))
		encoded.Write(refEncodeValue(page.Values[index]))
	}
	return sha256.Sum256(encoded.Bytes())
}

func refInternalHash(page *Page) [32]byte {
	concat := []byte("INTERNAL")
	for _, key := range page.Keys {
		concat = append(concat, refEncodeKey(key)...)
	}
	for _, child := range page.Children {
		concat = append(concat, child.Hash[:]...)
	}
	return sha256.Sum256(concat)
}

func refReconstructLocatorRoot(proof LocatorLeafProof) [32]byte {
	leaf := Page{PageID: proof.PageID, IsLeaf: true, Keys: proof.Keys, Values: proof.Values}
	if proof.NextPageID != nil {
		leaf.Next = &Page{PageID: *proof.NextPageID}
	}
	current := refLeafHash(&leaf)
	for _, step := range proof.Path {
		children := make([]*Page, len(step.ChildHashes))
		for index, hash := range step.ChildHashes {
			children[index] = &Page{Hash: hash}
		}
		children[step.ChildIndex].Hash = current
		parent := Page{Keys: step.Keys, Children: children}
		current = refInternalHash(&parent)
	}
	return current
}

func randomString(random *rand.Rand) string {
	words := []string{"", "T0", "tenant-17", "spark-executor", "INFO", "R3", "é-unicode-ß", "a longer service name with spaces"}
	return words[random.Intn(len(words))]
}

func randomKey(random *rand.Rand) LocatorKey {
	var id uuid.UUID
	random.Read(id[:])
	return LocatorKey{
		TenantID: randomString(random), ServiceID: randomString(random), LogType: randomString(random),
		RegionID: randomString(random), LogID: id,
		EventTime: time.Unix(1_480_000_000+random.Int63n(1<<24), random.Int63n(1_000_000_000)).UTC(),
	}
}

func randomValue(random *rand.Rand) *LocatorValue {
	if random.Intn(5) == 0 {
		return nil
	}
	return &LocatorValue{RegionID: randomString(random), ShardID: randomString(random),
		SegmentID: randomString(random), LeafID: randomString(random)}
}

func randomLeafPage(random *rand.Rand, keys int) *Page {
	page := &Page{PageID: random.Int63n(1 << 40), IsLeaf: true}
	for i := 0; i < keys; i++ {
		page.Keys = append(page.Keys, randomKey(random))
		page.Values = append(page.Values, randomValue(random))
	}
	if random.Intn(3) > 0 {
		page.Next = &Page{PageID: random.Int63n(1 << 40)}
	}
	return page
}

func randomInternalPage(random *rand.Rand, keys int) *Page {
	page := &Page{PageID: random.Int63n(1 << 40)}
	for i := 0; i < keys; i++ {
		page.Keys = append(page.Keys, randomKey(random))
	}
	for i := 0; i <= keys; i++ {
		child := &Page{}
		random.Read(child.Hash[:])
		page.Children = append(page.Children, child)
	}
	return page
}

func TestKeyAndValueEncodingsAreUnchanged(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	for i := 0; i < 500; i++ {
		key, value := randomKey(random), randomValue(random)
		if !bytes.Equal(encodeKey(key), refEncodeKey(key)) {
			t.Fatalf("key encoding differs for %+v", key)
		}
		if !bytes.Equal(encodeValue(value), refEncodeValue(value)) {
			t.Fatalf("value encoding differs for %+v", value)
		}
	}
	if !bytes.Equal(encodeValue(nil), refEncodeValue(nil)) {
		t.Fatal("nil value encoding differs")
	}
}

func TestPageHashesAreUnchanged(t *testing.T) {
	random := rand.New(rand.NewSource(2))
	for _, keys := range []int{0, 1, 2, 7, 64, 300} {
		leaf := randomLeafPage(random, keys)
		if got, want := leaf.leafHash(), refLeafHash(leaf); got != want {
			t.Fatalf("leaf page with %d keys: hash differs", keys)
		}
		internal := randomInternalPage(random, keys)
		if got, want := internal.internalHash(), refInternalHash(internal); got != want {
			t.Fatalf("internal page with %d keys: hash differs", keys)
		}
	}
}

func TestReconstructLocatorRootIsUnchanged(t *testing.T) {
	random := rand.New(rand.NewSource(4))
	for trial := 0; trial < 50; trial++ {
		leaf := randomLeafPage(random, 1+random.Intn(40))
		proof := LocatorLeafProof{PageID: leaf.PageID, Keys: leaf.Keys, Values: leaf.Values}
		if leaf.Next != nil {
			next := leaf.Next.PageID
			proof.NextPageID = &next
		}
		for depth := random.Intn(5); depth >= 0; depth-- {
			keys := 1 + random.Intn(30)
			step := LocatorProofStep{PageID: random.Int63n(1 << 30), ChildIndex: random.Intn(keys + 1)}
			for i := 0; i < keys; i++ {
				step.Keys = append(step.Keys, randomKey(random))
			}
			for i := 0; i <= keys; i++ {
				var hash [32]byte
				random.Read(hash[:])
				step.ChildHashes = append(step.ChildHashes, hash)
			}
			proof.Path = append(proof.Path, step)
		}
		got, err := ReconstructLocatorRoot(proof)
		if err != nil {
			t.Fatal(err)
		}
		if want := refReconstructLocatorRoot(proof); got != want {
			t.Fatalf("trial %d: reconstructed root differs", trial)
		}
	}
}

func TestPageHashingAllocatesLittle(t *testing.T) {
	random := rand.New(rand.NewSource(5))
	leaf, internal := randomLeafPage(random, 64), randomInternalPage(random, 64)
	leaf.leafHash() // warm the buffer pool
	internal.internalHash()
	if allocs := testing.AllocsPerRun(50, func() { _ = leaf.leafHash() }); allocs > 1 {
		t.Errorf("leafHash allocated %v times per call", allocs)
	}
	if allocs := testing.AllocsPerRun(50, func() { _ = internal.internalHash() }); allocs > 1 {
		t.Errorf("internalHash allocated %v times per call", allocs)
	}
}

func BenchmarkLeafHash(b *testing.B) {
	leaf := randomLeafPage(rand.New(rand.NewSource(6)), 64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = leaf.leafHash()
	}
}

func BenchmarkReconstructLocatorRoot(b *testing.B) {
	random := rand.New(rand.NewSource(7))
	leaf := randomLeafPage(random, 64)
	proof := LocatorLeafProof{PageID: leaf.PageID, Keys: leaf.Keys, Values: leaf.Values}
	for depth := 0; depth < 4; depth++ {
		step := LocatorProofStep{PageID: int64(depth), ChildIndex: 3}
		for i := 0; i < 63; i++ {
			step.Keys = append(step.Keys, randomKey(random))
		}
		step.ChildHashes = make([][32]byte, 64)
		proof.Path = append(proof.Path, step)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ReconstructLocatorRoot(proof); err != nil {
			b.Fatal(err)
		}
	}
}
