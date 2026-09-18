package hmf

import (
	"crypto/sha256"
	"encoding/binary"
)

const treeCommitmentDomain = "HMF_TREE_V1"

// CommitSegmentRoot binds a raw Segment Merkle root to its physical identity
// and leaf count before it is inserted into the Shard tree.
func CommitSegmentRoot(regionID string, shardID, segmentID, leafCount int64,
	rawRoot [32]byte) [32]byte {
	return commitTreeRoot("SEGMENT", regionID, shardID, segmentID, leafCount, rawRoot)
}

// CommitShardRoot binds a raw Shard Merkle root before it is inserted into the
// Region tree.
func CommitShardRoot(regionID string, shardID, leafCount int64,
	rawRoot [32]byte) [32]byte {
	return commitTreeRoot("SHARD", regionID, shardID, -1, leafCount, rawRoot)
}

// CommitRegionRoot binds a raw Region Merkle root before it is inserted into
// the Global tree.
func CommitRegionRoot(regionID string, leafCount int64, rawRoot [32]byte) [32]byte {
	return commitTreeRoot("REGION", regionID, -1, -1, leafCount, rawRoot)
}

// CommitGlobalRoot is the externally anchored R_G commitment.
func CommitGlobalRoot(leafCount int64, rawRoot [32]byte) [32]byte {
	return commitTreeRoot("GLOBAL", "", -1, -1, leafCount, rawRoot)
}

func commitTreeRoot(kind, regionID string, shardID, segmentID, leafCount int64,
	rawRoot [32]byte) [32]byte {
	hasher := sha256.New()
	writeCommitmentString(hasher, treeCommitmentDomain)
	writeCommitmentString(hasher, kind)
	writeCommitmentString(hasher, regionID)
	writeCommitmentInt64(hasher, shardID)
	writeCommitmentInt64(hasher, segmentID)
	writeCommitmentInt64(hasher, leafCount)
	_, _ = hasher.Write(rawRoot[:])
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

type commitmentWriter interface {
	Write([]byte) (int, error)
}

func writeCommitmentString(writer commitmentWriter, value string) {
	length := [4]byte{}
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}

func writeCommitmentInt64(writer commitmentWriter, value int64) {
	encoded := [8]byte{}
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	_, _ = writer.Write(encoded[:])
}
