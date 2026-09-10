package domain

import (
	"crypto/sha256"
)

func HashPair(left, right *[32]byte) [32]byte {
	if right == nil {
		return sha256.Sum256((*left)[:])
	}

	combined := append((*left)[:], (*right)[:]...)
	return sha256.Sum256(combined)
}

func ComputeLeafHash(nonce, c, t, AD []byte) [32]byte {
	combined := append([]byte("LOG-LEAF"), nonce...)
	combined = append(combined, c...)
	combined = append(combined, t...)
	combined = append(combined, AD...)
	return sha256.Sum256(combined)
}
