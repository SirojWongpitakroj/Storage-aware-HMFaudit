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
