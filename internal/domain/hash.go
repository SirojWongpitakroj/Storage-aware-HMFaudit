package domain

import (
	"crypto/sha256"
)

func HashPair(prefix string, left, right *[32]byte) [32]byte {

	combined := append([]byte(prefix), (*left)[:]...)
	if right != nil {
		combined = append(combined, (*right)[:]...)
	}

	return sha256.Sum256(combined)
}
